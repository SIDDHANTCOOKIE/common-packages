import type { Event } from "nostr-tools";
import { createBlossomAuthorization } from "./blossom.js";
import { nextCreatedAt } from "./clock.js";
import { publishDeletionRequest } from "./deletion.js";
import type { DriveKeyring } from "./drive-key.js";
import { AppShapedFileError } from "./errors.js";
import { buildEvent } from "./events.js";
import type { FileEntry } from "./file-entry.js";
import { signingMaterial } from "./metadata.js";
import { assertFolder } from "./schema.js";
import { buildCoordinate } from "./sharing/link.js";
import type { BlossomTransport, FileEventStore, FilePublishResult, FileSigner, FolderEntry } from "./types.js";

export interface RepublishContext {
  store: FileEventStore;
  keyring: DriveKeyring;
  relays?: string[];
  client?: string;
}

export interface Republished {
  event: Event;
  publishResult: FilePublishResult;
}

/**
 * Republishes the SAME `d` with new content: encrypted and signed by the ACTIVE Drive Key (even if the
 * old event was authored by a rotated one — listings key by `d`, so the newest event wins across keys),
 * with a created_at that beats the version being replaced even if that one is future-dated.
 */
async function republish(
  context: RepublishContext,
  subtype: "files" | "folder",
  d: string,
  payload: unknown,
  replacesCreatedAt: number,
): Promise<Republished> {
  const event = buildEvent({
    subtype,
    d,
    payload,
    ...signingMaterial(context.keyring),
    createdAt: Math.max(nextCreatedAt(), replacesCreatedAt + 1),
    ...(context.client ? { client: context.client } : {}),
  });
  const publishResult = await context.store.publishEvent(event, context.relays ? { relays: context.relays } : undefined);
  if (!publishResult.ok) throw new Error("No relay accepted the republished metadata event");
  return { event, publishResult };
}

function assertName(name: string): void {
  if (name.length === 0) throw new Error("name must not be empty");
}

/**
 * Renames a file. Everything else in the decrypted payload — including fields this SDK does not
 * understand — is republished untouched, so renaming an app-written file does not silently rewrite it.
 */
export async function renameFile(file: FileEntry, name: string, context: RepublishContext): Promise<Republished> {
  assertName(name);
  return republish(context, "files", file.id, { ...file.raw, name }, file.createdAt);
}

/**
 * Moves a file under another folder id. An app-written file places itself by folder PATH, and a path
 * cannot be turned into a parent id without inventing one, so those are refused rather than half-moved.
 */
export async function moveFile(file: FileEntry, parent: string, context: RepublishContext): Promise<Republished> {
  if (file.appShaped) throw new AppShapedFileError("move");
  return republish(context, "files", file.id, { ...file.raw, parent }, file.createdAt);
}

export async function renameFolder(folder: FolderEntry, name: string, context: RepublishContext): Promise<Republished> {
  const next = { name, parent: folder.parent };
  assertFolder(next);
  return republish(context, "folder", folder.id, next, folder.createdAt);
}

export async function moveFolder(folder: FolderEntry, parent: string, context: RepublishContext): Promise<Republished> {
  if (parent === folder.id) throw new Error("A folder cannot be moved into itself");
  const next = { name: folder.name, parent };
  assertFolder(next);
  return republish(context, "folder", folder.id, next, folder.createdAt);
}

export interface DeleteFileContext extends RepublishContext {
  /** Identity signer: signs the BUD-02 delete authorization only. */
  signer: FileSigner;
  transport: BlossomTransport;
  now?: () => number;
}

export interface DeleteFileOptions {
  /**
   * Every blob hash some OTHER file still references (see findHashesStillReferenced). Required, and
   * anything in it is never deleted from a server.
   *
   * Only build this from a COMPLETE index. The SDK cannot know whether the host's list is complete, and
   * an incomplete one reads exactly like "nothing else uses this hash": the shared blob is destroyed and
   * the surviving copies keep listing normally, failing only later with a 404. The app gates on the
   * index reaching EOSE — not on "the store is non-empty", because a partially loaded store is
   * indistinguishable from a complete one to this check. Do the same, or pass every hash you have.
   */
  stillReferenced: ReadonlySet<string>;
  reason?: string;
}

export interface BlobDeletion {
  hash: string;
  server: string;
}

export interface DeleteFileResult {
  tombstone: Republished;
  /** Whether a relay accepted the best-effort NIP-09 request. Never gates anything. */
  deletionRequested: boolean;
  blobs: {
    deleted: BlobDeletion[];
    skipped: Array<{ hash: string; reason: "still-referenced" | "legacy-chunked" | "transport-cannot-delete" }>;
    failed: Array<BlobDeletion & { error: unknown }>;
  };
}

/**
 * Deletes a file: (1) a tombstone republish — this is what deletion actually relies on, relays are not
 * obliged to honor NIP-09 — which MUST land or nothing else happens, so a failure never leaves a listed
 * file whose blob is already gone; (2) a best-effort NIP-09 kind-5 `a` request; (3) best-effort blob
 * deletion on each of the file's servers, skipping every hash in `stillReferenced`. Each blob is
 * independent: one failure never blocks the rest, and an orphaned blob beats a half-deleted file.
 *
 * Legacy per-chunk files get the tombstone only; their chunk blobs are reported skipped.
 */
export async function deleteFile(file: FileEntry, context: DeleteFileContext, options: DeleteFileOptions): Promise<DeleteFileResult> {
  const tombstone = await republish(context, "files", file.id, { ...file.raw, deleted: true }, file.createdAt);

  const deletionRequested = await publishDeletionRequest(
    context.store,
    context.keyring.active,
    [buildCoordinate(context.keyring.active.publicKey, file.id)],
    options.reason ?? `Deleted ${file.name}`,
    context.relays,
  );

  const blobs: DeleteFileResult["blobs"] = { deleted: [], skipped: [], failed: [] };
  const candidates: string[] = [];
  if (file.legacyChunked) {
    for (const hash of file.legacyChunkHashes) blobs.skipped.push({ hash, reason: "legacy-chunked" });
  } else if (file.blobHash) {
    candidates.push(file.blobHash);
  }
  if (file.previewHash) candidates.push(file.previewHash);

  const toDelete = candidates.filter((hash) => {
    if (!options.stillReferenced.has(hash)) return true;
    blobs.skipped.push({ hash, reason: "still-referenced" });
    return false;
  });
  if (toDelete.length === 0) return { tombstone, deletionRequested, blobs };
  if (!context.transport.delete) {
    for (const hash of toDelete) blobs.skipped.push({ hash, reason: "transport-cannot-delete" });
    return { tombstone, deletionRequested, blobs };
  }

  // One authorization covering every blob, so the user signs once; generous expiry for slow servers.
  const authorization = await createBlossomAuthorization(
    context.signer,
    "delete",
    toDelete,
    `Delete ${file.name}`,
    600,
    context.now ?? (() => Math.floor(Date.now() / 1000)),
  );
  for (const hash of toDelete) {
    for (const server of file.servers) {
      try {
        await context.transport.delete({ server, hash, authorization });
        blobs.deleted.push({ hash, server });
      } catch (error) {
        blobs.failed.push({ hash, server, error });
      }
    }
  }
  return { tombstone, deletionRequested, blobs };
}
