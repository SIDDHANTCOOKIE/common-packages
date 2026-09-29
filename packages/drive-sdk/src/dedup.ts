import { LegacyChunkedFileError } from "./errors.js";
import type { FileEntry } from "./file-entry.js";
import { createFileMetadata, randomDTag } from "./metadata.js";
import type { DriveKeyring } from "./drive-key.js";
import type { BlossomTransport, CreatedFileMetadata, FileEventStore, FilePublishResult } from "./types.js";

// Client-level dedup, per NIP-FS: "unencryptedFileHash is used to dedupe files at the client level since
// the hash generated after encryption will always be unique due to rotating nonce and encryption key."
// Two uploads of identical bytes get different blobHash and encryptionKey every time, so only the
// PLAINTEXT hash can catch them. These helpers are pure over a list the HOST supplies: the SDK holds no
// index, so "best effort against what you have loaded" is exactly as good as that list is complete.

/**
 * The most recent live copy of these bytes in `files`, or undefined. Tombstones and legacy per-chunk
 * files are skipped — a legacy match must not shadow an older, reusable one.
 */
export function findDuplicate(files: readonly FileEntry[], unencryptedFileHash: string): FileEntry | undefined {
  const wanted = unencryptedFileHash.toLowerCase();
  return files
    .filter((f) => !f.deleted && !f.legacyChunked && f.unencryptedFileHash?.toLowerCase() === wanted)
    .sort((a, b) => b.createdAt - a.createdAt)[0];
}

/**
 * Whether a match from {@link findDuplicate} is safe to reuse: its blob is still on a server, not
 * merely present in a possibly stale list. A reuse of a deleted blob mints metadata that is broken from
 * the moment it exists and fails only later, at download.
 *
 * Legacy per-chunk files are always false: one chunk existing proves nothing about the set, and
 * checking every chunk is a request each. `transport.exists` throws when it cannot tell, and a throw
 * (or a transport with no `exists`) reads as false — fall through to a real upload rather than gamble.
 */
export async function isBlobLive(file: FileEntry, transport: BlossomTransport, signal?: AbortSignal): Promise<boolean> {
  if (file.legacyChunked || file.blobHash === undefined || !transport.exists) return false;
  const blobHash = file.blobHash;
  for (const server of file.servers) {
    try {
      if (await transport.exists({ server, hash: blobHash, signal })) return true;
    } catch {
      // uncertain on this server: keep looking, never assume live
    }
  }
  return false;
}

export interface LinkDuplicateInputs {
  name: string;
  parent: string;
  type?: string;
  d?: string;
  createdAt?: number;
  uploadedAt?: number;
  client?: string;
}

/**
 * Publishes a NEW metadata entry that points at an existing blob (same blobHash, key, servers) instead
 * of uploading again. Check {@link isBlobLive} first. The copy shares the blob with the original, so
 * deleting either must consult `stillReferenced` (see deleteFile).
 */
export async function linkDuplicate(
  duplicate: FileEntry,
  inputs: LinkDuplicateInputs,
  context: { store: FileEventStore; keyring: DriveKeyring },
): Promise<{ metadata: CreatedFileMetadata; publishResult: FilePublishResult }> {
  if (duplicate.legacyChunked || duplicate.blobHash === undefined || duplicate.chunkSize === undefined) {
    throw new LegacyChunkedFileError(duplicate.id);
  }
  if (duplicate.unencryptedFileHash === undefined) throw new Error("Cannot link a duplicate without an unencryptedFileHash");
  const metadata = createFileMetadata({
    name: inputs.name,
    type: inputs.type ?? duplicate.type,
    parent: inputs.parent,
    servers: duplicate.servers,
    keyring: context.keyring,
    size: duplicate.size,
    encryptionKey: duplicate.encryptionKey,
    unencryptedFileHash: duplicate.unencryptedFileHash,
    blobHash: duplicate.blobHash,
    chunkSize: duplicate.chunkSize,
    ...(duplicate.previewHash ? { previewHash: duplicate.previewHash } : {}),
    d: inputs.d ?? randomDTag(),
    ...(inputs.createdAt !== undefined ? { createdAt: inputs.createdAt } : {}),
    ...(inputs.uploadedAt !== undefined ? { uploadedAt: inputs.uploadedAt } : {}),
    ...(inputs.client !== undefined ? { client: inputs.client } : {}),
  });
  const publishResult = await context.store.publishEvent(metadata.event);
  if (!publishResult.ok) throw new Error("No relay accepted the file metadata event");
  return { metadata, publishResult };
}

/**
 * Blob hashes still referenced by some file OUTSIDE `deleting` — i.e. hashes that must not be deleted
 * from a server. Dedup makes N metadata entries fan into one blob, so deleting per file cannot assume
 * it owns the bytes. Takes the whole delete set so a bulk delete gets one consistent answer.
 *
 * Best-effort in the safe direction only: this is just what `files` contains. Absence here is "no
 * evidence", never permission — see the warning on deleteFile.
 */
export function findHashesStillReferenced(files: readonly FileEntry[], deleting: readonly FileEntry[]): Set<string> {
  const deletingIds = new Set(deleting.map((f) => f.id));
  const referenced = new Set<string>();
  for (const other of files) {
    if (other.deleted || deletingIds.has(other.id)) continue;
    if (other.blobHash) referenced.add(other.blobHash);
    if (other.previewHash) referenced.add(other.previewHash);
    for (const hash of other.legacyChunkHashes) referenced.add(hash);
  }
  return referenced;
}
