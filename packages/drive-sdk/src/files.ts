import { createBlossomAuthorization } from "./blossom.js";
import { METADATA_KIND } from "./constants.js";
import { keyringEntries } from "./drive-key.js";
import { tagValue } from "./events.js";
import { toBlobFile, type BlobFile, type FileEntry } from "./file-entry.js";
import { decryptFileBytes, encryptFile } from "./crypto.js";
import { throwIfAborted } from "./encoding.js";
import { createFileMetadata, decryptFileEntry, decryptFolderMetadata, keyringConversationKeys } from "./metadata.js";
import type { File, Folder } from "./schema.js";
import type { DownloadFileContext, EncryptedFile, FileFetchHandle, FetchFilesContext, FetchFoldersContext, FolderEntry, FolderFetchHandle, UploadBlobContext, UploadFileContext, UploadFileInputs, UploadFileResult } from "./types.js";
import type { Event, Filter } from "nostr-tools";

function emitProgress(
  callback: ((value: import("./types.js").FileProgress) => void) | undefined,
  operation: "upload" | "download",
  completedBytes: number,
  totalBytes: number,
): void {
  callback?.({ operation, completedBytes, totalBytes });
}

interface FetchMetadataContext {
  store: FetchFilesContext["store"];
  keyring: FetchFilesContext["keyring"];
  filter?: Filter;
  onEose?: () => void;
  onError?: (error: unknown) => void;
  relayHints?: string[];
}

function fetchMetadata<T, R>(
  subtype: "files" | "folder",
  context: FetchMetadataContext,
  decrypt: (event: Event, keys: Uint8Array[]) => T,
  toResult: (value: T, event: Event, d: string) => R,
  onValues: (values: R[]) => void,
  isLive: (value: R) => boolean = () => true,
): FileFetchHandle {
  // Keyed by `d` alone, not (author, d): after a Drive Key rotation the same file is republished under
  // the new key and must replace the old event, exactly as the app's file index does.
  const entries = new Map<string, { createdAt: number; eventId: string; value?: R }>();
  const keys = keyringConversationKeys(context.keyring);
  const metadataFilter: Filter = {
    ...context.filter,
    kinds: [METADATA_KIND],
    authors: context.filter?.authors ?? keyringEntries(context.keyring).map((entry) => entry.publicKey),
    // Not filtered by `#t` for files: some legacy events predate the tag. Other subtypes (shares,
    // bookkeeping) carry a different `t` and are skipped below.
    ...(subtype === "folder" ? { "#t": ["folder"] } : {}),
  };
  let stopped = false;
  const emit = () => onValues([...entries.values()]
    .sort((a, b) => b.createdAt - a.createdAt || b.eventId.localeCompare(a.eventId))
    .flatMap((entry) => entry.value !== undefined && isLive(entry.value) ? [entry.value] : []));
  const handle = context.store.observe(
    [metadataFilter],
    {
      onEvent(event) {
        if (stopped || event.kind !== METADATA_KIND) return;
        const type = tagValue(event, "t");
        if (type !== undefined && type !== subtype) return;
        const d = tagValue(event, "d");
        if (!d) return;
        const current = entries.get(d);
        if (current && (current.createdAt > event.created_at || (current.createdAt === event.created_at && current.eventId >= event.id))) return;
        // Recorded even when it fails to decrypt, so an older decryptable version cannot resurrect
        // a file the newest event superseded.
        const entry: { createdAt: number; eventId: string; value?: R } = { createdAt: event.created_at, eventId: event.id };
        entries.set(d, entry);
        try {
          entry.value = toResult(decrypt(event, keys), event, d);
        } catch (error) {
          context.onError?.(error);
        }
        emit();
      },
      onEose: () => context.onEose?.(),
    },
    context.relayHints ? { relays: context.relayHints } : undefined,
  );
  return { stop: () => { stopped = true; handle.unobserve(); } };
}

export function fetchFiles(context: FetchFilesContext): FileFetchHandle {
  return fetchMetadata<FileEntry, FileEntry>(
    "files",
    context,
    (event, keys) => decryptFileEntry(event, keys),
    (entry) => entry,
    context.onFiles,
    (entry) => !entry.deleted,
  );
}

export function fetchFolders(context: FetchFoldersContext): FolderFetchHandle {
  return fetchMetadata<Folder, FolderEntry>(
    "folder",
    context,
    (event, keys) => decryptFolderMetadata(event.content, keys),
    (folder, _event, d) => ({ ...folder, id: d }),
    context.onFolders,
  );
}

export async function uploadEncryptedFile(encryptedFile: EncryptedFile, context: UploadBlobContext): Promise<void> {
  if (context.servers.length === 0) throw new Error("At least one Blossom server is required");
  const totalBytes = encryptedFile.bytes.byteLength * context.servers.length;
  const authorization = context.authorization ?? await createBlossomAuthorization(
    context.signer,
    "upload",
    [encryptedFile.blobHash],
    context.authorizationContent ?? "Upload encrypted file",
    context.authorizationExpiresIn ?? 300,
    context.now ?? (() => Math.floor(Date.now() / 1000)),
  );
  let completedBytes = 0;
  for (const server of context.servers) {
    throwIfAborted(context.signal);
    await context.transport.upload({
      server,
      bytes: encryptedFile.bytes,
      authorization,
      signal: context.signal,
      onBytes: (current) => emitProgress(context.onProgress, "upload", completedBytes + current, totalBytes),
    });
    completedBytes += encryptedFile.bytes.byteLength;
    emitProgress(context.onProgress, "upload", completedBytes, totalBytes);
  }
}

export async function downloadFile(source: File | FileEntry | BlobFile, context: DownloadFileContext): Promise<Blob> {
  const file = toBlobFile(source);
  const expectedSize = file.size + Math.max(1, Math.ceil(file.size / file.chunkSize)) * 16;
  const authorization = context.authorization
    ?? (context.signer
      ? await createBlossomAuthorization(
        context.signer,
        "get",
        [file.blobHash],
        context.authorizationContent ?? "Download encrypted file",
        context.authorizationExpiresIn ?? 300,
        context.now ?? (() => Math.floor(Date.now() / 1000)),
      )
      : undefined);
  const errors: unknown[] = [];
  for (const server of file.servers) {
    throwIfAborted(context.signal);
    try {
      const bytes = await context.transport.download({
        server,
        hash: file.blobHash,
        expectedSize,
        authorization,
        signal: context.signal,
        onBytes: (current, total) => emitProgress(context.onProgress, "download", current, total),
      });
      const plaintext = await decryptFileBytes(bytes, file);
      emitProgress(context.onProgress, "download", bytes.byteLength, bytes.byteLength);
      return new Blob([new Uint8Array(plaintext)], { type: file.type });
    } catch (error) {
      if (context.signal?.aborted) throw error;
      errors.push(error);
    }
  }
  throw new AggregateError(errors, "Unable to download a valid encrypted file from any Blossom server");
}

export async function uploadFile(
  source: Blob | Uint8Array,
  inputs: UploadFileInputs,
  context: UploadFileContext,
): Promise<UploadFileResult> {
  const encryptedFile = await encryptFile(source, { chunkSize: inputs.chunkSize });
  const metadata = createFileMetadata({
    name: inputs.name,
    type: inputs.type,
    parent: inputs.parent,
    servers: inputs.servers,
    keyring: context.keyring,
    ...(inputs.previewHash ? { previewHash: inputs.previewHash } : {}),
    uploadedAt: inputs.uploadedAt,
    client: inputs.client,
    d: inputs.d,
    createdAt: inputs.createdAt,
    size: encryptedFile.size,
    encryptionKey: encryptedFile.encryptionKey,
    unencryptedFileHash: encryptedFile.unencryptedFileHash,
    blobHash: encryptedFile.blobHash,
    chunkSize: encryptedFile.chunkSize,
  });
  await uploadEncryptedFile(encryptedFile, { ...context, servers: inputs.servers });
  throwIfAborted(context.signal);
  const event = metadata.event;
  const publishResult = await context.store.publishEvent(event);
  if (!publishResult.ok) throw new Error("No relay accepted the file metadata event");
  return { encryptedFile, metadata, event, publishResult };
}
