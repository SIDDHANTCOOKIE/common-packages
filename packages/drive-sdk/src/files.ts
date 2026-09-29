import { createBlossomAuthorization } from "./blossom.js";
import { METADATA_KIND } from "./constants.js";
import { AllServersFailedError, BlossomHttpError, RangeNotSatisfiedError, UploadRefusedError, type ServerFailure } from "./errors.js";
import { decryptRange, streamDecrypt, type ByteReader } from "./stream.js";
import { keyringEntries } from "./drive-key.js";
import { tagValue } from "./events.js";
import { toBlobFile, type BlobFile, type FileEntry } from "./file-entry.js";
import { decryptFileBytes, encryptFile } from "./crypto.js";
import { throwIfAborted } from "./encoding.js";
import { createFileMetadata, decryptFileEntry, decryptFolderMetadata, keyringConversationKeys, randomDTag } from "./metadata.js";
import type { File, Folder } from "./schema.js";
import type { DownloadFileContext, EncryptedFile, FileFetchHandle, FetchFilesContext, FetchFoldersContext, FolderEntry, FolderFetchHandle, UploadBlobContext, UploadFileContext, UploadFileInputs, UploadFileResult, UploadOutcome } from "./types.js";
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
        // Equal created_at: relays keep the LOWEST id (NIP-01), so the listing must too or it disagrees with them.
        if (current && (current.createdAt > event.created_at || (current.createdAt === event.created_at && current.eventId <= event.id))) return;
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
    (folder, event, d) => ({ ...folder, id: d, createdAt: event.created_at }),
    context.onFolders,
  );
}

// Statuses a retry cannot fix: skip the remaining same-server attempts (a foregone conclusion three times).
const PERMANENT_STATUSES = new Set([401, 403, 413, 415]);

function isPermanent(error: unknown): boolean {
  return error instanceof BlossomHttpError && PERMANENT_STATUSES.has(error.status);
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Uploads the one concatenated blob, reporting honestly what happened per server.
 *
 * Per server: an optional BUD-06 preflight (`transport.canAccept`) — a definitive refusal skips that
 * server without sending the body, anything inconclusive proceeds to the real PUT — then up to
 * `attempts` PUTs. One BUD-02 authorization is signed once and replayed across servers (it is
 * server-agnostic), so falling back costs no extra signer prompt.
 *
 * `fallback` stops at the first success; `replicate` tries them all. At least one must succeed or
 * AllServersFailedError carries every server's failure. Abort errors propagate immediately.
 */
export async function uploadEncryptedFile(encryptedFile: EncryptedFile, context: UploadBlobContext): Promise<UploadOutcome> {
  if (context.servers.length === 0) throw new Error("At least one Blossom server is required");
  const now = context.now ?? (() => Math.floor(Date.now() / 1000));
  const authorization = context.authorization ?? await createBlossomAuthorization(
    context.signer,
    "upload",
    [encryptedFile.blobHash],
    context.authorizationContent ?? "Upload encrypted file",
    context.authorizationExpiresIn ?? 300,
    now,
  );
  const strategy = context.strategy ?? "fallback";
  const attempts = Math.max(1, context.attempts ?? 3);
  const sleep = context.sleep ?? defaultSleep;
  const landed: string[] = [];
  const failures: ServerFailure[] = [];
  const totalBytes = encryptedFile.bytes.byteLength * (strategy === "replicate" ? context.servers.length : 1);
  let completedBytes = 0;

  for (const server of context.servers) {
    throwIfAborted(context.signal);
    if (strategy === "fallback" && landed.length > 0) break;

    if (context.transport.canAccept) {
      const verdict = await context.transport.canAccept({
        server,
        size: encryptedFile.bytes.byteLength,
        sha256: encryptedFile.blobHash,
        type: "application/octet-stream",
        authorization,
        signal: context.signal,
      });
      if (!verdict.ok) {
        failures.push({ server, refused: true, error: new UploadRefusedError(verdict.reason || "Server refused this upload", verdict.status) });
        continue;
      }
    }

    let lastError: unknown;
    let succeeded = false;
    for (let attempt = 1; attempt <= attempts && !succeeded; attempt += 1) {
      throwIfAborted(context.signal);
      try {
        await context.transport.upload({
          server,
          bytes: encryptedFile.bytes,
          authorization,
          signal: context.signal,
          onBytes: (current) => emitProgress(context.onProgress, "upload", completedBytes + current, totalBytes),
        });
        succeeded = true;
      } catch (error) {
        if (context.signal?.aborted) throw error;
        lastError = error;
        if (isPermanent(error) || attempt === attempts) break;
        await sleep(context.retryDelayMs ?? 3000);
      }
    }
    if (succeeded) {
      landed.push(server);
      completedBytes += encryptedFile.bytes.byteLength;
      emitProgress(context.onProgress, "upload", completedBytes, totalBytes);
    } else {
      failures.push({ server, refused: false, error: lastError });
    }
  }

  if (landed.length === 0) throw new AllServersFailedError(failures);
  return { landed, failures };
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
  const d = inputs.d ?? randomDTag();
  const uploadedAt = inputs.uploadedAt ?? Date.now();
  const build =(servers: string[]) => createFileMetadata({
    name: inputs.name,
    type: inputs.type,
    parent: inputs.parent,
    servers,
    keyring: context.keyring,
    ...(inputs.previewHash ? { previewHash: inputs.previewHash } : {}),
    uploadedAt,
    client: inputs.client,
    d,
    createdAt: inputs.createdAt,
    size: encryptedFile.size,
    encryptionKey: encryptedFile.encryptionKey,
    unencryptedFileHash: encryptedFile.unencryptedFileHash,
    blobHash: encryptedFile.blobHash,
    chunkSize: encryptedFile.chunkSize,
  });
  build(inputs.servers); // validate before any bytes leave the machine
  const upload = await uploadEncryptedFile(encryptedFile, { ...context, servers: inputs.servers });
  throwIfAborted(context.signal);
  // `servers` records where the blob actually is — a server that failed or refused is not listed.
  const metadata = build(upload.landed);
  const event = metadata.event;
  const publishResult = await context.store.publishEvent(event);
  if (!publishResult.ok) throw new Error("No relay accepted the file metadata event");
  return { upload, encryptedFile, metadata, event, publishResult };
}

async function downloadAuthorization(file: BlobFile, context: DownloadFileContext): Promise<string | undefined> {
  if (context.authorization) return context.authorization;
  if (!context.signer) return undefined;
  return createBlossomAuthorization(
    context.signer,
    "get",
    [file.blobHash],
    context.authorizationContent ?? "Download encrypted file",
    context.authorizationExpiresIn ?? 300,
    context.now ?? (() => Math.floor(Date.now() / 1000)),
  );
}

/**
 * Streams a file's plaintext segments: opens the blob on the first server that answers (falling back
 * on open failure), then decrypts frame by frame with streamDecrypt. A failure MID-stream is not
 * retried on another server — bytes were already yielded; the caller restarts. Throws on truncation,
 * overrun and hash mismatch; discard anything written before such a throw.
 */
export async function* downloadFileStream(source: File | FileEntry | BlobFile, context: DownloadFileContext): AsyncGenerator<Uint8Array> {
  const file = toBlobFile(source);
  if (!context.transport.downloadStream) throw new Error("This Blossom transport cannot stream downloads");
  const authorization = await downloadAuthorization(file, context);
  const errors: unknown[] = [];
  let reader: ByteReader | undefined;
  for (const server of file.servers) {
    throwIfAborted(context.signal);
    try {
      reader = await context.transport.downloadStream({ server, hash: file.blobHash, authorization, signal: context.signal });
      break;
    } catch (error) {
      if (context.signal?.aborted) throw error;
      errors.push(error);
    }
  }
  if (!reader) throw new AggregateError(errors, "Unable to open the encrypted blob on any Blossom server");
  yield* streamDecrypt(reader, file);
}

/**
 * Reads plaintext bytes [start, end] fetching only the covering segments. Tries each server; if the
 * ones that answer all ignore Range, throws RangeNotSatisfiedError so the caller can fall back to
 * downloadFileStream — misaligned bytes are never decoded.
 */
export async function readFileRange(source: File | FileEntry | BlobFile, start: number, end: number, context: DownloadFileContext): Promise<Uint8Array> {
  const file = toBlobFile(source);
  if (!context.transport.downloadRange) throw new Error("This Blossom transport cannot fetch ranges");
  const downloadRange = context.transport.downloadRange.bind(context.transport);
  const authorization = await downloadAuthorization(file, context);
  const errors: unknown[] = [];
  let ignored = false;
  for (const server of file.servers) {
    throwIfAborted(context.signal);
    try {
      return await decryptRange(file, start, end, ({ start: from, end: to }) =>
        downloadRange({ server, hash: file.blobHash, start: from, end: to, authorization, signal: context.signal }));
    } catch (error) {
      if (context.signal?.aborted || error instanceof RangeError) throw error;
      if (error instanceof RangeNotSatisfiedError) ignored = true;
      errors.push(error);
    }
  }
  if (ignored && errors.every((e) => e instanceof RangeNotSatisfiedError)) throw new RangeNotSatisfiedError();
  throw new AggregateError(errors, "Unable to read a valid range from any Blossom server");
}
