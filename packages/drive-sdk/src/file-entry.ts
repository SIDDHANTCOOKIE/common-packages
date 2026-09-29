import { InvalidFileMetadataError, LegacyChunkedFileError } from "./errors.js";
import { isValidEncryptionKey, type File } from "./schema.js";

// Reading is lenient, writing is strict (docs/adr/0002-deliberate-parity.md).
//
// The SDK WRITES the NIP-FS spec shape (`parent` id, `servers[]`). The formstr-drive app writes a
// different shape today (`folder` = a path string, `id`, `server`, `deleted`), and a drive is shared
// between both, so READING accepts both. One decrypted JSON object becomes one FileEntry.

const HEX_64 = /^[0-9a-f]{64}$/i;
const HTTP_URL = /^https?:\/\/\S+$/;

/** A file as listed from the drive, whichever shape it was written in. */
export interface FileEntry {
  /** The event's `d` tag — the stable handle for rename/move/delete. Never read from the payload. */
  id: string;
  /** Pubkey of the Drive Key that authored the newest event for this file. */
  author: string;
  /** `created_at` of that event. */
  createdAt: number;
  name: string;
  size: number;
  type: string;
  uploadedAt: number;
  servers: string[];
  encryptionKey: string;
  encryptionAlgorithm: "aes-gcm";
  /** Spec shape only. An app-shaped file has no parent id and this is undefined — it is never derived from `folderPath`. */
  parent?: string;
  /** App shape only: the folder as a path string, e.g. "/a/b". A path, NOT an id. */
  folderPath?: string;
  /** Optional in the app's shape. Integrity is verified on download only when present. */
  unencryptedFileHash?: string;
  previewHash?: string;
  /** Single-blob layout. Absent on legacy chunked files. */
  blobHash?: string;
  chunkSize?: number;
  /** True for the pre-NIP-FS per-chunk layout: parses and lists, cannot be downloaded or reused. */
  legacyChunked: boolean;
  /** Blob hashes of a legacy chunked file, kept only so reference counting can see them. */
  legacyChunkHashes: string[];
  /** Tombstone: republished with `deleted: true`. Listings exclude these. */
  deleted: boolean;
  /** True when written by the app (path-based) rather than in the spec shape. */
  appShaped: boolean;
  /** The exact decrypted JSON, so a rename republishes every field it does not understand. */
  raw: Record<string, unknown>;
}

/** Everything needed to fetch and decrypt one single-blob file. A spec `File` satisfies it. */
export interface BlobFile {
  size: number;
  chunkSize: number;
  blobHash: string;
  encryptionKey: string;
  unencryptedFileHash?: string;
  servers: readonly string[];
  type: string;
}

export interface FileEntryMeta {
  id: string;
  author: string;
  createdAt: number;
}

function invalid(field: string, why: string): never {
  throw new InvalidFileMetadataError(`Invalid file metadata: /${field}: ${why}`);
}

function hex64(value: unknown, field: string): string {
  if (typeof value !== "string" || !HEX_64.test(value)) invalid(field, "expected 64 hex characters");
  return value;
}

/**
 * Reads one decrypted file payload in either shape. Throws InvalidFileMetadataError for anything
 * that is neither. Mapping: `server` → `servers=[server]` when `servers` is absent; `folder` →
 * `folderPath`; `deleted: true` → tombstone; `chunks` without `blobHash` → legacy chunked.
 */
export function readFileMetadata(value: unknown, meta: FileEntryMeta): FileEntry {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid("", "expected an object");
  const raw = value as Record<string, unknown>;

  const { name, size, type, uploadedAt } = raw;
  if (typeof name !== "string" || name.length === 0) invalid("name", "expected a non-empty string");
  if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) invalid("size", "expected a non-negative integer");
  if (typeof type !== "string") invalid("type", "expected a string");
  if (typeof uploadedAt !== "number" || !Number.isFinite(uploadedAt) || uploadedAt < 0) invalid("uploadedAt", "expected a non-negative number");

  const encryptionKey = hex64(raw.encryptionKey, "encryptionKey");
  if (!isValidEncryptionKey(encryptionKey)) invalid("encryptionKey", "Expected a valid secp256k1 private key");
  const algorithm = raw.encryptionAlgorithm ?? "aes-gcm";
  if (algorithm !== "aes-gcm") invalid("encryptionAlgorithm", `unsupported algorithm ${String(algorithm)}`);

  let servers: string[];
  if (Array.isArray(raw.servers)) {
    servers = raw.servers as string[];
    if (servers.length === 0 || servers.some((s) => typeof s !== "string" || !HTTP_URL.test(s))) invalid("servers", "expected a non-empty list of http(s) URLs");
  } else if (typeof raw.server === "string" && HTTP_URL.test(raw.server)) {
    servers = [raw.server];
  } else {
    return invalid("servers", "expected `servers` (spec) or `server` (app)");
  }

  const hasBlob = raw.blobHash !== undefined || raw.chunkSize !== undefined;
  let blobHash: string | undefined;
  let chunkSize: number | undefined;
  let legacyChunkHashes: string[] = [];
  if (hasBlob) {
    blobHash = hex64(raw.blobHash, "blobHash");
    if (typeof raw.chunkSize !== "number" || !Number.isSafeInteger(raw.chunkSize) || raw.chunkSize < 1) invalid("chunkSize", "expected a positive integer");
    chunkSize = raw.chunkSize;
  } else if (Array.isArray(raw.chunks) && raw.chunks.length > 0) {
    // Old metadata stored chunks as bare hash strings; newer as { hash, server? }.
    legacyChunkHashes = raw.chunks.map((chunk) => {
      const hash = typeof chunk === "string" ? chunk : (chunk as { hash?: unknown } | null)?.hash;
      return hex64(hash, "chunks");
    });
  } else {
    invalid("blobHash", "expected `blobHash` + `chunkSize` (single blob) or `chunks` (legacy)");
  }

  if (raw.unencryptedFileHash !== undefined) hex64(raw.unencryptedFileHash, "unencryptedFileHash");
  if (raw.previewHash !== undefined) hex64(raw.previewHash, "previewHash");
  if (raw.parent !== undefined && typeof raw.parent !== "string") invalid("parent", "expected a string");
  if (raw.folder !== undefined && typeof raw.folder !== "string") invalid("folder", "expected a string path");

  const entry: FileEntry = {
    id: meta.id,
    author: meta.author,
    createdAt: meta.createdAt,
    name,
    size,
    type,
    uploadedAt,
    servers,
    encryptionKey,
    encryptionAlgorithm: "aes-gcm",
    legacyChunked: blobHash === undefined,
    legacyChunkHashes,
    deleted: raw.deleted === true,
    appShaped: raw.parent === undefined,
    raw,
  };
  if (blobHash !== undefined) entry.blobHash = blobHash;
  if (chunkSize !== undefined) entry.chunkSize = chunkSize;
  if (raw.unencryptedFileHash !== undefined) entry.unencryptedFileHash = raw.unencryptedFileHash as string;
  if (raw.previewHash !== undefined) entry.previewHash = raw.previewHash as string;
  if (raw.parent !== undefined) entry.parent = raw.parent as string;
  if (raw.folder !== undefined) entry.folderPath = raw.folder as string;
  return entry;
}

/**
 * Narrows any file-like input to a downloadable single blob, or throws the typed legacy error.
 * A strict spec `File` passes through untouched.
 */
export function toBlobFile(file: File | FileEntry | BlobFile): BlobFile {
  const candidate = file as Partial<FileEntry> & Partial<BlobFile>;
  if (candidate.legacyChunked === true || candidate.blobHash === undefined || candidate.chunkSize === undefined) {
    throw new LegacyChunkedFileError(candidate.id);
  }
  if (!HEX_64.test(candidate.blobHash)) invalid("blobHash", "expected 64 hex characters");
  if (!Number.isSafeInteger(candidate.chunkSize) || candidate.chunkSize < 1) invalid("chunkSize", "expected a positive integer");
  if (typeof candidate.size !== "number" || !Number.isSafeInteger(candidate.size) || candidate.size < 0) invalid("size", "expected a non-negative integer");
  if (typeof candidate.encryptionKey !== "string" || !HEX_64.test(candidate.encryptionKey) || !isValidEncryptionKey(candidate.encryptionKey)) {
    invalid("encryptionKey", "Expected a valid secp256k1 private key");
  }
  if (candidate.unencryptedFileHash !== undefined && !HEX_64.test(candidate.unencryptedFileHash)) invalid("unencryptedFileHash", "expected 64 hex characters");
  if (!Array.isArray(candidate.servers) || candidate.servers.length === 0) invalid("servers", "expected a non-empty list");
  return {
    size: candidate.size,
    chunkSize: candidate.chunkSize,
    blobHash: candidate.blobHash,
    encryptionKey: candidate.encryptionKey,
    ...(candidate.unencryptedFileHash !== undefined ? { unencryptedFileHash: candidate.unencryptedFileHash } : {}),
    servers: candidate.servers,
    type: typeof candidate.type === "string" ? candidate.type : "",
  };
}
