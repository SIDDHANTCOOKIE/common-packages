import type { Event, EventTemplate, Filter } from "nostr-tools";
import type { DriveKeyring } from "./drive-key.js";
import type { ServerFailure } from "./errors.js";
import type { FileEntry } from "./file-entry.js";
import type { File, Folder } from "./schema.js";
import type { ByteReader } from "./stream.js";

/** A folder as listed: its `d` tag as `id`, and the created_at of the event it came from. */
export type FolderEntry = Folder & { id: string; createdAt: number };

export interface EncryptedFile {
  bytes: Uint8Array;
  blobHash: string;
  encryptionKey: string;
  unencryptedFileHash: string;
  size: number;
  chunkSize: number;
}

export interface FileSigner {
  getPublicKey(): Promise<string>;
  signEvent(event: EventTemplate): Promise<Event>;
}

/** The user's main identity signer: signs the Drive Key event and Blossom auth, and encrypts to self. */
export interface IdentitySigner extends FileSigner, IdentityEncryptionSigner {}

export interface IdentityEncryptionSigner {
  getPublicKey(): Promise<string>;
  nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string>;
  nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
}

/** One relay's answer to a publish, as reported by @formstr/local-relay. */
export interface FileRelayOutcome {
  relay: string;
  status: string;
  message?: string;
}

export interface FilePublishResult {
  ok: boolean;
  accepted: number;
  total: number;
  relayResults: FileRelayOutcome[];
}

/**
 * Structural subset of @formstr/local-relay (>=0.6) DataLayer used by this
 * package. `relays` on observe/publishEvent are per-call hints — nothing here
 * mutates the host's global routing.
 */
export interface FileEventStore {
  observe(
    filters: Filter[],
    handlers: { onEvent(event: Event): void; onEose?(): void },
    options?: { localOnly?: boolean; relays?: string[] },
  ): { unobserve(): void };
  publishEvent(event: Event, options?: { relays?: string[] }): Promise<FilePublishResult>;
  /** Relays an event was observed on. Only needed to prove relay coverage (see docs/adr/0003). */
  seenOn?(eventId: string): Promise<string[]>;
}

export interface FileProgress {
  operation: "upload" | "download";
  completedBytes: number;
  totalBytes: number;
}

export interface BlossomTransport {
  upload(input: {
    server: string;
    bytes: Uint8Array;
    authorization?: string;
    signal?: AbortSignal;
    onBytes?: (completedBytes: number, totalBytes: number) => void;
  }): Promise<void>;
  download(input: {
    server: string;
    hash: string;
    expectedSize?: number;
    authorization?: string;
    signal?: AbortSignal;
    onBytes?: (completedBytes: number, totalBytes: number) => void;
  }): Promise<Uint8Array>;
  /**
   * BUD-06 `HEAD /upload` preflight. Only a definitive refusal (403/413/415) may return `ok: false`;
   * 404/501/429/5xx and timeouts are inconclusive and must return `ok: true` so the real PUT decides.
   */
  canAccept?(input: {
    server: string;
    size: number;
    sha256: string;
    type: string;
    authorization?: string;
    signal?: AbortSignal;
  }): Promise<{ ok: boolean; reason?: string; status?: number }>;
  /** Opens the raw blob as a byte stream, for streamDecrypt. */
  downloadStream?(input: { server: string; hash: string; authorization?: string; signal?: AbortSignal }): Promise<ByteReader>;
  /** Fetches ciphertext bytes [start, end] (inclusive). `satisfied` is true only for a 206. */
  downloadRange?(input: {
    server: string;
    hash: string;
    start: number;
    end: number;
    authorization?: string;
    signal?: AbortSignal;
  }): Promise<{ bytes: Uint8Array; satisfied: boolean }>;
  /** Whether the blob is on the server. Throws when it cannot tell — never guesses `false`. */
  exists?(input: { server: string; hash: string; authorization?: string; signal?: AbortSignal }): Promise<boolean>;
  /** BUD-02 delete. A blob that is already gone counts as success. */
  delete?(input: { server: string; hash: string; authorization: string; signal?: AbortSignal }): Promise<void>;
}

export interface FetchFilesContext {
  store: FileEventStore;
  keyring: DriveKeyring;
  /** Extra constraints; `authors` defaults to every Drive Key pubkey in the keyring. */
  filter?: Filter;
  onFiles: (files: FileEntry[]) => void;
  onEose?: () => void;
  onError?: (error: unknown) => void;
  relayHints?: string[];
}

export interface FetchFoldersContext {
  store: FileEventStore;
  keyring: DriveKeyring;
  filter?: Filter;
  onFolders: (folders: FolderEntry[]) => void;
  onEose?: () => void;
  onError?: (error: unknown) => void;
  relayHints?: string[];
}

export interface FileFetchHandle {
  stop(): void;
}

export interface FolderFetchHandle {
  stop(): void;
}

export interface DownloadFileContext {
  transport: BlossomTransport;
  /** Used to construct BUD-01 GET authorization when the server requires it. */
  signer?: FileSigner;
  authorization?: string;
  authorizationContent?: string;
  authorizationExpiresIn?: number;
  now?: () => number;
  signal?: AbortSignal;
  onProgress?: (progress: FileProgress) => void;
}

export interface UploadBlobContext {
  signer: FileSigner;
  transport: BlossomTransport;
  servers: readonly string[];
  signal?: AbortSignal;
  onProgress?: (progress: FileProgress) => void;
  authorization?: string;
  authorizationContent?: string;
  authorizationExpiresIn?: number;
  now?: () => number;
  /**
   * `fallback` (default, what the app does): stop at the first server that accepts the blob.
   * `replicate`: upload to every listed server. Either way `servers` in the metadata is only the
   * servers the blob actually landed on, and at least one must succeed.
   */
  strategy?: "fallback" | "replicate";
  /** Attempts per server before moving on. Permanent refusals (401/403/413/415) are never retried. Default 3. */
  attempts?: number;
  /** Delay between attempts on one server. Default 3000. */
  retryDelayMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

export interface UploadOutcome {
  /** Servers the blob actually landed on, in the order they were tried. */
  landed: string[];
  /** Every server that did not take it, and why. Empty on a clean run. */
  failures: ServerFailure[];
}

export interface FileMetadataInputs {
  name: string;
  unencryptedFileHash: string;
  size: number;
  type: string;
  parent: string;
  servers: string[];
  encryptionKey: string;
  blobHash: string;
  chunkSize: number;
  keyring: DriveKeyring;
  previewHash?: string;
  uploadedAt?: number;
  client?: string;
  d?: string;
  createdAt?: number;
}

export interface CreatedFileMetadata {
  d: string;
  file: File;
  /** Signed with the active Drive Key. */
  event: Event;
}

export interface FolderMetadataInputs {
  name: string;
  parent: string;
  keyring: DriveKeyring;
  client?: string;
  d?: string;
  createdAt?: number;
}

export interface CreatedFolderMetadata {
  d: string;
  folder: Folder;
  event: Event;
}

export interface UploadFileInputs {
  name: string;
  type: string;
  parent: string;
  servers: string[];
  previewHash?: string;
  uploadedAt?: number;
  client?: string;
  d?: string;
  createdAt?: number;
  chunkSize?: number;
}

export interface UploadFileContext extends Omit<UploadBlobContext, "servers"> {
  store: FileEventStore;
  keyring: DriveKeyring;
}

export interface UploadFileResult {
  upload: UploadOutcome;
  encryptedFile: EncryptedFile;
  metadata: CreatedFileMetadata;
  event: Event;
  publishResult: FilePublishResult;
}
