import type { Event, EventTemplate, Filter } from "nostr-tools";
import type { File, Folder } from "./schema.js";

export type FolderEntry = Folder & { id: string };

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
  /** @deprecated removed in the signing commit — events are signed here, not by the store. */
  publish(template: EventTemplate): Promise<{ event: Event; result: FilePublishResult }>;
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
}

export interface FetchFilesContext {
  dataLayer: FileEventStore;
  metadataConversationKey: Uint8Array;
  onFiles: (files: File[]) => void;
  onEose?: () => void;
  onError?: (error: unknown) => void;
  relayHints?: string[];
}

export interface FetchFoldersContext {
  dataLayer: FileEventStore;
  metadataConversationKey: Uint8Array;
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
  metadataConversationKey: Uint8Array;
  previewHash?: string;
  uploadedAt?: number;
  client?: string;
  d?: string;
  createdAt?: number;
}

export interface CreatedFileMetadata {
  d: string;
  file: File;
  event: EventTemplate;
}

export interface FolderMetadataInputs {
  name: string;
  parent: string;
  metadataConversationKey: Uint8Array;
  client?: string;
  d?: string;
  createdAt?: number;
}

export interface CreatedFolderMetadata {
  d: string;
  folder: Folder;
  event: EventTemplate;
}

export interface UploadFileInputs {
  name: string;
  type: string;
  parent: string;
  servers: string[];
  metadataConversationKey: Uint8Array;
  previewHash?: string;
  uploadedAt?: number;
  client?: string;
  d?: string;
  createdAt?: number;
  chunkSize?: number;
}

export interface UploadFileContext extends Omit<UploadBlobContext, "servers"> {
  dataLayer: FileEventStore;
}

export interface UploadFileResult {
  encryptedFile: EncryptedFile;
  metadata: CreatedFileMetadata;
  event: Event;
  publishResult: FilePublishResult;
}

export interface SharedFileOptions {
  client?: string;
  d?: string;
  createdAt?: number;
}

export interface CreatedSharedFileMetadata {
  d: string;
  file: File;
  sharingKey: string;
  publicSharingKey: string;
  event: EventTemplate;
}

export interface ShareFileContext extends SharedFileOptions {
  dataLayer: FileEventStore;
}

export interface ShareFileResult extends CreatedSharedFileMetadata {
  signedEvent: Event;
  publishResult: FilePublishResult;
}
