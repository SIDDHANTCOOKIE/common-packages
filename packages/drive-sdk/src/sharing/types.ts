import type { DriveKeyring } from "../drive-key.js";
import type { FileEntry } from "../file-entry.js";
import type { FileEventStore } from "../types.js";

/** A share link, decoded. `naddr` points at the event; `k` is the ephemeral secret (hex). */
export interface ShareLinkPayload {
  naddr: string;
  k: string;
}

export interface ShareSource {
  type: "file" | "folder";
  /** File id (file shares). */
  id?: string;
  /** Folder path (folder shares written by the app). */
  path?: string;
}

/** What a container share lists; kept so entries written by the app round-trip. */
export interface ShareMember {
  id: string;
  coordinate: string;
}

/** One entry of "Shared by me", from a `shared-container` bookkeeping event. */
export interface SharedByMeEntry {
  kind: "file" | "folder";
  name: string;
  source: ShareSource;
  /** Unix SECONDS — the raw created_at of the bookkeeping event. */
  sharedAtSeconds: number;
  /** Full link, rebuilt from the stored payload with the relays the share landed on. */
  url: string;
  /** `d` of the bookkeeping event itself — needed to supersede it. */
  infoD: string;
  infoCoordinate: string;
  /** Coordinate the link resolves to. */
  coordinate: string;
  relays: string[];
  /** The share's ephemeral secret (hex). */
  encryptionKey: string;
  members: ShareMember[];
  /** Set once revoked; the entry stays listed so a failed revoke stays retryable. */
  revokedAt?: number;
}

export interface RevokedSharePayload {
  v: 1;
  revoked: true;
  at: number;
  kind: "file" | "folder";
}

export type ResolvedShare =
  | { kind: "file"; file: FileEntry }
  | { kind: "revoked"; target: "file" | "folder"; at: number };

export interface ShareContext {
  store: FileEventStore;
  keyring: DriveKeyring;
  /** Read hints added to every lookup (in addition to a link's own hints). */
  relays?: string[];
  client?: string;
  /** Hard cap on a lookup. Default 8000. */
  timeoutMs?: number;
  /** Settle this long after the last event. Default 1200. */
  quietMs?: number;
  /** Base URL prefixed to the `#shared=…` fragment of links this call builds. */
  baseUrl?: string;
}

export interface ResolveShareContext {
  store: FileEventStore;
  relays?: string[];
  timeoutMs?: number;
  quietMs?: number;
}

export interface ShareResult {
  url: string;
  /** True when nothing was published: a live share for this file already existed. */
  reused: boolean;
  coordinate: string;
  /** False when the link works but the "Shared by me" bookkeeping event did not land. */
  infoWritten: boolean;
  infoError?: unknown;
}

export interface RevokeResult {
  /** When the revoke was authored (unix seconds). */
  at: number;
  /** False when the share is dead but the bookkeeping event still shows it as live. */
  infoWritten: boolean;
  infoError?: unknown;
}
