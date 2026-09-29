import { finalizeEvent, nip44, type Event } from "nostr-tools";
import { nextCreatedAt } from "./clock.js";
import { DRIVE_SDK_CLIENT, METADATA_KIND } from "./constants.js";
import { FolderShareUnsupportedError } from "./errors.js";

// The ONLY place a kind-34578 event's tags are written and its content is encrypted and signed.
// Every metadata, share and share-bookkeeping event is built through buildEvent, so:
//  - tag order is fixed and matches the app: d, t, client, encrypted, then extra tags
//    (formstr-drive src/services/sharing/event.ts). Order is part of the wire format for any
//    consumer that indexes tags positionally.
//  - the `["encrypted","nip44"]` tag cannot drift from the cipher: content goes through
//    nip44.v2 here and nowhere else. The app once wrote that tag in seven places while a
//    different, incompatible AES-GCM construction produced the content.
// Pure and synchronous: no I/O, no clocks other than the shared nextCreatedAt.

export type EventSubtype = "files" | "folder" | "shared-file" | "container" | "shared-container";

export interface BuildEventArgs {
  subtype: EventSubtype;
  /** The addressable `d` tag. */
  d: string;
  /** JSON-serialized and NIP-44 encrypted here — callers never touch a cipher. */
  payload: unknown;
  conversationKey: Uint8Array;
  /** Drive Key secret (or, for tests, any key) the event is authored with. */
  signingKey: Uint8Array;
  /** Defaults to nextCreatedAt(). Republishes over an existing coordinate should pass a value that beats it. */
  createdAt?: number;
  /** Tags after the four every event carries, e.g. `["revoked","1"]` on a superseding share event. */
  extraTags?: string[][];
  client?: string;
}

export function buildEvent(args: BuildEventArgs): Event {
  // `container` is folder sharing: readable (resolveShare recognizes it) but never written here.
  if (args.subtype === "container") throw new FolderShareUnsupportedError("create");
  return finalizeEvent(
    {
      kind: METADATA_KIND,
      created_at: args.createdAt ?? nextCreatedAt(),
      tags: [
        ["d", args.d],
        ["t", args.subtype],
        ["client", args.client ?? DRIVE_SDK_CLIENT],
        ["encrypted", "nip44"],
        ...(args.extraTags ?? []),
      ],
      content: nip44.v2.encrypt(JSON.stringify(args.payload), args.conversationKey),
    },
    args.signingKey,
  );
}

/**
 * Decrypts under a single conversation key or, for a keyring, tries each in order until one
 * validates the NIP-44 MAC — this is what recovers files encrypted under an older, rotated key
 * (mirrors formstr-drive's decryptMetadataWithDriveKey). Throws the last error if none does.
 */
export function decryptWithKeys(content: string, keys: Uint8Array | readonly Uint8Array[]): unknown {
  const list = keys instanceof Uint8Array ? [keys] : keys;
  let lastError: unknown = new Error("No Drive Key available to decrypt metadata");
  for (const key of list) {
    try {
      return JSON.parse(nip44.v2.decrypt(content, key));
    } catch (error) {
      lastError = error; // wrong key (bad MAC): try the next one
    }
  }
  throw lastError;
}

export function tagValue(event: Pick<Event, "tags">, name: string): string | undefined {
  return event.tags.find((tag) => tag[0] === name)?.[1];
}
