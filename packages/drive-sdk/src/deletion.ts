import { finalizeEvent } from "nostr-tools";
import { hexToBytes } from "nostr-tools/utils";
import { METADATA_KIND } from "./constants.js";
import type { DriveKeyEntry } from "./drive-key.js";
import type { FileEventStore } from "./types.js";

/**
 * Best-effort NIP-09 kind-5 deletion request for addressable coordinates ("34578:<pubkey>:<d>"),
 * signed with the Drive Key that authored them (a kind-5 from key A cannot touch key B's events).
 * Never throws and never gates anything: many relays do not honor kind-5 for addressable events, so
 * this is a courtesy on top of whatever actually supersedes the event — a tombstone republish for
 * files, a "revoked" republish for shares. Returns whether any relay accepted it.
 */
export async function publishDeletionRequest(
  store: FileEventStore,
  key: DriveKeyEntry,
  coordinates: string[],
  reason: string,
  relays?: string[],
): Promise<boolean> {
  if (coordinates.length === 0) return false;
  try {
    const event = finalizeEvent(
      {
        kind: 5,
        created_at: Math.floor(Date.now() / 1000),
        tags: [...coordinates.map((coordinate) => ["a", coordinate]), ["k", String(METADATA_KIND)]],
        content: reason,
      },
      hexToBytes(key.secretKeyHex),
    );
    return (await store.publishEvent(event, relays ? { relays } : undefined)).ok;
  } catch {
    return false;
  }
}
