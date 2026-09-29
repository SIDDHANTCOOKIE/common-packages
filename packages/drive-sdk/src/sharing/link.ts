import { nip19 } from "nostr-tools";
import { METADATA_KIND } from "../constants.js";
import type { ShareLinkPayload } from "./types.js";

// The ONLY place the share link's wire format is known: `#shared=<naddr>&k=<64-hex>`.
// `naddr` (NIP-19) is the standard pointer — kind, drive pubkey, d, relay hints. It has no TLV for a
// secret and must not be forced into one, so the ephemeral key rides outside it, joined by `&k=`.
// The fragment is never sent to a server. Which subtype the link points at is NOT in the link: it is
// read off the fetched event's own `t` tag, so there is no second place for that claim to drift.

export const SHARE_HASH_PREFIX = "#shared=";
const HEX_64 = /^[0-9a-f]{64}$/i;

export function buildCoordinate(pubkey: string, d: string): string {
  return `${METADATA_KIND}:${pubkey}:${d}`;
}

/** Splits "kind:pubkey:d". Throws on anything malformed: callers only pass coordinates this package wrote. */
export function parseCoordinate(coordinate: string): { kind: number; pubkey: string; d: string } {
  const [kindString, pubkey, ...rest] = coordinate.split(":");
  const kind = Number(kindString);
  const d = rest.join(":");
  if (!Number.isFinite(kind) || !pubkey || !d) throw new Error(`Malformed coordinate: ${coordinate}`);
  return { kind, pubkey, d };
}

export interface EncodeShareLinkParams {
  pubkey: string;
  d: string;
  relays: string[];
  secretKeyHex: string;
  /** Prefix (origin + path) for the fragment. Default: the bare fragment. */
  baseUrl?: string;
}

export function encodeShareLink(params: EncodeShareLinkParams): string {
  if (!HEX_64.test(params.secretKeyHex)) throw new Error("Share key must be 64 hex characters");
  const naddr = nip19.naddrEncode({ kind: METADATA_KIND, pubkey: params.pubkey, identifier: params.d, relays: params.relays });
  return `${params.baseUrl ?? ""}${SHARE_HASH_PREFIX}${naddr}&k=${params.secretKeyHex}`;
}

/**
 * Decodes a share link (a bare `#shared=…` fragment or a full URL containing one). Returns null —
 * never throws — for anything malformed, a key that is not 64 hex, or an naddr of the wrong kind.
 */
export function decodeShareLink(input: string): ShareLinkPayload | null {
  const start = input.indexOf(SHARE_HASH_PREFIX);
  if (start === -1) return null;
  const rest = input.slice(start + SHARE_HASH_PREFIX.length);
  const separator = rest.indexOf("&k=");
  if (separator === -1) return null;
  const naddr = rest.slice(0, separator);
  const k = rest.slice(separator + "&k=".length);
  if (!naddr || !HEX_64.test(k)) return null;
  return decodePointer(naddr) ? { naddr, k } : null;
}

/** The pointer inside an naddr, or null if it does not decode to an naddr of our kind. */
export function decodePointer(naddr: string): { kind: number; pubkey: string; d: string; relays: string[] } | null {
  try {
    const decoded = nip19.decode(naddr);
    if (decoded.type !== "naddr" || decoded.data.kind !== METADATA_KIND) return null;
    return { kind: decoded.data.kind, pubkey: decoded.data.pubkey, d: decoded.data.identifier, relays: decoded.data.relays ?? [] };
  } catch {
    return null;
  }
}
