import { generateSecretKey, getPublicKey, nip44, type Event } from "nostr-tools";
import { bytesToHex, hexToBytes } from "nostr-tools/utils";
import { nextCreatedAt } from "./clock.js";
import { DRIVE_SDK_CLIENT, METADATA_KIND } from "./constants.js";
import { conversationKeyFromSecret } from "./crypto.js";
import {
  DriveKeyDroppedError,
  DriveKeyMintRefusedError,
  DriveKeyUnavailableError,
} from "./errors.js";
import { isValidEncryptionKey } from "./schema.js";
import type { FileEventStore, FilePublishResult, IdentitySigner } from "./types.js";

// The Drive Key is a secp256k1 secret stored in the user's own replaceable kind
// 34578 event at d=`0:<pubkey>`, encrypted to the identity key. Everything else
// (file metadata, shares) is signed and encrypted with it. There is ONE such
// event per identity: publishing a second one does not coexist with the first,
// it replaces it on every relay that accepts it. That is the whole hazard this
// module is built around — see docs/adr/0003-drive-key-mint-hazard.md.

/** A decrypted Drive Key: the secret, its pubkey, and the NIP-44 self conversation key. */
export interface DriveKeyEntry {
  secretKeyHex: string;
  publicKey: string;
  conversationKey: Uint8Array;
}

/**
 * Every Drive Key the identity has ever had. `active` encrypts and signs new
 * events; `previous` exist only so older events stay readable and addressable.
 */
export interface DriveKeyring {
  active: DriveKeyEntry;
  previous: DriveKeyEntry[];
}

export type DriveKeyStatus =
  | { kind: "ready"; keyring: DriveKeyring; event: Event; stale: boolean }
  // No key exists anywhere reachable, and that absence was PROVEN (relay coverage).
  | { kind: "empty-confirmed" }
  // Don't know: timeout, unreachable relays, an unreadable event, or no way to prove coverage.
  // Must never be treated as permission to create a key.
  | { kind: "unresolved"; reason: string };

export interface DriveKeyContext {
  store: FileEventStore;
  signer: IdentitySigner;
  /** Read-relay hints for the lookup. */
  relays?: string[];
  /**
   * The relay set the host's lookups fan out to. Required, together with
   * `store.seenOn`, for `empty-confirmed` to ever be emitted: the proof is that
   * EVERY one of these relays answered a control query. Without both, a lookup
   * that finds nothing is `unresolved`.
   */
  configuredRelays?: string[];
  /** Cache-only lookup. Never yields `empty-confirmed` — a cache proves nothing about relays. */
  localOnly?: boolean;
  /** Wait after the local-cache EOSE for the network to answer. Default 3000. */
  settleMs?: number;
  /** Hard cap on one lookup. Default 20000. */
  timeoutMs?: number;
  /** Cap on the relay-coverage control query. Default 5000. */
  proofTimeoutMs?: number;
  signal?: AbortSignal;
  client?: string;
}

export interface DriveKeyMintMarker {
  has(identityPubkey: string): Promise<boolean>;
  record(identityPubkey: string): Promise<void>;
}

export interface MintDriveKeyContext extends DriveKeyContext {
  /**
   * Durable per-identity "already minted" flag, owned by the host (the SDK has no
   * storage). A second `empty-confirmed` verdict later in an identity's life must
   * still refuse to mint again.
   */
  marker?: DriveKeyMintMarker;
}

export interface PublishedDriveKey {
  keyring: DriveKeyring;
  event: Event;
  publishResult: FilePublishResult;
}

/** `empty-confirmed` is a proof about a moment, not the identity — see the TTL rationale in the ADR. */
export const EMPTY_CONFIRMED_TTL_MS = 30_000;

const DEFAULT_SETTLE_MS = 3_000;
const DEFAULT_TIMEOUT_MS = 20_000;
const DEFAULT_PROOF_TIMEOUT_MS = 5_000;

// Broad existence kinds: profile, contacts, relay list, and this protocol's own kind. Any ONE proves
// the identity has been used, independent of whether the Drive Key event specifically is readable.
const EXISTENCE_KINDS = [0, 3, 10002, METADATA_KIND];

export function driveKeyDTag(identityPubkey: string): string {
  return `0:${identityPubkey}`;
}

export function driveKeyEntry(secretKeyHex: string): DriveKeyEntry {
  const secret = hexToBytes(secretKeyHex);
  const publicKey = getPublicKey(secret);
  return { secretKeyHex, publicKey, conversationKey: nip44.v2.utils.getConversationKey(secret, publicKey) };
}

/** Active first, then previous — the order metadata decryption tries them. */
export function keyringEntries(keyring: DriveKeyring): DriveKeyEntry[] {
  return [keyring.active, ...keyring.previous];
}

export function deriveMetadataConversationKey(encryptionKey: string): Uint8Array {
  if (!isValidEncryptionKey(encryptionKey)) {
    throw new Error("Invalid encryption key metadata: /encryptionKey: Expected a valid secp256k1 private key");
  }
  return conversationKeyFromSecret(encryptionKey);
}

const HEX_64 = /^[0-9a-f]{64}$/i;

function usableSecret(value: unknown): value is string {
  return typeof value === "string" && HEX_64.test(value) && isValidEncryptionKey(value);
}

/**
 * Reads every Drive Key payload shape ever written, active key first:
 *  - `{ encryptionKey, previousKeys? }` — current (previousKeys is what rotation adds)
 *  - `[["encryptionKey", hex]]` — legacy array-of-tags; every production key was minted this way
 *    before the keyring rework, and it is still what an existing user's event contains.
 * Returns null when nothing usable is in there. A malformed entry inside `previousKeys` is skipped
 * rather than discarding the whole payload — one bad entry must not hide the good ones.
 */
export function parseDriveKeyPayload(json: string): { active: string; previous: string[] } | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (Array.isArray(parsed)) {
    const tag = parsed.find((t): t is unknown[] => Array.isArray(t) && t.length >= 2 && t[0] === "encryptionKey");
    return usableSecret(tag?.[1]) ? { active: (tag as unknown[])[1] as string, previous: [] } : null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const { encryptionKey, previousKeys } = parsed as { encryptionKey?: unknown; previousKeys?: unknown };
  if (!usableSecret(encryptionKey)) return null;
  const previous = Array.isArray(previousKeys) ? previousKeys.filter(usableSecret) : [];
  return { active: encryptionKey, previous: previous.filter((key) => key !== encryptionKey) };
}

function newestFirst(events: Iterable<Event>): Event[] {
  // NIP-01: on equal created_at the lowest id is the one relays keep.
  return [...events].sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1));
}

function abortError(): DOMException {
  return new DOMException("Operation aborted", "AbortError");
}

interface FetchedDriveKeyEvents {
  events: Event[];
}

function fetchDriveKeyEvents(context: DriveKeyContext, pubkey: string): Promise<FetchedDriveKeyEvents> {
  return new Promise((resolve, reject) => {
    const found = new Map<string, Event>();
    const d = driveKeyDTag(pubkey);
    let settled = false;
    let settleTimer: ReturnType<typeof setTimeout> | undefined;
    let handle: { unobserve(): void } | undefined;

    const cleanup = () => {
      clearTimeout(settleTimer);
      clearTimeout(hardTimer);
      handle?.unobserve();
      context.signal?.removeEventListener("abort", onAbort);
    };
    const finish = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve({ events: newestFirst(found.values()) });
    };
    const onAbort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(abortError());
    };

    // A timeout resolves with whatever arrived — including nothing. It says NOTHING about whether
    // a key exists; the caller must not read an empty result as "confirmed absent".
    const hardTimer = setTimeout(finish, context.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    if (context.signal?.aborted) return onAbort();
    context.signal?.addEventListener("abort", onAbort, { once: true });

    handle = context.store.observe(
      [{ kinds: [METADATA_KIND], authors: [pubkey], "#d": [d] }],
      {
        onEvent(event) {
          if (event.kind !== METADATA_KIND || event.pubkey !== pubkey) return;
          if (!event.tags.some((tag) => tag[0] === "d" && tag[1] === d)) return;
          found.set(event.id, event);
        },
        onEose() {
          // EOSE is the local-cache replay finishing, NOT proof the network answered. Resolving here
          // would let a stale cached copy of the one replaceable event win the race and tear the
          // interest down before a relay can deliver the newer version.
          if (context.localOnly) return finish();
          settleTimer ??= setTimeout(finish, context.settleMs ?? DEFAULT_SETTLE_MS);
        },
      },
      {
        ...(context.relays ? { relays: context.relays } : {}),
        ...(context.localOnly !== undefined ? { localOnly: context.localOnly } : {}),
      },
    );
    if (settled) handle.unobserve();
  });
}

/** Positive per-relay proof that the configured relays answered a control query just now. */
async function proveRelayCoverage(context: DriveKeyContext): Promise<boolean> {
  const { store, configuredRelays } = context;
  if (!store.seenOn || !configuredRelays || configuredRelays.length === 0) return false;
  const seenOn = store.seenOn.bind(store);

  const answeredBy = new Set<string>();
  try {
    const controlEvents = await new Promise<Event[]>((resolve) => {
      const found: Event[] = [];
      let handle: { unobserve(): void } | undefined;
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        handle?.unobserve();
        resolve(found);
      };
      const timer = setTimeout(finish, context.proofTimeoutMs ?? DEFAULT_PROOF_TIMEOUT_MS);
      // Deliberately NOT scoped to this identity: a genuinely new user has no events under any kind,
      // so an author-scoped control would always come back empty and prove nothing about whether
      // relays are even listening.
      handle = store.observe([{ kinds: [1, 0, 3, 10002], limit: 5 }], {
        onEvent: (event) => { found.push(event); },
        onEose: finish,
      }, context.relays ? { relays: context.relays } : undefined);
      if (done) handle.unobserve();
    });
    for (const event of controlEvents) {
      for (const relay of await seenOn(event.id).catch(() => [] as string[])) answeredBy.add(normalizeRelay(relay));
    }
  } catch {
    // Whatever was collected stands; an incomplete answeredBy yields "not covered" below.
  }
  // Full coverage, not a quorum: two relays saying "nothing" proves nothing about the third, silent
  // one — and the silent one is exactly where the key may live.
  return configuredRelays.every((relay) => answeredBy.has(normalizeRelay(relay)));
}

function normalizeRelay(url: string): string {
  return url.trim().replace(/\/+$/, "").toLowerCase();
}

type IdentityHistory = "new" | "existing" | "unknown";

/** Has this identity EVER published anything? Never cached: a stale "new" would authorize a mint. */
async function establishIdentityHistory(context: DriveKeyContext, pubkey: string): Promise<IdentityHistory> {
  const seen = await new Promise<boolean>((resolve) => {
    let found = false;
    let done = false;
    let handle: { unobserve(): void } | undefined;
    const finish = (value: boolean) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      handle?.unobserve();
      resolve(value);
    };
    const timer = setTimeout(() => finish(found), context.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    handle = context.store.observe(
      [{ kinds: EXISTENCE_KINDS, authors: [pubkey], limit: 1 }],
      {
        onEvent() { found = true; finish(true); },
        // The local EOSE says nothing about the network; only a positive sighting is conclusive.
        onEose() { if (context.localOnly) finish(found); },
      },
      {
        ...(context.relays ? { relays: context.relays } : {}),
        ...(context.localOnly !== undefined ? { localOnly: context.localOnly } : {}),
      },
    );
    if (done) handle.unobserve();
  });
  if (seen) return "existing";
  return (await proveRelayCoverage(context)) ? "new" : "unknown";
}

interface Ingested {
  active: string;
  previous: string[];
  newest: Event;
  newestKeys: string[];
  unusable: number;
}

async function ingest(context: DriveKeyContext, pubkey: string, events: Event[]): Promise<Ingested | null> {
  let unusable = 0;
  let result: Ingested | null = null;
  const seen = new Set<string>();
  for (const event of events) {
    let payload: ReturnType<typeof parseDriveKeyPayload> = null;
    try {
      payload = parseDriveKeyPayload(await context.signer.nip44Decrypt(pubkey, event.content));
    } catch {
      // Signer refused or the ciphertext is corrupt: this event is unusable, which is NOT absence.
    }
    if (!payload) {
      unusable += 1;
      continue;
    }
    if (!result) {
      result = { active: payload.active, previous: [], newest: event, newestKeys: [payload.active, ...payload.previous], unusable: 0 };
      seen.add(payload.active);
    } else if (!seen.has(payload.active)) {
      seen.add(payload.active);
      result.previous.push(payload.active);
    }
    for (const key of payload.previous) {
      if (seen.has(key)) continue;
      seen.add(key);
      result.previous.push(key);
    }
  }
  if (result) result.unusable = unusable;
  return result;
}

function toStatus(ingested: Ingested): DriveKeyStatus {
  const union = new Set([ingested.active, ...ingested.previous]);
  return {
    kind: "ready",
    keyring: { active: driveKeyEntry(ingested.active), previous: ingested.previous.map(driveKeyEntry) },
    event: ingested.newest,
    // The newest relay event carries fewer secrets than we can prove exist: an earlier accidental mint
    // replaced a wider event. See healDriveKey.
    stale: ingested.newestKeys.length < union.size,
  };
}

/**
 * Resolves the Drive Key WITHOUT ever creating anything and WITHOUT consulting any cache.
 *
 *  - keys found                                 → `ready`
 *  - events exist but none is usable            → `unresolved` (a key exists; "can't read" ≠ "absent")
 *  - nothing found, identity has history        → `unresolved` (after one retry — its relay list may
 *                                                  have just told the store where to look)
 *  - nothing found, coverage proven, no history → `empty-confirmed`
 *  - anything else, including every timeout     → `unresolved`
 */
export async function resolveDriveKeyStatus(context: DriveKeyContext): Promise<DriveKeyStatus> {
  const pubkey = await context.signer.getPublicKey();

  const first = await fetchDriveKeyEvents(context, pubkey);
  const ingested = await ingest(context, pubkey, first.events);
  if (ingested) return toStatus(ingested);

  if (first.events.length > 0) {
    return {
      kind: "unresolved",
      reason: "A Drive Key event exists for this identity but could not be read (unrecognized format or decrypt failure)",
    };
  }
  if (context.localOnly) {
    return { kind: "unresolved", reason: "Cache-only lookup found no Drive Key; a cache cannot prove absence" };
  }

  const history = await establishIdentityHistory(context, pubkey);
  if (history === "existing") {
    const retry = await fetchDriveKeyEvents(context, pubkey);
    const retried = await ingest(context, pubkey, retry.events);
    if (retried) return toStatus(retried);
    return {
      kind: "unresolved",
      reason: retry.events.length > 0
        ? "A Drive Key event exists for this identity but could not be read"
        : "This identity has published before, but no Drive Key could be found for it (yet)",
    };
  }
  if (history === "new") return { kind: "empty-confirmed" };
  return {
    kind: "unresolved",
    reason: context.store.seenOn && context.configuredRelays?.length
      ? "Not every configured relay answered, so the absence of a Drive Key is not proven"
      : "Relay coverage cannot be proven (no store.seenOn or configuredRelays); the host must decide",
  };
}

export interface DriveKeyStatusCache {
  get(): Promise<DriveKeyStatus>;
  invalidate(): void;
}

/**
 * A read-side cache with the only lifetimes that are safe: `ready` is stable (keys are only ever
 * added), `empty-confirmed` is good for EMPTY_CONFIRMED_TTL_MS, `unresolved` is never cached (it is a
 * statement about right-now connectivity). Concurrent cold callers share one lookup. Keyed by
 * identity: a signer switch drops the entry.
 *
 * Nothing in this package accepts a status from here as input to a mint — mintDriveKey re-resolves.
 */
export function createDriveKeyStatusCache(
  context: DriveKeyContext,
  options: { now?: () => number } = {},
): DriveKeyStatusCache {
  const now = options.now ?? Date.now;
  let entry: { pubkey: string; status: DriveKeyStatus; at: number } | null = null;
  let inFlight: { pubkey: string; promise: Promise<DriveKeyStatus> } | null = null;

  return {
    async get() {
      const pubkey = await context.signer.getPublicKey();
      if (
        entry?.pubkey === pubkey
        && (entry.status.kind === "ready" || (entry.status.kind === "empty-confirmed" && now() - entry.at < EMPTY_CONFIRMED_TTL_MS))
      ) {
        return entry.status;
      }
      if (inFlight?.pubkey === pubkey) return inFlight.promise;
      const promise = resolveDriveKeyStatus(context).then((status) => {
        if (inFlight?.promise === promise) entry = { pubkey, status, at: now() };
        return status;
      });
      inFlight = { pubkey, promise };
      try {
        return await promise;
      } finally {
        if (inFlight?.promise === promise) inFlight = null;
      }
    },
    invalidate() {
      entry = null;
    },
  };
}

// Per-identity guard against two overlapping key publishes. Deliberately not a "never again this
// session" latch: a refusal must be retriable once conditions improve.
const publishing = new Set<string>();

async function withPublishGuard<T>(pubkey: string, run: () => Promise<T>): Promise<T> {
  if (publishing.has(pubkey)) {
    throw new DriveKeyMintRefusedError("Another Drive Key publish is already in flight for this identity", { kind: "in-flight" });
  }
  publishing.add(pubkey);
  try {
    return await run();
  } finally {
    publishing.delete(pubkey);
  }
}

/** Throws unless every secret in `known` is carried by the event about to be published. */
export function assertKeyringPreserved(known: readonly string[], active: string, previous: readonly string[]): void {
  const published = new Set([active, ...previous]);
  const dropped = known.filter((secret) => !published.has(secret));
  if (dropped.length > 0) {
    throw new DriveKeyDroppedError(`Refusing to publish a Drive Key event that drops ${dropped.length} existing key(s)`);
  }
}

/**
 * The ONLY function that publishes a Drive Key event. Every path funnels through here so the
 * no-key-dropped invariant lives in one place: `known` is every secret that must survive.
 */
async function publishKeyring(
  context: DriveKeyContext,
  pubkey: string,
  active: string,
  previous: string[],
  known: readonly string[],
  minCreatedAt: number,
): Promise<PublishedDriveKey> {
  assertKeyringPreserved(known, active, previous);
  const payload: { encryptionKey: string; previousKeys?: string[] } = { encryptionKey: active };
  if (previous.length > 0) payload.previousKeys = previous;

  const content = await context.signer.nip44Encrypt(pubkey, JSON.stringify(payload));
  const event = await context.signer.signEvent({
    kind: METADATA_KIND,
    // Must also beat the event being replaced, whatever its own timestamp is.
    created_at: Math.max(nextCreatedAt(), minCreatedAt + 1),
    tags: [["d", driveKeyDTag(pubkey)], ["client", context.client ?? DRIVE_SDK_CLIENT]],
    content,
  });
  if (event.pubkey !== pubkey) throw new Error("Signer returned a Drive Key event for a different pubkey");
  const publishResult = await context.store.publishEvent(event, context.relays ? { relays: context.relays } : undefined);
  if (!publishResult.ok) throw new Error("No relay accepted the Drive Key event");
  return {
    keyring: { active: driveKeyEntry(active), previous: previous.map(driveKeyEntry) },
    event,
    publishResult,
  };
}

/**
 * Creates the first Drive Key. Refuses unless a lookup started RIGHT HERE reports `empty-confirmed`.
 * There is no parameter for a status: a cached or stale verdict cannot be passed in, because acting
 * on one publishes a key over one that exists but was unreachable, destroying it on every relay that
 * accepts the publish.
 */
export async function mintDriveKey(context: MintDriveKeyContext): Promise<PublishedDriveKey> {
  const pubkey = await context.signer.getPublicKey();
  return withPublishGuard(pubkey, async () => {
    if (await context.marker?.has(pubkey)) {
      throw new DriveKeyMintRefusedError("A Drive Key was already minted for this identity", { kind: "already-minted" });
    }
    const status = await resolveDriveKeyStatus(context);
    if (status.kind !== "empty-confirmed") {
      throw new DriveKeyMintRefusedError(
        status.kind === "ready"
          ? "A Drive Key already exists for this identity"
          : `Not minting: ${status.reason}`,
        status,
      );
    }
    const minted = await publishKeyring(context, pubkey, bytesToHex(generateSecretKey()), [], [], 0);
    // Not recorded on failure: a new user whose first mint hit a network blip must be able to retry.
    await context.marker?.record(pubkey);
    return minted;
  });
}

export interface RotateDriveKeyOptions {
  /** Adopt this secret as the new active key (recovery/migration). Default: a fresh random key. */
  encryptionKey?: string;
}

/**
 * Makes a new key active and moves the old active key into `previousKeys`. The keyring is resolved
 * uncached first and must be `ready`; nothing already in it can be dropped. Files encrypted under the
 * old key stay readable because the old key is still in the event.
 */
export async function rotateDriveKey(
  context: DriveKeyContext,
  options: RotateDriveKeyOptions = {},
): Promise<PublishedDriveKey> {
  const pubkey = await context.signer.getPublicKey();
  const next = options.encryptionKey ?? bytesToHex(generateSecretKey());
  if (!usableSecret(next)) throw new Error("Invalid encryption key: expected a valid secp256k1 private key");
  return withPublishGuard(pubkey, async () => {
    const status = await resolveDriveKeyStatus(context);
    if (status.kind !== "ready") throw new DriveKeyUnavailableError(status);
    const known = keyringEntries(status.keyring).map((entry) => entry.secretKeyHex);
    const previous = known.filter((secret) => secret !== next);
    return publishKeyring(context, pubkey, next, previous, known, status.event.created_at);
  });
}

/**
 * Republishes a merged event when the newest relay event carries fewer keys than are provably held
 * (an earlier accidental mint replaced a wider one). Only ever ADDS: it needs a `ready` keyring and
 * publishes the union with the current active key unchanged. Returns null when nothing needed healing.
 */
export async function healDriveKey(context: DriveKeyContext): Promise<PublishedDriveKey | null> {
  const pubkey = await context.signer.getPublicKey();
  return withPublishGuard(pubkey, async () => {
    const status = await resolveDriveKeyStatus(context);
    if (status.kind !== "ready") throw new DriveKeyUnavailableError(status);
    if (!status.stale) return null;
    const known = keyringEntries(status.keyring).map((entry) => entry.secretKeyHex);
    return publishKeyring(context, pubkey, known[0]!, known.slice(1), known, status.event.created_at);
  });
}
