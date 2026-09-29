import { generateSecretKey, getPublicKey, nip44, type Event } from "nostr-tools";
import { bytesToHex } from "nostr-tools/utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  assertKeyringPreserved,
  createDriveKeyStatusCache,
  DriveKeyDroppedError,
  driveKeyDTag,
  driveKeyEntry,
  DriveKeyMintRefusedError,
  DriveKeyUnavailableError,
  EMPTY_CONFIRMED_TTL_MS,
  healDriveKey,
  keyringEntries,
  METADATA_KIND,
  mintDriveKey,
  deriveMetadataConversationKey,
  parseDriveKeyPayload,
  resolveDriveKeyStatus,
  rotateDriveKey,
  type DriveKeyContext,
  type DriveKeyMintMarker,
} from "../src/index.js";
import { FakeRelay, flush, makeIdentity } from "./helpers.js";

const KEY_A = "01".repeat(32);
const KEY_B = "02".repeat(32);
const KEY_C = "03".repeat(32);

const identity = makeIdentity(9);
const RELAYS = ["wss://relay.one", "wss://relay.two"];

async function keyEvent(payload: unknown, createdAt: number, signer = identity): Promise<Event> {
  const content = await signer.nip44Encrypt(signer.pubkey, JSON.stringify(payload));
  return signer.signEvent({
    kind: METADATA_KIND,
    created_at: createdAt,
    tags: [["d", driveKeyDTag(signer.pubkey)], ["client", "formstr-drive"]],
    content,
  });
}

function context(store: FakeRelay, extra: Partial<DriveKeyContext> = {}): DriveKeyContext {
  return { store, signer: identity, settleMs: 5, timeoutMs: 60, proofTimeoutMs: 20, ...extra };
}

/** A store that can prove coverage: every configured relay "saw" the control events. */
function provingRelay(covered: string[] = RELAYS): FakeRelay {
  const relay = new FakeRelay({ seenOn: () => covered });
  relay.add(makeControlEvent());
  return relay;
}

function makeControlEvent(): Event {
  const other = makeIdentity(77);
  return {
    id: "c".repeat(64),
    pubkey: other.pubkey,
    created_at: 1,
    kind: 1,
    tags: [],
    content: "hello",
    sig: "0".repeat(128),
  };
}

describe("parseDriveKeyPayload", () => {
  it("reads the current object shape with and without previousKeys", () => {
    expect(parseDriveKeyPayload(JSON.stringify({ encryptionKey: KEY_A }))).toEqual({ active: KEY_A, previous: [] });
    expect(parseDriveKeyPayload(JSON.stringify({ encryptionKey: KEY_A, previousKeys: [KEY_B, KEY_C] })))
      .toEqual({ active: KEY_A, previous: [KEY_B, KEY_C] });
  });

  it("reads the legacy array-of-tags shape", () => {
    expect(parseDriveKeyPayload(JSON.stringify([["encryptionKey", KEY_A]]))).toEqual({ active: KEY_A, previous: [] });
    expect(parseDriveKeyPayload(JSON.stringify([["other", "x"], ["encryptionKey", KEY_B, "extra"]])))
      .toEqual({ active: KEY_B, previous: [] });
  });

  it("skips malformed previousKeys entries instead of discarding the payload", () => {
    const bad = "0".repeat(64); // not a valid secp256k1 scalar
    expect(parseDriveKeyPayload(JSON.stringify({ encryptionKey: KEY_A, previousKeys: [KEY_B, "nope", 5, bad, KEY_A] })))
      .toEqual({ active: KEY_A, previous: [KEY_B] });
    expect(parseDriveKeyPayload(JSON.stringify({ encryptionKey: KEY_A, previousKeys: "x" })))
      .toEqual({ active: KEY_A, previous: [] });
  });

  it("returns null for anything without a usable active key", () => {
    for (const json of [
      "not json",
      "null",
      "42",
      "{}",
      JSON.stringify({ encryptionKey: "short" }),
      JSON.stringify({ encryptionKey: "0".repeat(64) }),
      JSON.stringify([["encryptionKey", "short"]]),
      JSON.stringify([["encryptionKey"]]),
      JSON.stringify([]),
    ]) {
      expect(parseDriveKeyPayload(json)).toBeNull();
    }
  });
});

describe("key helpers", () => {
  it("derives entries and the metadata conversation key", () => {
    const entry = driveKeyEntry(KEY_A);
    expect(entry.publicKey).toBe(getPublicKey(Uint8Array.from(Buffer.from(KEY_A, "hex"))));
    expect(entry.conversationKey).toEqual(deriveMetadataConversationKey(KEY_A));
    expect(() => deriveMetadataConversationKey("0".repeat(64))).toThrow("valid secp256k1");
    expect(keyringEntries({ active: entry, previous: [driveKeyEntry(KEY_B)] }).map((e) => e.secretKeyHex)).toEqual([KEY_A, KEY_B]);
  });

  it("assertKeyringPreserved rejects any publish that drops a known key", () => {
    expect(() => assertKeyringPreserved([KEY_A, KEY_B], KEY_C, [KEY_A, KEY_B])).not.toThrow();
    expect(() => assertKeyringPreserved([KEY_A, KEY_B], KEY_C, [KEY_A])).toThrow(DriveKeyDroppedError);
  });
});

describe("resolveDriveKeyStatus", () => {
  it("is ready for each payload shape and exposes active + previous", async () => {
    for (const payload of [
      { encryptionKey: KEY_A },
      { encryptionKey: KEY_A, previousKeys: [KEY_B] },
      [["encryptionKey", KEY_A]],
    ]) {
      const relay = new FakeRelay().add(await keyEvent(payload, 10));
      const status = await resolveDriveKeyStatus(context(relay));
      expect(status.kind).toBe("ready");
      if (status.kind !== "ready") throw new Error("unreachable");
      expect(status.keyring.active.secretKeyHex).toBe(KEY_A);
      expect(status.keyring.previous.map((k) => k.secretKeyHex)).toEqual(Array.isArray(payload) || !("previousKeys" in payload) ? [] : [KEY_B]);
      expect(status.stale).toBe(false);
    }
  });

  it("asks the store for exactly the identity's own Drive Key coordinate, with hints", async () => {
    const relay = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A }, 10));
    await resolveDriveKeyStatus(context(relay, { relays: RELAYS }));
    expect(relay.observations[0]!.filters).toEqual([
      { kinds: [METADATA_KIND], authors: [identity.pubkey], "#d": [driveKeyDTag(identity.pubkey)] },
    ]);
    expect(relay.observations[0]!.options).toEqual({ relays: RELAYS });
    expect(relay.observations.every((o) => o.unobserved)).toBe(true);
  });

  it("takes the active key from the newest event and unions older keys, flagging a narrower newest event as stale", async () => {
    const relay = new FakeRelay().add(
      await keyEvent({ encryptionKey: KEY_B }, 20), // newest carries only B
      await keyEvent({ encryptionKey: KEY_A, previousKeys: [KEY_C] }, 10),
    );
    const status = await resolveDriveKeyStatus(context(relay));
    if (status.kind !== "ready") throw new Error("expected ready");
    expect(status.keyring.active.secretKeyHex).toBe(KEY_B);
    expect(status.keyring.previous.map((k) => k.secretKeyHex)).toEqual([KEY_A, KEY_C]);
    expect(status.stale).toBe(true);
    expect(status.event.created_at).toBe(20);
  });

  it("waits past the local EOSE so a newer network event beats a stale cached one", async () => {
    const relay = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A }, 10));
    relay.arrivals = [await keyEvent({ encryptionKey: KEY_B, previousKeys: [KEY_A] }, 20)];
    const status = await resolveDriveKeyStatus(context(relay));
    if (status.kind !== "ready") throw new Error("expected ready");
    expect(status.keyring.active.secretKeyHex).toBe(KEY_B);
  });

  it("localOnly finishes at EOSE and can never be empty-confirmed", async () => {
    const found = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A }, 10));
    expect((await resolveDriveKeyStatus(context(found, { localOnly: true }))).kind).toBe("ready");
    expect(found.observations[0]!.options).toEqual({ localOnly: true });

    const empty = provingRelay();
    const status = await resolveDriveKeyStatus(context(empty, { localOnly: true, configuredRelays: RELAYS }));
    expect(status).toMatchObject({ kind: "unresolved" });
  });

  describe("REGRESSION: a timeout is never empty", () => {
    it("a silent network is unresolved even when the host supplied everything needed to prove coverage", async () => {
      const relay = new FakeRelay({ silent: true, seenOn: () => RELAYS });
      const status = await resolveDriveKeyStatus(context(relay, { configuredRelays: RELAYS, timeoutMs: 15, proofTimeoutMs: 15 }));
      expect(status.kind).toBe("unresolved");
    });

    it("a silent network with no proof capability is unresolved", async () => {
      const status = await resolveDriveKeyStatus(context(new FakeRelay({ silent: true }), { timeoutMs: 15 }));
      expect(status).toMatchObject({ kind: "unresolved" });
    });

    it("an empty store that cannot prove coverage is unresolved, and says why", async () => {
      const status = await resolveDriveKeyStatus(context(new FakeRelay()));
      expect(status).toMatchObject({ kind: "unresolved", reason: expect.stringContaining("cannot be proven") });
    });
  });

  it("events that exist but cannot be read are unresolved — 'cannot read' is not 'absent'", async () => {
    const stranger = makeIdentity(55);
    // Right coordinate and author, but encrypted so that our signer cannot decrypt it.
    const undecryptable = await identity.signEvent({
      kind: METADATA_KIND,
      created_at: 10,
      tags: [["d", driveKeyDTag(identity.pubkey)]],
      content: await stranger.nip44Encrypt(identity.pubkey, JSON.stringify({ encryptionKey: KEY_A })),
    });
    const relay = new FakeRelay().add(undecryptable);
    const garbled = new FakeRelay().add(await keyEvent({ nothing: true }, 10));
    for (const store of [relay, garbled]) {
      const status = await resolveDriveKeyStatus(context(store, { configuredRelays: RELAYS }));
      expect(status).toMatchObject({ kind: "unresolved", reason: expect.stringContaining("could not be read") });
    }
  });

  it("ignores events for other authors or coordinates", async () => {
    const other = makeIdentity(66);
    const relay = new FakeRelay();
    // Bypass the fake's filter matching by delivering directly through arrivals of a different d.
    relay.add(await keyEvent({ encryptionKey: KEY_A }, 10, other));
    const status = await resolveDriveKeyStatus(context(relay));
    expect(status.kind).toBe("unresolved");
  });

  it("is empty-confirmed only when every configured relay answered the control query", async () => {
    const status = await resolveDriveKeyStatus(context(provingRelay(), { configuredRelays: RELAYS }));
    expect(status).toEqual({ kind: "empty-confirmed" });
  });

  it("normalizes relay URLs when comparing coverage", async () => {
    const relay = provingRelay(["WSS://Relay.One/", "wss://relay.two"]);
    expect(await resolveDriveKeyStatus(context(relay, { configuredRelays: RELAYS }))).toEqual({ kind: "empty-confirmed" });
  });

  it("partial coverage stays unresolved", async () => {
    const status = await resolveDriveKeyStatus(context(provingRelay(["wss://relay.one"]), { configuredRelays: RELAYS }));
    expect(status).toMatchObject({ kind: "unresolved", reason: expect.stringContaining("Not every configured relay") });
  });

  it("does not prove coverage without configuredRelays, without seenOn, or when seenOn throws", async () => {
    expect((await resolveDriveKeyStatus(context(provingRelay()))).kind).toBe("unresolved");
    const noSeenOn = new FakeRelay().add(makeControlEvent());
    expect((await resolveDriveKeyStatus(context(noSeenOn, { configuredRelays: RELAYS }))).kind).toBe("unresolved");
    const throwing = new FakeRelay({ seenOn: () => { throw new Error("boom"); } }).add(makeControlEvent());
    expect((await resolveDriveKeyStatus(context(throwing, { configuredRelays: RELAYS }))).kind).toBe("unresolved");
  });

  it("an identity with history but no Drive Key is unresolved, never empty", async () => {
    const profile = { ...makeControlEvent(), pubkey: identity.pubkey, kind: 0, id: "d".repeat(64) };
    const relay = provingRelay().add(profile);
    const status = await resolveDriveKeyStatus(context(relay, { configuredRelays: RELAYS }));
    expect(status).toMatchObject({ kind: "unresolved", reason: expect.stringContaining("published before") });
  });

  it("retries once after finding history, because the relay list may have just told the store where to look", async () => {
    const profile = { ...makeControlEvent(), pubkey: identity.pubkey, kind: 0, id: "d".repeat(64) };
    const relay = new FakeRelay().add(profile);
    const late = await keyEvent({ encryptionKey: KEY_A }, 10);
    let calls = 0;
    const observe = relay.observe.bind(relay);
    relay.observe = (filters, handlers, options) => {
      if (filters[0]?.["#d"]) {
        calls += 1;
        if (calls === 2) relay.add(late); // only the retry can see it
      }
      return observe(filters, handlers, options);
    };
    const status = await resolveDriveKeyStatus(context(relay));
    expect(status.kind).toBe("ready");
    expect(calls).toBe(2);
  });

  it("history plus an unreadable event on retry is unresolved", async () => {
    const profile = { ...makeControlEvent(), pubkey: identity.pubkey, kind: 0, id: "d".repeat(64) };
    const relay = new FakeRelay().add(profile);
    const garbled = await keyEvent({ nothing: true }, 10);
    let calls = 0;
    const observe = relay.observe.bind(relay);
    relay.observe = (filters, handlers, options) => {
      if (filters[0]?.["#d"]) {
        calls += 1;
        if (calls === 2) relay.add(garbled);
      }
      return observe(filters, handlers, options);
    };
    const status = await resolveDriveKeyStatus(context(relay));
    expect(status).toMatchObject({ kind: "unresolved", reason: expect.stringContaining("could not be read") });
  });

  it("history is looked for cache-only when localOnly (never reached: localOnly returns earlier)", async () => {
    const status = await resolveDriveKeyStatus(context(new FakeRelay(), { localOnly: true }));
    expect(status.kind).toBe("unresolved");
  });

  it("honors an already-aborted or later-aborted signal", async () => {
    const pre = new AbortController();
    pre.abort();
    await expect(resolveDriveKeyStatus(context(new FakeRelay({ silent: true }), { signal: pre.signal })))
      .rejects.toMatchObject({ name: "AbortError" });

    const later = new AbortController();
    const promise = resolveDriveKeyStatus(context(new FakeRelay({ silent: true }), { signal: later.signal, timeoutMs: 1000 }));
    await flush();
    later.abort();
    await expect(promise).rejects.toMatchObject({ name: "AbortError" });
  });
});

describe("mintDriveKey", () => {
  it("publishes a fresh key signed by the identity, once coverage is proven", async () => {
    const relay = provingRelay();
    const marker: DriveKeyMintMarker = { has: vi.fn(async () => false), record: vi.fn(async () => {}) };
    const minted = await mintDriveKey({ ...context(relay, { configuredRelays: RELAYS, relays: RELAYS }), marker });

    expect(relay.published).toHaveLength(1);
    const { event, relays } = relay.published[0]!;
    expect(relays).toEqual(RELAYS);
    expect(event.pubkey).toBe(identity.pubkey); // identity signs the Drive Key event itself
    expect(event.tags).toEqual([["d", driveKeyDTag(identity.pubkey)], ["client", "formstr-drive-sdk"]]);
    const payload = JSON.parse(await identity.nip44Decrypt(identity.pubkey, event.content));
    expect(payload).toEqual({ encryptionKey: minted.keyring.active.secretKeyHex });
    expect(minted.keyring.previous).toEqual([]);
    expect(marker.record).toHaveBeenCalledWith(identity.pubkey);
  });

  it("refuses when a key already exists", async () => {
    const relay = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A }, 10));
    const error = await mintDriveKey(context(relay)).catch((e) => e);
    expect(error).toBeInstanceOf(DriveKeyMintRefusedError);
    expect(error.status.kind).toBe("ready");
    expect(relay.published).toHaveLength(0);
  });

  it("refuses when the verdict is unresolved (timeout, unreachable relays)", async () => {
    const relay = new FakeRelay({ silent: true });
    const error = await mintDriveKey(context(relay, { timeoutMs: 15 })).catch((e) => e);
    expect(error).toBeInstanceOf(DriveKeyMintRefusedError);
    expect(error.status.kind).toBe("unresolved");
    expect(relay.published).toHaveLength(0);
  });

  it("refuses when the durable marker says this identity already minted", async () => {
    const relay = provingRelay();
    const marker = { has: async () => true, record: vi.fn() };
    const error = await mintDriveKey({ ...context(relay, { configuredRelays: RELAYS }), marker }).catch((e) => e);
    expect(error.status).toEqual({ kind: "already-minted" });
    expect(relay.published).toHaveLength(0);
  });

  it("does not record the marker when the publish fails, so a new user can retry", async () => {
    const relay = new FakeRelay({ seenOn: () => RELAYS, publishResult: { ok: false, accepted: 0, total: 1, relayResults: [] } });
    relay.add(makeControlEvent());
    const marker = { has: async () => false, record: vi.fn() };
    await expect(mintDriveKey({ ...context(relay, { configuredRelays: RELAYS }), marker })).rejects.toThrow("No relay accepted");
    expect(marker.record).not.toHaveBeenCalled();
  });

  it("refuses an overlapping mint for the same identity", async () => {
    const relay = provingRelay();
    const ctx = context(relay, { configuredRelays: RELAYS });
    const first = mintDriveKey(ctx);
    const second = await mintDriveKey(ctx).catch((e) => e);
    expect(second.status).toEqual({ kind: "in-flight" });
    await first;
    expect(relay.published).toHaveLength(1);
  });

  it("rejects a signer that returns an event for a different pubkey", async () => {
    const relay = provingRelay();
    const rogue = { ...identity, signEvent: async (t: Parameters<typeof identity.signEvent>[0]) => makeIdentity(3).signEvent(t) };
    await expect(mintDriveKey({ ...context(relay, { configuredRelays: RELAYS }), signer: rogue })).rejects.toThrow("different pubkey");
  });

  describe("REGRESSION: never acts on a cached or stale verdict", () => {
    it("re-resolves at mint time even though the cache still says empty-confirmed", async () => {
      const relay = provingRelay();
      const ctx = context(relay, { configuredRelays: RELAYS });
      const cache = createDriveKeyStatusCache(ctx);
      expect((await cache.get()).kind).toBe("empty-confirmed");

      // A relay that was unreachable comes back carrying the real key.
      relay.add(await keyEvent({ encryptionKey: KEY_A }, 10));
      expect((await cache.get()).kind).toBe("empty-confirmed"); // the cache is now stale…

      const error = await mintDriveKey(ctx).catch((e) => e); // …and must not be able to authorize this.
      expect(error).toBeInstanceOf(DriveKeyMintRefusedError);
      expect(error.status.kind).toBe("ready");
      expect(relay.published).toHaveLength(0);
    });

    it("exposes no way to hand mintDriveKey a status", () => {
      expect(mintDriveKey.length).toBe(1);
    });
  });
});

describe("rotateDriveKey", () => {
  it("moves the old active key into previousKeys and keeps every older key", async () => {
    const relay = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A, previousKeys: [KEY_B] }, 10));
    const rotated = await rotateDriveKey(context(relay), { encryptionKey: KEY_C });

    expect(rotated.keyring.active.secretKeyHex).toBe(KEY_C);
    expect(rotated.keyring.previous.map((k) => k.secretKeyHex)).toEqual([KEY_A, KEY_B]);
    const payload = JSON.parse(await identity.nip44Decrypt(identity.pubkey, relay.publishedEvents[0]!.content));
    expect(payload).toEqual({ encryptionKey: KEY_C, previousKeys: [KEY_A, KEY_B] });
  });

  it("generates a fresh key by default and always supersedes the event it replaces", async () => {
    const relay = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A }, 4_000_000_000));
    const rotated = await rotateDriveKey(context(relay));
    expect(rotated.keyring.active.secretKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(rotated.keyring.active.secretKeyHex).not.toBe(KEY_A);
    expect(rotated.event.created_at).toBeGreaterThan(4_000_000_000);
  });

  it("re-adopting an existing previous key as active does not duplicate or drop anything", async () => {
    const relay = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A, previousKeys: [KEY_B] }, 10));
    const rotated = await rotateDriveKey(context(relay), { encryptionKey: KEY_B });
    expect(rotated.keyring.active.secretKeyHex).toBe(KEY_B);
    expect(rotated.keyring.previous.map((k) => k.secretKeyHex)).toEqual([KEY_A]);
  });

  it("refuses to rotate when the keyring is not resolved, rather than publishing a key with an empty history", async () => {
    const relay = new FakeRelay({ silent: true });
    const error = await rotateDriveKey(context(relay, { timeoutMs: 15 })).catch((e) => e);
    expect(error).toBeInstanceOf(DriveKeyUnavailableError);
    expect(error.message).toContain("unresolved");
    expect(relay.published).toHaveLength(0);

    const empty = await rotateDriveKey(context(provingRelay(), { configuredRelays: RELAYS })).catch((e) => e);
    expect(empty).toBeInstanceOf(DriveKeyUnavailableError);
    expect(empty.message).toContain("No Drive Key exists");
  });

  it("rejects an invalid supplied key before touching the network", async () => {
    const relay = new FakeRelay();
    await expect(rotateDriveKey(context(relay), { encryptionKey: "0".repeat(64) })).rejects.toThrow("valid secp256k1");
    expect(relay.observations).toHaveLength(0);
  });

  it("round-trips: what rotation publishes resolves back to the same keyring", async () => {
    const relay = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A }, 10));
    const rotated = await rotateDriveKey(context(relay));
    const status = await resolveDriveKeyStatus(context(relay));
    if (status.kind !== "ready") throw new Error("expected ready");
    expect(status.keyring.active.secretKeyHex).toBe(rotated.keyring.active.secretKeyHex);
    expect(status.keyring.previous.map((k) => k.secretKeyHex)).toEqual([KEY_A]);
  });
});

describe("healDriveKey", () => {
  it("republishes the union when the newest relay event is narrower than what is provably held", async () => {
    const relay = new FakeRelay().add(
      await keyEvent({ encryptionKey: KEY_B }, 20),
      await keyEvent({ encryptionKey: KEY_A }, 10),
    );
    const healed = await healDriveKey(context(relay));
    expect(healed?.keyring.active.secretKeyHex).toBe(KEY_B);
    expect(healed?.keyring.previous.map((k) => k.secretKeyHex)).toEqual([KEY_A]);
    expect(healed!.event.created_at).toBeGreaterThan(20);
  });

  it("does nothing when the newest event is already complete, and refuses when unresolved", async () => {
    const complete = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A }, 10));
    expect(await healDriveKey(context(complete))).toBeNull();
    expect(complete.published).toHaveLength(0);
    await expect(healDriveKey(context(new FakeRelay({ silent: true }), { timeoutMs: 15 }))).rejects.toBeInstanceOf(DriveKeyUnavailableError);
  });
});

describe("createDriveKeyStatusCache", () => {
  beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));
  afterEach(() => vi.useRealTimers());

  it("caches ready keyrings indefinitely", async () => {
    const relay = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A }, 10));
    const cache = createDriveKeyStatusCache(context(relay));
    const first = await cache.get();
    vi.setSystemTime(Date.now() + 10 * EMPTY_CONFIRMED_TTL_MS);
    expect(await cache.get()).toBe(first);
    expect(relay.observations.filter((o) => o.filters[0]?.["#d"])).toHaveLength(1);
  });

  it("caches empty-confirmed only for the TTL", async () => {
    const relay = provingRelay();
    const cache = createDriveKeyStatusCache(context(relay, { configuredRelays: RELAYS }));
    expect((await cache.get()).kind).toBe("empty-confirmed");
    const lookups = () => relay.observations.filter((o) => o.filters[0]?.["#d"]).length;
    expect(lookups()).toBe(1);
    vi.setSystemTime(Date.now() + EMPTY_CONFIRMED_TTL_MS - 1);
    await cache.get();
    expect(lookups()).toBe(1);
    vi.setSystemTime(Date.now() + 2);
    await cache.get();
    expect(lookups()).toBe(2);
  });

  it("never caches unresolved", async () => {
    const relay = new FakeRelay();
    const cache = createDriveKeyStatusCache(context(relay));
    expect((await cache.get()).kind).toBe("unresolved");
    expect((await cache.get()).kind).toBe("unresolved");
    expect(relay.observations.filter((o) => o.filters[0]?.["#d"])).toHaveLength(2);
  });

  it("shares one lookup between concurrent cold callers and supports invalidate()", async () => {
    const relay = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A }, 10));
    const cache = createDriveKeyStatusCache(context(relay));
    const [a, b] = await Promise.all([cache.get(), cache.get()]);
    expect(a).toBe(b);
    expect(relay.observations.filter((o) => o.filters[0]?.["#d"])).toHaveLength(1);
    cache.invalidate();
    await cache.get();
    expect(relay.observations.filter((o) => o.filters[0]?.["#d"])).toHaveLength(2);
  });

  it("drops the entry when the signed-in identity changes", async () => {
    const relay = new FakeRelay().add(await keyEvent({ encryptionKey: KEY_A }, 10));
    let current = identity;
    const signer = { ...identity, getPublicKey: async () => current.pubkey, nip44Decrypt: (p: string, c: string) => current.nip44Decrypt(p, c) };
    const cache = createDriveKeyStatusCache({ ...context(relay), signer });
    expect((await cache.get()).kind).toBe("ready");
    current = makeIdentity(11);
    expect((await cache.get()).kind).toBe("unresolved"); // the new identity must not inherit the old keyring
  });
});

describe("secrets", () => {
  it("generated keys are valid secp256k1 secrets", () => {
    const hex = bytesToHex(generateSecretKey());
    expect(() => nip44.v2.utils.getConversationKey(Uint8Array.from(Buffer.from(hex, "hex")), getPublicKey(Uint8Array.from(Buffer.from(hex, "hex"))))).not.toThrow();
  });
});
