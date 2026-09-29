import { getPublicKey, nip19, nip44, type Event } from "nostr-tools";
import { hexToBytes } from "nostr-tools/utils";
import { describe, expect, it, vi } from "vitest";
import {
  buildCoordinate,
  buildEvent,
  createFileShare,
  decodePointer,
  decodeShareLink,
  driveKeyEntry,
  encodeShareLink,
  ensureFileShare,
  FolderShareUnsupportedError,
  InvalidShareLinkError,
  LegacyChunkedFileError,
  listShares,
  METADATA_KIND,
  parseCoordinate,
  readFileMetadata,
  relaysFromPublish,
  resolveShare,
  revokeShare,
  ShareKeyMissingError,
  ShareNotFoundError,
  type DriveKeyring,
  type FileEntry,
  type ShareContext,
  type SharedByMeEntry,
} from "../src/index.js";
import { FakeRelay, flush, okResult } from "./helpers.js";

const KEY_NEW = "06".repeat(32);
const KEY_OLD = "05".repeat(32);
const FILE_KEY = "07".repeat(32);
const keyring: DriveKeyring = { active: driveKeyEntry(KEY_NEW), previous: [driveKeyEntry(KEY_OLD)] };

const specFile = {
  name: "spec.txt",
  unencryptedFileHash: "a".repeat(64),
  size: 10,
  type: "text/plain",
  parent: "folder1",
  uploadedAt: 1_700_000_000_000,
  servers: ["https://one.example"],
  encryptionKey: FILE_KEY,
  encryptionAlgorithm: "aes-gcm",
  blobHash: "b".repeat(64),
  chunkSize: 4,
};

function fileEntry(id = "file1", raw: Record<string, unknown> = specFile): FileEntry {
  return readFileMetadata(raw, { id, author: keyring.active.publicKey, createdAt: 1 });
}

function ctx(store: FakeRelay, extra: Partial<ShareContext> = {}): ShareContext {
  return { store, keyring, quietMs: 5, timeoutMs: 80, ...extra };
}

const RELAY_A = "wss://relay.a";
const RELAY_B = "wss://relay.b";

describe("share link codec", () => {
  const pubkey = keyring.active.publicKey;
  const k = "ab".repeat(32);

  it("round-trips #shared=<naddr>&k=<hex>, and stock nip19 decodes the naddr", () => {
    const link = encodeShareLink({ pubkey, d: "s-1234abcd", relays: [RELAY_A], secretKeyHex: k });
    expect(link).toMatch(/^#shared=naddr1[0-9a-z]+&k=[0-9a-f]{64}$/);
    const decoded = decodeShareLink(link)!;
    expect(decoded.k).toBe(k);
    // No SDK code in this decode path:
    const stock = nip19.decode(decoded.naddr);
    expect(stock.type).toBe("naddr");
    expect(stock.data).toEqual({ kind: 34578, pubkey, identifier: "s-1234abcd", relays: [RELAY_A] });
    expect(decodePointer(decoded.naddr)).toEqual({ kind: 34578, pubkey, d: "s-1234abcd", relays: [RELAY_A] });
  });

  it("accepts a full URL and honors baseUrl", () => {
    const link = encodeShareLink({ pubkey, d: "s-1", relays: [], secretKeyHex: k, baseUrl: "https://drive.example/app" });
    expect(link.startsWith("https://drive.example/app#shared=naddr1")).toBe(true);
    expect(decodeShareLink(link)?.k).toBe(k);
  });

  it("decode returns null — never throws — for anything malformed or the wrong kind", () => {
    const good = encodeShareLink({ pubkey, d: "s-1", relays: [], secretKeyHex: k });
    const naddr = decodeShareLink(good)!.naddr;
    const wrongKind = nip19.naddrEncode({ kind: 30023, pubkey, identifier: "x", relays: [] });
    for (const input of [
      "",
      "#other=1",
      "#shared=",
      `#shared=${naddr}`, // no key
      `#shared=${naddr}&k=`,
      `#shared=${naddr}&k=short`,
      `#shared=${naddr}&k=${"z".repeat(64)}`,
      `#shared=&k=${k}`,
      `#shared=notanaddr&k=${k}`,
      `#shared=${wrongKind}&k=${k}`,
      `#shared=${nip19.npubEncode(pubkey)}&k=${k}`,
    ]) {
      expect(() => decodeShareLink(input)).not.toThrow();
      expect(decodeShareLink(input), input).toBeNull();
    }
    expect(decodePointer("garbage")).toBeNull();
    expect(decodePointer(wrongKind)).toBeNull();
  });

  it("refuses to encode a malformed key, and coordinates parse strictly", () => {
    expect(() => encodeShareLink({ pubkey, d: "x", relays: [], secretKeyHex: "nope" })).toThrow("64 hex");
    expect(buildCoordinate(pubkey, "a:b")).toBe(`34578:${pubkey}:a:b`);
    expect(parseCoordinate(`34578:${pubkey}:a:b`)).toEqual({ kind: 34578, pubkey, d: "a:b" });
    expect(() => parseCoordinate("nope")).toThrow("Malformed");
  });
});

describe("relaysFromPublish", () => {
  it("keeps accepted relays only, deduplicated", () => {
    expect(relaysFromPublish({
      ok: true, accepted: 2, total: 4,
      relayResults: [
        { relay: RELAY_A, status: "accepted" },
        { relay: "wss://rejected", status: "rejected" },
        { relay: "wss://slow", status: "timeout" },
        { relay: RELAY_A, status: "accepted" },
        { relay: RELAY_B, status: "accepted" },
      ],
    })).toEqual([RELAY_A, RELAY_B]);
  });
});

describe("createFileShare", () => {
  it("publishes a Drive-Key-signed shared-file event the link's key decrypts (stock nostr-tools only)", async () => {
    const relay = new FakeRelay({ publishResult: okResult(RELAY_A, RELAY_B) });
    const result = await createFileShare(fileEntry(), ctx(relay));

    const [shareEvent, infoEvent] = relay.publishedEvents;
    expect(shareEvent!.pubkey).toBe(keyring.active.publicKey);
    const d = shareEvent!.tags[0]![1]!;
    expect(d).toMatch(/^s-[0-9a-f]{8}$/);
    expect(shareEvent!.tags.map((t) => t[0])).toEqual(["d", "t", "client", "encrypted"]);
    expect(shareEvent!.tags[1]).toEqual(["t", "shared-file"]);
    expect(shareEvent!.tags[3]).toEqual(["encrypted", "nip44"]);
    expect(result.coordinate).toBe(buildCoordinate(keyring.active.publicKey, d));

    // Decode the link and decrypt with nothing but nostr-tools.
    const [, naddr, k] = /^#shared=([^&]+)&k=(.+)$/.exec(result.url)!;
    const pointer = nip19.decode(naddr!);
    expect(pointer.type === "naddr" && pointer.data.identifier).toBe(d);
    expect(pointer.type === "naddr" && pointer.data.relays).toEqual([RELAY_A, RELAY_B]);
    const secret = hexToBytes(k!);
    const plaintext = nip44.v2.decrypt(shareEvent!.content, nip44.v2.utils.getConversationKey(secret, getPublicKey(secret)));
    expect(JSON.parse(plaintext)).toEqual(specFile);

    expect(infoEvent!.tags[0]![1]).toMatch(/^si-[0-9a-f]{8}$/);
    expect(result).toMatchObject({ reused: false, infoWritten: true });
  });

  it("takes relay hints from the publish result — accepted relays only, never assumed", async () => {
    const relay = new FakeRelay({
      publishResult: { ok: true, accepted: 1, total: 2, relayResults: [{ relay: RELAY_A, status: "accepted" }, { relay: "wss://down", status: "failed" }] },
    });
    const result = await createFileShare(fileEntry(), ctx(relay));
    const pointer = decodePointer(decodeShareLink(result.url)!.naddr)!;
    expect(pointer.relays).toEqual([RELAY_A]);
  });

  it("writes bookkeeping with the exact payload shape, encrypted to the Drive Key", async () => {
    const relay = new FakeRelay({ publishResult: okResult(RELAY_A) });
    const result = await createFileShare(fileEntry("f-42"), ctx(relay));
    const info = relay.publishedEvents[1]!;
    expect(info.tags[1]).toEqual(["t", "shared-container"]);
    expect(info.pubkey).toBe(keyring.active.publicKey);
    const payload = JSON.parse(nip44.v2.decrypt(info.content, keyring.active.conversationKey));
    expect(payload).toEqual({
      v: 1,
      kind: "file",
      name: "spec.txt",
      source: { type: "file", id: "f-42" },
      coordinate: result.coordinate,
      relays: [RELAY_A],
      members: [],
      encryptionKey: decodeShareLink(result.url)!.k,
    });
  });

  it("shares an app-shaped file in its own shape", async () => {
    const { parent: _p, servers: _s, ...rest } = specFile;
    const appRaw = { ...rest, server: "https://one.example", folder: "/docs", id: "abc" };
    const relay = new FakeRelay();
    const result = await createFileShare(fileEntry("abc", appRaw), ctx(relay));
    const secret = hexToBytes(decodeShareLink(result.url)!.k);
    const payload = JSON.parse(nip44.v2.decrypt(relay.publishedEvents[0]!.content, nip44.v2.utils.getConversationKey(secret, getPublicKey(secret))));
    expect(payload).toEqual(appRaw);
  });

  it("still returns the link when only the bookkeeping write fails, and says so", async () => {
    let calls = 0;
    const relay = new FakeRelay({ publishResult: () => (++calls === 1 ? okResult(RELAY_A) : { ok: false, accepted: 0, total: 1, relayResults: [] }) });
    const result = await createFileShare(fileEntry(), ctx(relay));
    expect(result.infoWritten).toBe(false);
    expect(String(result.infoError)).toContain("bookkeeping");
    expect(decodeShareLink(result.url)).not.toBeNull();
  });

  it("throws when no relay accepts the share event, and refuses deleted or legacy files", async () => {
    const failing = new FakeRelay({ publishResult: { ok: false, accepted: 0, total: 1, relayResults: [] } });
    await expect(createFileShare(fileEntry(), ctx(failing))).rejects.toThrow("No relay accepted");
    await expect(createFileShare(fileEntry("x", { ...specFile, deleted: true }), ctx(new FakeRelay()))).rejects.toThrow("deleted");
    const { blobHash: _b, chunkSize: _c, ...legacy } = specFile;
    await expect(createFileShare(fileEntry("x", { ...legacy, chunks: ["c".repeat(64)] }), ctx(new FakeRelay()))).rejects.toBeInstanceOf(LegacyChunkedFileError);
  });

  it("passes write hints through to the store", async () => {
    const relay = new FakeRelay();
    await createFileShare(fileEntry(), ctx(relay, { relays: [RELAY_B] }));
    expect(relay.published[0]!.relays).toEqual([RELAY_B]);
  });
});

async function share(relay: FakeRelay, file = fileEntry()) {
  const result = await createFileShare(file, ctx(relay, { relays: undefined }));
  return { result, link: result.url, event: relay.publishedEvents[0]! };
}

describe("resolveShare", () => {
  it("resolves a link to file metadata with no signer", async () => {
    const relay = new FakeRelay({ publishResult: okResult(RELAY_A) });
    const { link } = await share(relay);
    const resolved = await resolveShare(link, { store: relay, quietMs: 5, timeoutMs: 80 });
    expect(resolved.kind).toBe("file");
    if (resolved.kind !== "file") return;
    expect(resolved.file).toMatchObject({ name: "spec.txt", blobHash: "b".repeat(64), servers: ["https://one.example"] });
  });

  it("looks up by coordinate using the link's hints, per call — no global routing", async () => {
    const relay = new FakeRelay({ publishResult: okResult(RELAY_A) });
    const { link, event } = await share(relay);
    await resolveShare(link, { store: relay, relays: [RELAY_B], quietMs: 5, timeoutMs: 80 });
    const lookup = relay.observations.at(-1)!;
    expect(lookup.filters).toEqual([{ kinds: [METADATA_KIND], authors: [keyring.active.publicKey], "#d": [event.tags[0]![1]] }]);
    expect(lookup.options).toEqual({ relays: [RELAY_A, RELAY_B] });
  });

  it("accepts an already-decoded payload and an app-shaped file's own id", async () => {
    const relay = new FakeRelay();
    const { parent: _p, servers: _s, ...rest } = specFile;
    const { link } = await share(relay, fileEntry("abc", { ...rest, server: "https://one.example", folder: "/x", id: "abc" }));
    const resolved = await resolveShare(decodeShareLink(link)!, { store: relay, quietMs: 5, timeoutMs: 80 });
    expect(resolved.kind === "file" && resolved.file.id).toBe("abc");
    expect(resolved.kind === "file" && resolved.file.folderPath).toBe("/x");
  });

  it("newest event wins, even when it arrives after the first", async () => {
    const relay = new FakeRelay();
    const { link, event } = await share(relay);
    const secret = hexToBytes(decodeShareLink(link)!.k);
    const newer = buildEvent({
      subtype: "shared-file", d: event.tags[0]![1]!, payload: { ...specFile, name: "second.txt" },
      conversationKey: nip44.v2.utils.getConversationKey(secret, getPublicKey(secret)),
      signingKey: hexToBytes(KEY_NEW), createdAt: event.created_at + 10,
    });
    relay.arrivals = [newer];
    const resolved = await resolveShare(link, { store: relay, quietMs: 30, timeoutMs: 200 });
    expect(resolved.kind === "file" && resolved.file.name).toBe("second.txt");
  });

  it("throws a typed not-found when nothing answers within the timeout", async () => {
    const relay = new FakeRelay({ silent: true });
    const link = encodeShareLink({ pubkey: keyring.active.publicKey, d: "s-x", relays: [], secretKeyHex: "ab".repeat(32) });
    await expect(resolveShare(link, { store: relay, timeoutMs: 20 })).rejects.toBeInstanceOf(ShareNotFoundError);
  });

  it("rejects malformed links, bad keys, wrong keys and non-file subtypes", async () => {
    const relay = new FakeRelay();
    await expect(resolveShare("nonsense", { store: relay })).rejects.toBeInstanceOf(InvalidShareLinkError);
    const { link, event } = await share(relay);
    await expect(resolveShare({ naddr: "bad", k: "ab".repeat(32) }, { store: relay })).rejects.toBeInstanceOf(InvalidShareLinkError);
    await expect(resolveShare({ ...decodeShareLink(link)!, k: "0".repeat(64) }, { store: relay })).rejects.toBeInstanceOf(InvalidShareLinkError);
    const wrong = { ...decodeShareLink(link)!, k: "cd".repeat(32) };
    await expect(resolveShare(wrong, { store: relay, quietMs: 5, timeoutMs: 80 })).rejects.toThrow("Could not decrypt");

    const d = event.tags[0]![1]!;
    const folder = buildEvent({ subtype: "folder", d: "folderd", payload: {}, conversationKey: keyring.active.conversationKey, signingKey: hexToBytes(KEY_NEW), createdAt: 5 });
    relay.add(folder);
    const folderLink = encodeShareLink({ pubkey: keyring.active.publicKey, d: "folderd", relays: [], secretKeyHex: "ab".repeat(32) });
    await expect(resolveShare(folderLink, { store: relay, quietMs: 5, timeoutMs: 80 })).rejects.toThrow("not a shared file");
    expect(d).toMatch(/^s-/);
  });

  it("throws a typed 'folder shares not supported' error for t=container", async () => {
    const relay = new FakeRelay();
    const container = { ...buildEvent({ subtype: "files", d: "boxd", payload: {}, conversationKey: keyring.active.conversationKey, signingKey: hexToBytes(KEY_NEW), createdAt: 5 }) };
    const withT = { ...container, tags: [["d", "boxd"], ["t", "container"], ["client", "x"], ["encrypted", "nip44"]], id: "9".repeat(64) };
    relay.add(withT as Event);
    const link = encodeShareLink({ pubkey: keyring.active.publicKey, d: "boxd", relays: [], secretKeyHex: "ab".repeat(32) });
    const error = await resolveShare(link, { store: relay, quietMs: 5, timeoutMs: 80 }).catch((e) => e);
    expect(error).toBeInstanceOf(FolderShareUnsupportedError);
    expect(error.message).toContain("Folder shares are not supported");
  });
});

describe("revokeShare + revoked resolve", () => {
  async function shared() {
    const relay = new FakeRelay({ publishResult: okResult(RELAY_A) });
    const result = await createFileShare(fileEntry(), ctx(relay));
    const [entry] = await listShares(ctx(relay));
    return { relay, result, entry: entry! };
  }

  it("publishes a superseding event: same d and t, strictly newer, payload {v,revoked,at,kind}, revoked tag", async () => {
    const { relay, result, entry } = await shared();
    const original = relay.publishedEvents[0]!;
    const before = relay.published.length;
    const revoked = await revokeShare(entry, ctx(relay));
    const superseding = relay.publishedEvents[before]!;

    expect(superseding.tags.slice(0, 2)).toEqual(original.tags.slice(0, 2));
    expect(superseding.tags).toContainEqual(["revoked", "1"]);
    expect(superseding.created_at).toBeGreaterThan(original.created_at);
    expect(superseding.pubkey).toBe(original.pubkey);
    const secret = hexToBytes(decodeShareLink(result.url)!.k);
    const payload = JSON.parse(nip44.v2.decrypt(superseding.content, nip44.v2.utils.getConversationKey(secret, getPublicKey(secret))));
    expect(payload).toEqual({ v: 1, revoked: true, at: revoked.at, kind: "file" });
    expect(revoked.infoWritten).toBe(true);

    const resolved = await resolveShare(result.url, { store: relay, quietMs: 5, timeoutMs: 80 });
    expect(resolved).toMatchObject({ kind: "revoked", target: "file" });
  });

  it("beats an original that is dated in the future", async () => {
    const { relay, entry } = await shared();
    const original = relay.publishedEvents[0]!;
    const future = { ...original, created_at: original.created_at + 5000, id: "8".repeat(64) };
    relay.events.clear();
    relay.add(future);
    const before = relay.published.length;
    await revokeShare(entry, ctx(relay));
    expect(relay.publishedEvents[before]!.created_at).toBeGreaterThan(future.created_at);
  });

  it("uses the plaintext revoked tag even if the payload is unreadable", async () => {
    const { relay, result, entry } = await shared();
    await revokeShare(entry, ctx(relay));
    const superseding = relay.publishedEvents.find((e) => e.tags.some((t) => t[0] === "revoked"))!;
    relay.events.set(superseding.id, { ...superseding, content: "corrupted" });
    expect((await resolveShare(result.url, { store: relay, quietMs: 5, timeoutMs: 80 })).kind).toBe("revoked");
  });

  it("marks the bookkeeping entry revoked but keeps it listed", async () => {
    const { relay, entry } = await shared();
    const { at } = await revokeShare(entry, ctx(relay));
    const [after] = await listShares(ctx(relay));
    expect(after).toMatchObject({ infoD: entry.infoD, revokedAt: at });
  });

  it("requests NIP-09 deletion of the share coordinate only", async () => {
    const { relay, entry } = await shared();
    await revokeShare(entry, ctx(relay));
    await flush();
    const deletion = relay.publishedEvents.find((e) => e.kind === 5)!;
    expect(deletion.tags).toContainEqual(["a", entry.coordinate]);
    expect(deletion.tags.filter((t) => t[0] === "a")).toHaveLength(1);
    expect(deletion.tags).toContainEqual(["k", "34578"]);
  });

  it("revokes shares authored by a previous key using that key", async () => {
    const oldRing: DriveKeyring = { active: driveKeyEntry(KEY_OLD), previous: [] };
    const relay = new FakeRelay({ publishResult: okResult(RELAY_A) });
    await createFileShare(fileEntry(), { store: relay, keyring: oldRing, quietMs: 5, timeoutMs: 80 });
    const [entry] = await listShares(ctx(relay));
    const before = relay.published.length;
    await revokeShare(entry!, ctx(relay));
    expect(relay.publishedEvents[before]!.pubkey).toBe(driveKeyEntry(KEY_OLD).publicKey);
  });

  it("throws when the keyring no longer holds the authoring key, when it is a folder entry, or when nothing accepts", async () => {
    const { relay, entry } = await shared();
    await expect(revokeShare(entry, { ...ctx(relay), keyring: { active: driveKeyEntry("09".repeat(32)), previous: [] } })).rejects.toBeInstanceOf(ShareKeyMissingError);
    await expect(revokeShare({ ...entry, kind: "folder" }, ctx(relay))).rejects.toBeInstanceOf(FolderShareUnsupportedError);
    const dead = new FakeRelay({ publishResult: { ok: false, accepted: 0, total: 1, relayResults: [] } });
    dead.add(relay.publishedEvents[0]!);
    await expect(revokeShare(entry, ctx(dead))).rejects.toThrow("No relay accepted");
  });

  it("reports a failed bookkeeping update instead of hiding it", async () => {
    const { relay, entry } = await shared();
    let calls = 0;
    const flaky = new FakeRelay({ publishResult: () => (++calls === 1 ? okResult(RELAY_A) : { ok: false, accepted: 0, total: 1, relayResults: [] }) });
    flaky.add(...relay.events.values());
    const result = await revokeShare(entry, ctx(flaky));
    expect(result.infoWritten).toBe(false);
    expect(result.infoError).toBeDefined();
  });
});

describe("listShares", () => {
  it("lists newest first, one entry per bookkeeping d, across keys, skipping unreadable or malformed events", async () => {
    const relay = new FakeRelay({ publishResult: okResult(RELAY_A) });
    await createFileShare(fileEntry("f1"), ctx(relay));
    await createFileShare(fileEntry("f2", { ...specFile, name: "two.txt" }), ctx(relay));

    const infoFor = (secret: string, d: string, payload: unknown, createdAt: number) => buildEvent({
      subtype: "shared-container", d, payload, conversationKey: driveKeyEntry(secret).conversationKey, signingKey: hexToBytes(secret), createdAt,
    });
    relay.add(
      infoFor(KEY_NEW, "si-junk1", { v: 1 }, 1), // missing fields
      infoFor(KEY_NEW, "si-junk2", { v: 1, kind: "file", name: "x", coordinate: "bad", encryptionKey: "ab".repeat(32), source: { type: "file", id: "x" } }, 2),
      infoFor(KEY_NEW, "si-junk3", { v: 1, kind: "file", name: "x", coordinate: `34578:${"a".repeat(64)}:s-z`, encryptionKey: "nothex", source: { type: "file", id: "x" } }, 3),
      infoFor(KEY_NEW, "si-junk4", "just a string", 4),
      infoFor("09".repeat(32), "si-foreign", { v: 1 }, 5), // author not in the keyring: never delivered
      infoFor(KEY_OLD, "si-old", { v: 1, kind: "folder", name: "Docs", source: { type: "folder", path: "/docs" }, coordinate: `34578:${driveKeyEntry(KEY_OLD).publicKey}:c-1`, relays: [RELAY_B], members: [{ id: "a", coordinate: "34578:x:y" }], encryptionKey: "cd".repeat(32) }, 6),
    );
    const entries = await listShares(ctx(relay));
    expect(entries.map((e) => e.name).sort()).toEqual(["Docs", "spec.txt", "two.txt"]);
    expect(entries.map((e) => e.sharedAtSeconds)).toEqual([...entries.map((e) => e.sharedAtSeconds)].sort((a, b) => b - a));
    const docs = entries.find((e) => e.name === "Docs")!;
    expect(docs).toMatchObject({ kind: "folder", relays: [RELAY_B], members: [{ id: "a", coordinate: "34578:x:y" }] });
    expect(decodePointer(decodeShareLink(docs.url)!.naddr)!.relays).toEqual([RELAY_B]);
  });

  it("filters the relay query to the keyring's pubkeys and the bookkeeping subtype", async () => {
    const relay = new FakeRelay();
    await listShares(ctx(relay, { relays: [RELAY_B] }));
    expect(relay.observations[0]!.filters).toEqual([
      { kinds: [METADATA_KIND], authors: [driveKeyEntry(KEY_NEW).publicKey, driveKeyEntry(KEY_OLD).publicKey], "#t": ["shared-container"] },
    ]);
    expect(relay.observations[0]!.options).toEqual({ relays: [RELAY_B] });
  });
});

describe("ensureFileShare", () => {
  it("returns the existing live link instead of publishing a duplicate", async () => {
    const relay = new FakeRelay({ publishResult: okResult(RELAY_A) });
    const first = await ensureFileShare(fileEntry(), ctx(relay));
    const published = relay.published.length;
    const second = await ensureFileShare(fileEntry(), ctx(relay));
    expect(second).toMatchObject({ reused: true, url: first.url });
    expect(relay.published.length).toBe(published);
  });

  it("creates a new share for a different file and after the old one is revoked", async () => {
    const relay = new FakeRelay({ publishResult: okResult(RELAY_A) });
    const first = await ensureFileShare(fileEntry("f1"), ctx(relay));
    expect((await ensureFileShare(fileEntry("f2"), ctx(relay))).reused).toBe(false);
    const [entry] = (await listShares(ctx(relay))).filter((e) => e.source.id === "f1");
    await revokeShare(entry!, ctx(relay));
    const again = await ensureFileShare(fileEntry("f1"), ctx(relay));
    expect(again.reused).toBe(false);
    expect(again.url).not.toBe(first.url);
  });

  it("concurrent calls for one file share one in-flight request and one publish", async () => {
    const relay = new FakeRelay({ publishResult: okResult(RELAY_A) });
    const results = await Promise.all([1, 2, 3, 4].map(() => ensureFileShare(fileEntry(), ctx(relay))));
    expect(new Set(results.map((r) => r.url)).size).toBe(1);
    expect(relay.publishedEvents.filter((e) => e.tags[1]![1] === "shared-file")).toHaveLength(1);
  });

  it("uses knownEntries without touching the network, and a failure does not wedge later calls", async () => {
    const relay = new FakeRelay({ publishResult: okResult(RELAY_A) });
    await createFileShare(fileEntry(), ctx(relay));
    const known: SharedByMeEntry[] = await listShares(ctx(relay));
    const observed = relay.observations.length;
    expect((await ensureFileShare(fileEntry(), ctx(relay), { knownEntries: known })).reused).toBe(true);
    expect(relay.observations.length).toBe(observed);

    const failing = new FakeRelay({ publishResult: { ok: false, accepted: 0, total: 1, relayResults: [] } });
    await expect(ensureFileShare(fileEntry("f9"), ctx(failing))).rejects.toThrow();
    const healthy = new FakeRelay({ publishResult: okResult(RELAY_A) });
    expect((await ensureFileShare(fileEntry("f9"), ctx(healthy))).reused).toBe(false);
  });
});

describe("resolve is read-only on the store", () => {
  it("never publishes", async () => {
    const relay = new FakeRelay();
    const { link } = await share(relay);
    const published = relay.published.length;
    await resolveShare(link, { store: relay, quietMs: 5, timeoutMs: 80 });
    expect(relay.published.length).toBe(published);
    vi.restoreAllMocks();
  });
});
