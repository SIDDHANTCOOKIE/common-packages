import { getPublicKey, nip19, nip44, verifyEvent, type Event } from "nostr-tools";
import { hexToBytes } from "nostr-tools/utils";
import { describe, expect, it } from "vitest";
import vectors from "./vectors/app-0064bff.json";
import {
  createFileShare,
  decodeShareLink,
  decryptFileBytes,
  decryptFileEntry,
  decryptRange,
  deriveBlobKey,
  driveKeyEntry,
  downloadFile,
  encryptFile,
  encryptSegment,
  fetchFiles,
  LegacyChunkedFileError,
  listShares,
  mintDriveKey,
  resolveDriveKeyStatus,
  resolveShare,
  revokeShare,
  rotateDriveKey,
  segmentCount,
  streamDecrypt,
  uploadFile,
  type BlobFile,
  type BlossomTransport,
  type DriveKeyring,
  type FileEntry,
  type IdentitySigner,
} from "../src/index.js";
import { FakeRelay, flush, makeIdentity, okResult } from "./helpers.js";

// Every vector here was produced by formstr-drive's OWN code at 0064bff (scripts/generate-golden.mjs),
// not derived by hand. The SDK has to decode what the app actually writes.

const hexBytes = (hex: string) => hexToBytes(hex);
const identitySecret = hexBytes(vectors.identity.secretHex);

function appIdentity(): IdentitySigner {
  const pubkey = vectors.identity.pubkey;
  return {
    getPublicKey: async () => pubkey,
    signEvent: async () => { throw new Error("golden tests never sign with the identity"); },
    nip44Encrypt: async (peer, text) => nip44.v2.encrypt(text, nip44.v2.utils.getConversationKey(identitySecret, peer)),
    nip44Decrypt: async (peer, text) => nip44.v2.decrypt(text, nip44.v2.utils.getConversationKey(identitySecret, peer)),
  };
}

const ring: DriveKeyring = {
  active: driveKeyEntry(vectors.driveKeys.activeHex),
  previous: [driveKeyEntry(vectors.driveKeys.previousHex)],
};
const asEvent = (value: unknown) => value as Event;

function readerOf(hex: string, chunk: number) {
  const bytes = hexBytes(hex);
  let offset = 0;
  return {
    async read() {
      if (offset >= bytes.length) return { done: true as const };
      const value = bytes.subarray(offset, offset + chunk);
      offset += chunk;
      return { done: false as const, value };
    },
  };
}

describe("vectors are what they claim to be", () => {
  it("come from the pinned commit, and every event carries a valid signature", () => {
    expect(vectors.source.sha).toBe("0064bffcef4ecf73ae153894cce6a75b674f014d");
    for (const event of [
      vectors.driveKeyEvents.withPrevious.event, vectors.driveKeyEvents.objectOnly.event, vectors.driveKeyEvents.legacyArray.event,
      vectors.appFile.event, vectors.legacyChunkedFile.event, vectors.tombstone.event,
      vectors.share.event, vectors.share.info.event, vectors.revokedShare.event,
    ]) expect(verifyEvent(asEvent(event))).toBe(true);
  });
});

describe("NIP-FS blob written by the app", () => {
  const seg = vectors.segmentBlob;
  const file: BlobFile = {
    size: seg.plaintextHex.length / 2, chunkSize: seg.chunkSize, blobHash: seg.blobHash, encryptionKey: seg.fileKeyHex,
    unencryptedFileHash: seg.unencryptedFileHash, servers: ["https://blossom.one"], type: "text/plain",
  };
  const blob = hexBytes(seg.blobHex);
  const plaintext = hexBytes(seg.plaintextHex);

  it("the SDK's encryptSegment reproduces the app's frames byte for byte", async () => {
    const key = deriveBlobKey(seg.fileKeyHex);
    const total = segmentCount(plaintext.length, seg.chunkSize);
    for (let i = 0; i < total; i += 1) {
      const frame = await encryptSegment(plaintext.subarray(i * seg.chunkSize, Math.min(plaintext.length, (i + 1) * seg.chunkSize)), key, i, i === total - 1);
      expect(Buffer.from(frame).toString("hex")).toBe(seg.segmentFrames[i]);
    }
  });

  it("the buffered encryptFile produces the app's blob exactly (same key, same nonces)", async () => {
    const encrypted = await encryptFile(plaintext, { chunkSize: seg.chunkSize, encryptionKey: seg.fileKeyHex });
    expect(Buffer.from(encrypted.bytes).toString("hex")).toBe(seg.blobHex);
    expect(encrypted.blobHash).toBe(seg.blobHash);
    expect(encrypted.unencryptedFileHash).toBe(seg.unencryptedFileHash);
  });

  it("decrypts buffered, streamed (any chunking) and by range", async () => {
    expect(await decryptFileBytes(blob, file)).toEqual(plaintext);
    for (const chunk of [1, 7, 24, 1000]) {
      const parts: number[] = [];
      for await (const part of streamDecrypt(readerOf(seg.blobHex, chunk), file)) parts.push(...part);
      expect(new Uint8Array(parts)).toEqual(plaintext);
    }
    const range = await decryptRange(file, 10, 35, async ({ start, end }) => ({ bytes: blob.slice(start, end + 1), satisfied: true }));
    expect(range).toEqual(plaintext.subarray(10, 36));
  });
});

describe("Drive Key events written by the app, in each payload shape", () => {
  it.each([
    ["withPrevious", vectors.driveKeyEvents.withPrevious],
    ["objectOnly", vectors.driveKeyEvents.objectOnly],
    ["legacyArray", vectors.driveKeyEvents.legacyArray],
  ])("resolves %s to exactly the keyring the app's own reader reports", async (_name, vector) => {
    const relay = new FakeRelay().add(asEvent(vector.event));
    const status = await resolveDriveKeyStatus({ store: relay, signer: appIdentity(), settleMs: 5, timeoutMs: 60 });
    if (status.kind !== "ready") throw new Error(`expected ready, got ${JSON.stringify(status)}`);
    expect([status.keyring.active.secretKeyHex, ...status.keyring.previous.map((k) => k.secretKeyHex)]).toEqual(vector.appReads.all);
    expect(status.keyring.active.secretKeyHex).toBe(vector.appReads.active);
  });

  it("the shapes carry what we expect: previousKeys only where the app wrote them", () => {
    expect(vectors.driveKeyEvents.withPrevious.appReads.all).toEqual([vectors.driveKeys.activeHex, vectors.driveKeys.previousHex]);
    expect(vectors.driveKeyEvents.objectOnly.appReads.all).toEqual([vectors.driveKeys.activeHex]);
    expect(vectors.driveKeyEvents.legacyArray.appReads.all).toEqual([vectors.driveKeys.activeHex]);
  });

  it("the newest event of several wins, and the older key survives via previousKeys", async () => {
    const relay = new FakeRelay().add(asEvent(vectors.driveKeyEvents.legacyArray.event), asEvent(vectors.driveKeyEvents.withPrevious.event));
    const status = await resolveDriveKeyStatus({ store: relay, signer: appIdentity(), settleMs: 5, timeoutMs: 60 });
    expect(status.kind).toBe("ready");
  });
});

describe("file metadata written by the app", () => {
  const keys = [ring.active.conversationKey, ring.previous[0]!.conversationKey];

  it("decrypts an app-shaped event and maps it (server → servers, folder → folderPath, id from d)", () => {
    const entry = decryptFileEntry(asEvent(vectors.appFile.event), keys);
    expect(entry).toMatchObject({
      id: "abcd1234", name: "report.txt", folderPath: "/docs/reports", servers: ["https://blossom.one"], appShaped: true,
      blobHash: vectors.segmentBlob.blobHash, chunkSize: vectors.segmentBlob.chunkSize,
      author: vectors.driveKeys.activePubkey, deleted: false, legacyChunked: false,
    });
    expect(entry.parent).toBeUndefined(); // never fabricated from the path
  });

  it("lists the app's file, hides its tombstone, and keeps legacy chunked files typed", async () => {
    const relay = new FakeRelay().add(asEvent(vectors.appFile.event), asEvent(vectors.legacyChunkedFile.event));
    let files: FileEntry[] = [];
    const handle = fetchFiles({ store: relay, keyring: ring, onFiles: (f) => { files = f; } });
    await flush();
    expect(files.map((f) => f.id).sort()).toEqual(["abcd1234", "legacy01"]);
    expect(files.find((f) => f.id === "legacy01")).toMatchObject({ legacyChunked: true, appShaped: true });
    handle.stop();

    // The tombstone is a newer event for the SAME d: it removes the file from listings.
    const withTombstone = new FakeRelay().add(asEvent(vectors.appFile.event), asEvent(vectors.tombstone.event));
    let listed: FileEntry[] = [{} as FileEntry];
    fetchFiles({ store: withTombstone, keyring: ring, onFiles: (f) => { listed = f; } });
    await flush();
    expect(listed).toEqual([]);
  });

  it("tombstone parses as deleted; a legacy chunked file is not downloadable", async () => {
    expect(decryptFileEntry(asEvent(vectors.tombstone.event), keys).deleted).toBe(true);
    const legacy = decryptFileEntry(asEvent(vectors.legacyChunkedFile.event), keys);
    expect(legacy.legacyChunkHashes).toEqual(["c".repeat(64), "d".repeat(64)]);
    const transport: BlossomTransport = { async upload() {}, async download() { throw new Error("must not be reached"); } };
    await expect(downloadFile(legacy, { transport })).rejects.toBeInstanceOf(LegacyChunkedFileError);
  });

  it("downloads the app's file end to end from the app's own blob", async () => {
    const entry = decryptFileEntry(asEvent(vectors.appFile.event), keys);
    const blob = hexBytes(vectors.segmentBlob.blobHex);
    const transport: BlossomTransport = { async upload() {}, async download() { return blob; } };
    const downloaded = await downloadFile(entry, { transport });
    expect(new Uint8Array(await downloaded.arrayBuffer())).toEqual(hexBytes(vectors.segmentBlob.plaintextHex));
  });
});

describe("shares written by the app", () => {
  const { share, revokedShare } = vectors;

  it("decodes the app's link: #shared=<naddr>&k=<64-hex>", () => {
    const decoded = decodeShareLink(share.link)!;
    expect(decoded.k).toBe(share.k);
    const pointer = nip19.decode(decoded.naddr);
    expect(pointer.type === "naddr" && pointer.data).toEqual({
      kind: 34578, pubkey: vectors.driveKeys.activePubkey, identifier: share.d, relays: share.relays,
    });
  });

  it("resolves the app's share to its file metadata", async () => {
    const relay = new FakeRelay().add(asEvent(share.event));
    const resolved = await resolveShare(share.link, { store: relay, quietMs: 5, timeoutMs: 80 });
    if (resolved.kind !== "file") throw new Error("expected a file");
    expect(resolved.file).toMatchObject({ id: "abcd1234", name: "report.txt", folderPath: "/docs/reports", servers: ["https://blossom.one"] });
    expect(relay.observations.at(-1)!.options).toEqual({ relays: share.relays });
  });

  it("the app's revoke supersedes the share: newest wins and reads as revoked", async () => {
    expect(revokedShare.event.created_at).toBeGreaterThan(share.event.created_at);
    expect(revokedShare.event.tags).toContainEqual(["revoked", "1"]);
    const relay = new FakeRelay().add(asEvent(share.event), asEvent(revokedShare.event));
    const resolved = await resolveShare(share.link, { store: relay, quietMs: 5, timeoutMs: 80 });
    expect(resolved).toEqual({ kind: "revoked", target: "file", at: revokedShare.event.created_at });

    // Same answer even when the payload is unreadable: the plaintext tag short-circuits.
    const corrupted = new FakeRelay().add(asEvent({ ...revokedShare.event, content: "corrupt" }));
    expect((await resolveShare(share.link, { store: corrupted, quietMs: 5, timeoutMs: 80 })).kind).toBe("revoked");

    // And the authenticated payload decrypts to the app's documented shape.
    const secret = hexBytes(share.k);
    const payload = JSON.parse(nip44.v2.decrypt(revokedShare.event.content, nip44.v2.utils.getConversationKey(secret, getPublicKey(secret))));
    expect(payload).toEqual(revokedShare.payload);
  });

  it("reads the app's bookkeeping event into 'Shared by me'", async () => {
    const relay = new FakeRelay().add(asEvent(share.info.event));
    const [entry] = await listShares({ store: relay, keyring: ring, quietMs: 5, timeoutMs: 80 });
    expect(entry).toMatchObject({
      kind: "file", name: "report.txt", source: { type: "file", id: "abcd1234" }, coordinate: share.coordinate,
      relays: share.relays, encryptionKey: share.k, infoD: share.info.d, members: [],
    });
    expect(entry!.revokedAt).toBeUndefined();
    expect(decodeShareLink(entry!.url)?.k).toBe(share.k);
  });

  it("revoking an app-made share with the SDK produces the same event shape the app's revoke does", async () => {
    const relay = new FakeRelay({ publishResult: okResult("wss://relay.one") }).add(asEvent(share.event), asEvent(share.info.event));
    const [entry] = await listShares({ store: relay, keyring: ring, quietMs: 5, timeoutMs: 80 });
    const before = relay.published.length;
    await revokeShare(entry!, { store: relay, keyring: ring, quietMs: 5, timeoutMs: 80 });
    const sdkRevoke = relay.publishedEvents[before]!;
    expect(sdkRevoke.tags.map((t) => t[0])).toEqual(revokedShare.event.tags.map((t) => t[0]));
    expect(sdkRevoke.tags.slice(0, 2)).toEqual(revokedShare.event.tags.slice(0, 2));
    expect(sdkRevoke.created_at).toBeGreaterThan(share.event.created_at);
    expect((await resolveShare(share.link, { store: relay, quietMs: 5, timeoutMs: 80 })).kind).toBe("revoked");
  });
});

describe("what the SDK writes decodes with stock nostr-tools (no SDK code in the decode path)", () => {
  const stockKey = (secretHex: string) => {
    const secret = hexToBytes(secretHex);
    return nip44.v2.utils.getConversationKey(secret, getPublicKey(secret));
  };
  const identity = makeIdentity(12);

  it("share link, share event, revoke event and bookkeeping event", async () => {
    const relay = new FakeRelay({ publishResult: okResult("wss://relay.one") });
    const active = driveKeyEntry("06".repeat(32));
    const sdkRing: DriveKeyring = { active, previous: [] };
    const raw = { ...vectors.appFile.metadata };
    const file = decryptFileEntry(asEvent(vectors.appFile.event), [ring.active.conversationKey]);
    expect(file.raw).toEqual(raw);
    const created = await createFileShare(file, { store: relay, keyring: sdkRing, quietMs: 5, timeoutMs: 80 });

    // Link → naddr → pointer → event → payload, using only nostr-tools.
    const [, naddr, k] = /^#shared=([^&]+)&k=([0-9a-f]{64})$/.exec(created.url)!;
    const pointer = nip19.decode(naddr!);
    if (pointer.type !== "naddr") throw new Error("not an naddr");
    const [shareEvent, infoEvent] = relay.publishedEvents;
    expect(pointer.data.identifier).toBe(shareEvent!.tags[0]![1]);
    expect(pointer.data.pubkey).toBe(active.publicKey);
    expect(verifyEvent(shareEvent!)).toBe(true);
    expect(JSON.parse(nip44.v2.decrypt(shareEvent!.content, stockKey(k!)))).toEqual(raw);
    expect(JSON.parse(nip44.v2.decrypt(infoEvent!.content, active.conversationKey))).toMatchObject({ v: 1, kind: "file", encryptionKey: k });

    const [entry] = await listShares({ store: relay, keyring: sdkRing, quietMs: 5, timeoutMs: 80 });
    const before = relay.published.length;
    await revokeShare(entry!, { store: relay, keyring: sdkRing, quietMs: 5, timeoutMs: 80 });
    const revoke = relay.publishedEvents[before]!;
    expect(revoke.tags).toContainEqual(["revoked", "1"]);
    expect(JSON.parse(nip44.v2.decrypt(revoke.content, stockKey(k!)))).toMatchObject({ v: 1, revoked: true, kind: "file" });
  });

  it("Drive Key events (mint, rotate) and uploaded metadata", async () => {
    const proof = new FakeRelay({ seenOn: () => ["wss://relay.one"] });
    proof.add({ id: "c".repeat(64), pubkey: "d".repeat(64), created_at: 1, kind: 1, tags: [], content: "x", sig: "0".repeat(128) });
    const ctx = { store: proof, signer: identity, configuredRelays: ["wss://relay.one"], settleMs: 5, timeoutMs: 60, proofTimeoutMs: 20 };
    const minted = await mintDriveKey(ctx);
    const identitySecretKey = hexToBytes(identity.secretHex);
    const conv = nip44.v2.utils.getConversationKey(identitySecretKey, identity.pubkey);
    const mintEvent = proof.publishedEvents[0]!;
    expect(JSON.parse(nip44.v2.decrypt(mintEvent.content, conv))).toEqual({ encryptionKey: minted.keyring.active.secretKeyHex });

    const rotated = await rotateDriveKey(ctx);
    const rotateEvent = proof.publishedEvents[1]!;
    expect(JSON.parse(nip44.v2.decrypt(rotateEvent.content, conv))).toEqual({
      encryptionKey: rotated.keyring.active.secretKeyHex, previousKeys: [minted.keyring.active.secretKeyHex],
    });

    const transport: BlossomTransport = { async upload() {}, async download() { throw new Error("unused"); } };
    const uploaded = await uploadFile(new Uint8Array([1, 2, 3]), { name: "a.bin", type: "application/octet-stream", parent: "", servers: ["https://s.example"] }, {
      store: proof, keyring: rotated.keyring, signer: identity, transport,
    });
    const payload = JSON.parse(nip44.v2.decrypt(uploaded.event.content, rotated.keyring.active.conversationKey));
    expect(payload).toMatchObject({ name: "a.bin", parent: "", servers: ["https://s.example"], size: 3 });
    expect(uploaded.event.tags.map((t) => t[0])).toEqual(["d", "t", "client", "encrypted"]);
  });
});
