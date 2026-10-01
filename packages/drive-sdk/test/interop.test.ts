import { getPublicKey, nip19, nip44, verifyEvent } from "nostr-tools";
import { hexToBytes } from "nostr-tools/utils";
import { describe, expect, it } from "vitest";
import {
  createFileShare,
  driveKeyEntry,
  listShares,
  mintDriveKey,
  readFileMetadata,
  revokeShare,
  rotateDriveKey,
  uploadFile,
  type BlossomTransport,
  type DriveKeyring,
} from "../src/index.js";
import { FakeRelay, makeIdentity, okResult } from "./helpers.js";

// What the SDK WRITES must decode with stock nostr-tools alone — nip19.decode and nip44.v2.decrypt, no
// SDK code in the decode path — so any other client can read it.

const stockKey = (secretHex: string) => {
  const secret = hexToBytes(secretHex);
  return nip44.v2.utils.getConversationKey(secret, getPublicKey(secret));
};

/** A file as the formstr-drive app writes it: folder path, id, server (see docs/adr/0002). */
const appShapedFile = {
  id: "abcd1234", name: "report.txt", size: 40, type: "text/plain", folder: "/docs/reports",
  uploadedAt: 1_700_000_000_000, server: "https://blossom.one", servers: ["https://blossom.one"],
  encryptionKey: "31".repeat(32), encryptionAlgorithm: "aes-gcm",
  blobHash: "b".repeat(64), chunkSize: 16, unencryptedFileHash: "a".repeat(64),
};

describe("what the SDK writes decodes with stock nostr-tools", () => {
  const identity = makeIdentity(12);

  it("share link, share event, revoke event and bookkeeping event", async () => {
    const relay = new FakeRelay({ publishResult: okResult("wss://relay.one") });
    const active = driveKeyEntry("06".repeat(32));
    const ring: DriveKeyring = { active, previous: [] };
    const file = readFileMetadata(appShapedFile, { id: "abcd1234", author: active.publicKey, createdAt: 1 });
    const created = await createFileShare(file, { store: relay, keyring: ring, quietMs: 5, timeoutMs: 80 });

    // Link → naddr → pointer → event → payload, using only nostr-tools.
    const [, naddr, k] = /^#shared=([^&]+)&k=([0-9a-f]{64})$/.exec(created.url)!;
    const pointer = nip19.decode(naddr!);
    if (pointer.type !== "naddr") throw new Error("not an naddr");
    const [shareEvent, infoEvent] = relay.publishedEvents;
    expect(pointer.data.identifier).toBe(shareEvent!.tags[0]![1]);
    expect(pointer.data.pubkey).toBe(active.publicKey);
    expect(verifyEvent(shareEvent!)).toBe(true);
    expect(JSON.parse(nip44.v2.decrypt(shareEvent!.content, stockKey(k!)))).toEqual(appShapedFile);
    expect(JSON.parse(nip44.v2.decrypt(infoEvent!.content, active.conversationKey))).toMatchObject({ v: 1, kind: "file", encryptionKey: k });

    const [entry] = await listShares({ store: relay, keyring: ring, quietMs: 5, timeoutMs: 80 });
    const before = relay.published.length;
    await revokeShare(entry!, { store: relay, keyring: ring, quietMs: 5, timeoutMs: 80 });
    const revoke = relay.publishedEvents[before]!;
    expect(revoke.tags).toContainEqual(["revoked", "1"]);
    expect(JSON.parse(nip44.v2.decrypt(revoke.content, stockKey(k!)))).toMatchObject({ v: 1, revoked: true, kind: "file" });
  });

  it("Drive Key events (mint, rotate) and uploaded metadata", async () => {
    const proof = new FakeRelay({ seenOn: () => ["wss://relay.one"] });
    proof.add({ id: "c".repeat(64), pubkey: "d".repeat(64), created_at: 1, kind: 1, tags: [], content: "x", sig: "0".repeat(128) });
    const ctx = { store: proof, signer: identity, configuredRelays: ["wss://relay.one"], settleMs: 5, timeoutMs: 60, proofTimeoutMs: 20 };
    const minted = await mintDriveKey(ctx);
    const conv = nip44.v2.utils.getConversationKey(hexToBytes(identity.secretHex), identity.pubkey);
    expect(JSON.parse(nip44.v2.decrypt(proof.publishedEvents[0]!.content, conv))).toEqual({ encryptionKey: minted.keyring.active.secretKeyHex });

    const rotated = await rotateDriveKey(ctx);
    expect(JSON.parse(nip44.v2.decrypt(proof.publishedEvents[1]!.content, conv))).toEqual({
      encryptionKey: rotated.keyring.active.secretKeyHex, previousKeys: [minted.keyring.active.secretKeyHex],
    });

    const transport: BlossomTransport = { async upload() {}, async download() { throw new Error("unused"); } };
    const uploaded = await uploadFile(new Uint8Array([1, 2, 3]), { name: "a.bin", type: "application/octet-stream", parent: "", servers: ["https://s.example"] }, {
      store: proof, keyring: rotated.keyring, signer: identity, transport,
    });
    expect(JSON.parse(nip44.v2.decrypt(uploaded.event.content, rotated.keyring.active.conversationKey)))
      .toMatchObject({ name: "a.bin", parent: "", servers: ["https://s.example"], size: 3 });
    expect(uploaded.event.tags.map((t) => t[0])).toEqual(["d", "t", "client", "encrypted"]);
  });
});
