import { generateSecretKey, getPublicKey, nip44, verifyEvent, type Event } from "nostr-tools";
import { bytesToHex, hexToBytes } from "nostr-tools/utils";
import { describe, expect, it, vi } from "vitest";
import {
  AppShapedFileError,
  buildEvent,
  createFileMetadata,
  createFolderMetadata,
  decryptFileEntry,
  decryptWithKeys,
  downloadFile,
  driveKeyEntry,
  encryptFile,
  fetchFiles,
  fetchFolders,
  FolderShareUnsupportedError,
  LegacyChunkedFileError,
  METADATA_KIND,
  readFileMetadata,
  toBlobFile,
  uploadFile,
  type BlossomTransport,
  type DriveKeyring,
  type FileEntry,
  InvalidFileMetadataError,
} from "../src/index.js";
import { FakeRelay, makeIdentity } from "./helpers.js";

const KEY_OLD = "05".repeat(32);
const KEY_NEW = "06".repeat(32);
const FILE_KEY = "07".repeat(32);

function ring(active = KEY_NEW, previous: string[] = [KEY_OLD]): DriveKeyring {
  return { active: driveKeyEntry(active), previous: previous.map(driveKeyEntry) };
}

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

/** The shape formstr-drive writes today. */
const appFile = {
  name: "app.txt",
  id: "abcd1234",
  size: 10,
  type: "text/plain",
  folder: "/docs/reports",
  uploadedAt: 1_700_000_000_000,
  server: "https://one.example",
  encryptionKey: FILE_KEY,
  encryptionAlgorithm: "aes-gcm",
  servers: undefined,
  blobHash: "b".repeat(64),
  chunkSize: 65536,
};

const meta = { id: "file1", author: "f".repeat(64), createdAt: 5 };

describe("buildEvent", () => {
  const secret = generateSecretKey();
  const conversationKey = nip44.v2.utils.getConversationKey(secret, getPublicKey(secret));

  it("writes tags in the app's order: d, t, client, encrypted, then extras", () => {
    const event = buildEvent({
      subtype: "shared-file",
      d: "s-1234",
      payload: { hello: "world" },
      conversationKey,
      signingKey: secret,
      createdAt: 42,
      client: "someone",
      extraTags: [["revoked", "1"]],
    });
    expect(event.kind).toBe(METADATA_KIND);
    expect(event.created_at).toBe(42);
    expect(event.tags).toEqual([["d", "s-1234"], ["t", "shared-file"], ["client", "someone"], ["encrypted", "nip44"], ["revoked", "1"]]);
    expect(event.pubkey).toBe(getPublicKey(secret));
    expect(verifyEvent(event)).toBe(true);
  });

  it("encrypts with nip44.v2 only — stock nostr-tools decrypts it", () => {
    const event = buildEvent({ subtype: "files", d: "x", payload: { a: 1 }, conversationKey, signingKey: secret });
    expect(JSON.parse(nip44.v2.decrypt(event.content, conversationKey))).toEqual({ a: 1 });
    expect(event.tags[2]).toEqual(["client", "formstr-drive-sdk"]);
  });

  it("stamps created_at from the shared clock by default", () => {
    const a = buildEvent({ subtype: "files", d: "x", payload: {}, conversationKey, signingKey: secret });
    const b = buildEvent({ subtype: "files", d: "x", payload: {}, conversationKey, signingKey: secret });
    expect(b.created_at).toBeGreaterThan(a.created_at);
  });

  it("refuses to author a container: folder sharing is read-only here", () => {
    expect(() => buildEvent({ subtype: "container", d: "x", payload: {}, conversationKey, signingKey: secret }))
      .toThrow(FolderShareUnsupportedError);
  });
});

describe("decryptWithKeys", () => {
  it("tries every key in the keyring until the MAC validates", () => {
    const old = driveKeyEntry(KEY_OLD);
    const current = driveKeyEntry(KEY_NEW);
    const content = nip44.v2.encrypt(JSON.stringify({ ok: true }), old.conversationKey);
    expect(decryptWithKeys(content, [current.conversationKey, old.conversationKey])).toEqual({ ok: true });
    expect(decryptWithKeys(content, old.conversationKey)).toEqual({ ok: true });
  });

  it("throws when no key matches, and when there are no keys", () => {
    const content = nip44.v2.encrypt("{}", driveKeyEntry(KEY_OLD).conversationKey);
    expect(() => decryptWithKeys(content, [driveKeyEntry(KEY_NEW).conversationKey])).toThrow();
    expect(() => decryptWithKeys(content, [])).toThrow("No Drive Key available");
  });
});

describe("readFileMetadata", () => {
  it("reads the spec shape", () => {
    const entry = readFileMetadata(specFile, meta);
    expect(entry).toMatchObject({
      id: "file1", parent: "folder1", servers: ["https://one.example"], blobHash: "b".repeat(64), chunkSize: 4,
      legacyChunked: false, deleted: false, appShaped: false, unencryptedFileHash: "a".repeat(64),
    });
    expect(entry.folderPath).toBeUndefined();
  });

  it("reads the app's shape: server → servers, folder → folderPath (never a parent id), id from the d tag", () => {
    const entry = readFileMetadata(appFile, meta);
    expect(entry.id).toBe("file1"); // the payload's own `id` is ignored
    expect(entry.servers).toEqual(["https://one.example"]);
    expect(entry.folderPath).toBe("/docs/reports");
    expect(entry.parent).toBeUndefined();
    expect(entry.appShaped).toBe(true);
    expect(entry.unencryptedFileHash).toBeUndefined(); // optional in the app's shape
  });

  it("keeps `servers` when both `servers` and `server` are present", () => {
    const entry = readFileMetadata({ ...appFile, servers: ["https://a.example", "https://b.example"] }, meta);
    expect(entry.servers).toEqual(["https://a.example", "https://b.example"]);
  });

  it("maps deleted: true to a tombstone", () => {
    expect(readFileMetadata({ ...appFile, deleted: true }, meta).deleted).toBe(true);
    expect(readFileMetadata({ ...specFile, deleted: true }, meta).deleted).toBe(true);
    expect(readFileMetadata({ ...appFile, deleted: false }, meta).deleted).toBe(false);
  });

  it("parses legacy per-chunk files (string and object chunks) and flags them", () => {
    const { blobHash: _b, chunkSize: _c, ...legacy } = appFile;
    const withStrings = readFileMetadata({ ...legacy, chunks: ["c".repeat(64), "d".repeat(64)] }, meta);
    expect(withStrings).toMatchObject({ legacyChunked: true, legacyChunkHashes: ["c".repeat(64), "d".repeat(64)] });
    expect(withStrings.blobHash).toBeUndefined();
    const withObjects = readFileMetadata({ ...legacy, chunks: [{ hash: "c".repeat(64), server: "https://x.example" }] }, meta);
    expect(withObjects.legacyChunkHashes).toEqual(["c".repeat(64)]);
  });

  it("preserves the exact decrypted JSON for lossless republish", () => {
    const withExtra = { ...appFile, somethingNew: { nested: true } };
    expect(readFileMetadata(withExtra, meta).raw).toBe(withExtra);
  });

  it.each([
    ["not an object", null],
    ["an array", []],
    ["empty name", { ...specFile, name: "" }],
    ["negative size", { ...specFile, size: -1 }],
    ["fractional size", { ...specFile, size: 1.5 }],
    ["non-string type", { ...specFile, type: 3 }],
    ["bad uploadedAt", { ...specFile, uploadedAt: -5 }],
    ["short key", { ...specFile, encryptionKey: "abc" }],
    ["zero key", { ...specFile, encryptionKey: "0".repeat(64) }],
    ["other algorithm", { ...specFile, encryptionAlgorithm: "cbc" }],
    ["empty servers", { ...specFile, servers: [] }],
    ["non-http server", { ...specFile, servers: ["ftp://x"] }],
    ["no servers at all", { ...specFile, servers: undefined }],
    ["non-http single server", { ...appFile, servers: undefined, server: "ftp://x" }],
    ["blobHash without chunkSize", { ...specFile, chunkSize: undefined }],
    ["bad blobHash", { ...specFile, blobHash: "zz" }],
    ["zero chunkSize", { ...specFile, chunkSize: 0 }],
    ["neither blob nor chunks", { ...specFile, blobHash: undefined, chunkSize: undefined }],
    ["empty chunks", { ...specFile, blobHash: undefined, chunkSize: undefined, chunks: [] }],
    ["bad chunk hash", { ...specFile, blobHash: undefined, chunkSize: undefined, chunks: ["nope"] }],
    ["null chunk", { ...specFile, blobHash: undefined, chunkSize: undefined, chunks: [null] }],
    ["bad unencryptedFileHash", { ...specFile, unencryptedFileHash: "x" }],
    ["bad previewHash", { ...specFile, previewHash: "x" }],
    ["non-string parent", { ...specFile, parent: 1 }],
    ["non-string folder", { ...appFile, folder: 1 }],
  ])("rejects %s", (_name, value) => {
    expect(() => readFileMetadata(value, meta)).toThrow(InvalidFileMetadataError);
  });
});

describe("toBlobFile", () => {
  it("passes a spec File and a single-blob entry, dropping everything else", () => {
    expect(toBlobFile(specFile as never)).toEqual({
      size: 10, chunkSize: 4, blobHash: "b".repeat(64), encryptionKey: FILE_KEY, unencryptedFileHash: "a".repeat(64),
      servers: ["https://one.example"], type: "text/plain",
    });
    const entry = readFileMetadata(appFile, meta);
    expect(toBlobFile(entry)).toMatchObject({ blobHash: "b".repeat(64), chunkSize: 65536 });
    expect(toBlobFile(entry)).not.toHaveProperty("unencryptedFileHash");
  });

  it("throws the typed error for legacy chunked files — never a silent partial read", () => {
    const { blobHash: _b, chunkSize: _c, ...legacy } = appFile;
    const entry = readFileMetadata({ ...legacy, chunks: ["c".repeat(64)] }, meta);
    expect(() => toBlobFile(entry)).toThrow(LegacyChunkedFileError);
    expect(() => toBlobFile({ ...specFile, blobHash: undefined } as never)).toThrow(LegacyChunkedFileError);
  });

  it.each([
    ["blobHash", { blobHash: "zz" }],
    ["chunkSize", { chunkSize: 0 }],
    ["size", { size: -1 }],
    ["encryptionKey", { encryptionKey: "0".repeat(64) }],
    ["encryptionKey", { encryptionKey: 5 }],
    ["unencryptedFileHash", { unencryptedFileHash: "z" }],
    ["servers", { servers: [] }],
  ])("rejects a malformed %s", (_field, patch) => {
    expect(() => toBlobFile({ ...specFile, ...patch } as never)).toThrow(InvalidFileMetadataError);
  });

  it("defaults a missing type to empty", () => {
    expect(toBlobFile({ ...specFile, type: undefined } as never).type).toBe("");
  });
});

describe("fetchFiles / fetchFolders across a keyring", () => {
  const author = (secretHex: string) => hexToBytes(secretHex);

  function fileEvent(secretHex: string, d: string, createdAt: number, payload: unknown, tags?: string[][]): Event {
    const entry = driveKeyEntry(secretHex);
    const event = buildEvent({ subtype: "files", d, payload, conversationKey: entry.conversationKey, signingKey: author(secretHex), createdAt });
    // A rewritten event keeps a distinct id so the fake relay stores it alongside the original.
    return tags ? { ...event, tags, id: bytesToHex(generateSecretKey()) } : event;
  }

  function collect(relay: FakeRelay, keyring = ring()) {
    const lists: FileEntry[][] = [];
    const errors: unknown[] = [];
    const handle = fetchFiles({ store: relay, keyring, onFiles: (f) => lists.push(f), onError: (e) => errors.push(e) });
    return { lists, errors, handle, latest: () => lists.at(-1) };
  }

  it("subscribes to every Drive Key pubkey by default", async () => {
    const relay = new FakeRelay();
    collect(relay);
    expect(relay.observations[0]!.filters[0]!.authors).toEqual([driveKeyEntry(KEY_NEW).publicKey, driveKeyEntry(KEY_OLD).publicKey]);
  });

  it("decrypts files written under a previous key", async () => {
    const relay = new FakeRelay().add(fileEvent(KEY_OLD, "f1", 10, specFile));
    const { latest, handle } = collect(relay);
    await vi.waitFor(() => expect(latest()).toHaveLength(1));
    expect(latest()![0]).toMatchObject({ id: "f1", author: driveKeyEntry(KEY_OLD).publicKey, name: "spec.txt" });
    handle.stop();
  });

  it("a republish under the new key replaces the old-key event for the same file id", async () => {
    const relay = new FakeRelay().add(
      fileEvent(KEY_OLD, "f1", 10, specFile),
      fileEvent(KEY_NEW, "f1", 20, { ...specFile, name: "renamed.txt" }),
    );
    const { latest } = collect(relay);
    await vi.waitFor(() => expect(latest()).toHaveLength(1));
    expect(latest()![0]).toMatchObject({ name: "renamed.txt", author: driveKeyEntry(KEY_NEW).publicKey });
  });

  it("excludes tombstones but they still block older versions from resurrecting the file", async () => {
    const relay = new FakeRelay().add(
      fileEvent(KEY_NEW, "f1", 10, specFile),
      fileEvent(KEY_NEW, "f1", 20, { ...specFile, deleted: true }),
      fileEvent(KEY_NEW, "f2", 15, appFile),
    );
    const { latest } = collect(relay);
    await vi.waitFor(() => expect(latest()).toBeDefined());
    expect(latest()!.map((f) => f.id)).toEqual(["f2"]);
  });

  it("lists app-shaped and legacy chunked files rather than dropping them", async () => {
    const { blobHash: _b, chunkSize: _c, ...legacy } = appFile;
    const relay = new FakeRelay().add(
      fileEvent(KEY_NEW, "app", 10, appFile),
      fileEvent(KEY_NEW, "old", 11, { ...legacy, chunks: ["c".repeat(64)] }),
    );
    const { latest } = collect(relay);
    await vi.waitFor(() => expect(latest()).toHaveLength(2));
    expect(latest()!.find((f) => f.id === "old")!.legacyChunked).toBe(true);
    expect(latest()!.find((f) => f.id === "app")!.folderPath).toBe("/docs/reports");
  });

  it("ignores other subtypes on the same kind, accepts a missing t tag, and reports undecryptable or invalid events", async () => {
    const good = fileEvent(KEY_NEW, "f1", 10, specFile);
    const noT = fileEvent(KEY_NEW, "f2", 11, specFile, [["d", "f2"]]);
    const share = fileEvent(KEY_NEW, "s-1", 14, specFile, [["d", "s-1"], ["t", "shared-file"]]);
    // Authored by a keyring key but encrypted to a key we do not hold.
    const stranger = buildEvent({ subtype: "files", d: "f3", payload: specFile, conversationKey: driveKeyEntry("08".repeat(32)).conversationKey, signingKey: author(KEY_NEW), createdAt: 12 });
    const invalid = fileEvent(KEY_NEW, "f4", 13, { nope: true });
    const noD = fileEvent(KEY_NEW, "zz", 15, specFile, [["t", "files"]]);
    const relay = new FakeRelay().add(good, noT, share, stranger, invalid, noD);
    const { latest, errors } = collect(relay);
    await vi.waitFor(() => expect(errors).toHaveLength(2));
    expect(latest()!.map((f) => f.id).sort()).toEqual(["f1", "f2"]);
  });

  it("forwards relay hints, EOSE, extra filters, and stops observing", async () => {
    const relay = new FakeRelay();
    const onEose = vi.fn();
    const handle = fetchFiles({
      store: relay, keyring: ring(), onFiles: () => {}, onEose, relayHints: ["wss://hint"], filter: { authors: ["9".repeat(64)], since: 5 },
    });
    await vi.waitFor(() => expect(onEose).toHaveBeenCalled());
    expect(relay.observations[0]).toMatchObject({ filters: [{ authors: ["9".repeat(64)], since: 5, kinds: [METADATA_KIND] }], options: { relays: ["wss://hint"] } });
    handle.stop();
    expect(relay.observations[0]!.unobserved).toBe(true);
    // Events after stop are ignored.
    relay.publishEvent(fileEvent(KEY_NEW, "late", 30, specFile));
  });

  it("decryptFileEntry needs a d tag", () => {
    const event = fileEvent(KEY_NEW, "f1", 10, specFile);
    expect(() => decryptFileEntry({ ...event, tags: [] }, driveKeyEntry(KEY_NEW).conversationKey)).toThrow("no d tag");
  });

  it("fetches folders keyed by d across keys, and reports errors", async () => {
    const relay = new FakeRelay();
    const folderEvent = (secret: string, d: string, createdAt: number, name: string) => createFolderMetadata({ name, parent: "", keyring: ring(secret, []), d, createdAt }).event;
    relay.add(folderEvent(KEY_OLD, "d1", 10, "Old"), folderEvent(KEY_NEW, "d1", 20, "New"));
    const seen: string[][] = [];
    const errors: unknown[] = [];
    fetchFolders({ store: relay, keyring: ring(), onFolders: (f) => seen.push(f.map((x) => x.name)), onError: (e) => errors.push(e) });
    await vi.waitFor(() => expect(seen.at(-1)).toEqual(["New"]));
    expect(relay.observations[0]!.filters[0]!["#t"]).toEqual(["folder"]);
    relay.add({ ...folderEvent(KEY_NEW, "d2", 30, "x"), content: "garbage" });
    fetchFolders({ store: relay, keyring: ring(), onFolders: () => {}, onError: (e) => errors.push(e) });
    await vi.waitFor(() => expect(errors).toHaveLength(1));
  });
});

describe("signing and authorship", () => {
  it("metadata is signed by the Drive Key and encrypted to it; the identity signs only Blossom auth", async () => {
    const identity = makeIdentity(4);
    const identitySign = vi.fn(identity.signEvent);
    const relay = new FakeRelay();
    const keyring = ring();
    const uploaded: Array<{ authorization?: string }> = [];
    const transport: BlossomTransport = {
      async upload({ authorization }) { uploaded.push({ authorization }); },
      async download() { throw new Error("unused"); },
    };

    const result = await uploadFile(new Uint8Array([1, 2, 3]), {
      name: "a.bin", type: "application/octet-stream", parent: "", servers: ["https://one.example"],
    }, { store: relay, keyring, signer: { getPublicKey: identity.getPublicKey, signEvent: identitySign }, transport });

    expect(result.event.pubkey).toBe(keyring.active.publicKey);
    expect(result.event.pubkey).not.toBe(identity.pubkey);
    expect(verifyEvent(result.event)).toBe(true);
    expect(relay.publishedEvents).toEqual([result.event]); // published as a signed event, not a template
    expect(nip44.v2.decrypt(result.event.content, keyring.active.conversationKey)).toContain("a.bin");

    // The identity signer was asked for exactly one thing: the BUD-02 authorization (kind 24242).
    expect(identitySign).toHaveBeenCalledTimes(1);
    expect(identitySign.mock.calls[0]![0].kind).toBe(24242);
    expect(uploaded[0]!.authorization).toMatch(/^Nostr /);
  });

  it("createFileMetadata authors with the ACTIVE key even when previous keys exist", () => {
    const keyring = ring();
    const { event } = createFileMetadata({ ...specFile, keyring, d: "x", createdAt: 5 });
    expect(event.pubkey).toBe(keyring.active.publicKey);
    expect(() => nip44.v2.decrypt(event.content, keyring.previous[0]!.conversationKey)).toThrow();
  });
});

describe("downloading entries", () => {
  it("downloads an app-shaped entry that has no unencryptedFileHash, and refuses legacy ones", async () => {
    const bytes = new TextEncoder().encode("hello drive");
    const encrypted = await encryptFile(bytes, { chunkSize: 4, encryptionKey: FILE_KEY });
    const entry = readFileMetadata({
      ...appFile, size: encrypted.size, blobHash: encrypted.blobHash, chunkSize: 4, type: "text/plain",
    }, meta);
    const transport: BlossomTransport = {
      async upload() {},
      async download({ hash }) {
        if (hash !== encrypted.blobHash) throw new Error("missing");
        return encrypted.bytes;
      },
    };
    const blob = await downloadFile(entry, { transport });
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(bytes);

    const { blobHash: _b, chunkSize: _c, ...legacy } = appFile;
    const legacyEntry = readFileMetadata({ ...legacy, chunks: ["c".repeat(64)] }, meta);
    await expect(downloadFile(legacyEntry, { transport })).rejects.toBeInstanceOf(LegacyChunkedFileError);
  });

  it("AppShapedFileError describes the operation", () => {
    expect(new AppShapedFileError("move").message).toContain("move");
  });
});

describe("hex helpers used by fixtures", () => {
  it("bytesToHex round-trips", () => {
    expect(bytesToHex(hexToBytes(KEY_OLD))).toBe(KEY_OLD);
  });
});

describe("listing tie-break matches relays", () => {
  it("on equal created_at the LOWEST event id wins (NIP-01), whatever the arrival order", async () => {
    const entry = driveKeyEntry(KEY_NEW);
    const at = (name: string, id: string): Event => ({
      ...buildEvent({ subtype: "files", d: "same", payload: { ...specFile, name }, conversationKey: entry.conversationKey, signingKey: hexToBytes(KEY_NEW), createdAt: 10 }),
      id,
    });
    for (const order of [["1", "2"], ["2", "1"]]) {
      const relay = new FakeRelay();
      const lists: FileEntry[][] = [];
      for (const n of order) relay.add(at(`name-${n}`, n.repeat(64)));
      fetchFiles({ store: relay, keyring: ring(), onFiles: (f) => lists.push(f) });
      await vi.waitFor(() => expect(lists.length).toBeGreaterThan(0));
      expect(lists.at(-1)![0]!.name).toBe("name-1");
    }
  });
});
