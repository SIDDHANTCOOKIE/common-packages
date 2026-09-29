import { getPublicKey, nip44, verifyEvent, type Event, type EventTemplate, type Filter } from "nostr-tools";
import { hexToBytes } from "nostr-tools/utils";
import { describe, expect, it, vi } from "vitest";
import {
  assertFile,
  assertFolder,
  createFolderMetadata,
  createBlossomAuthorization,
  createFetchBlossomTransport,
  createFileMetadata,
  decryptFileBytes,
  decryptFileMetadata,
  decryptFolderMetadata,
  downloadFile,
  driveKeyEntry,
  encryptFile,
  fetchFiles,
  fetchFolders,
  fileSchema,
  folderSchema,
  isFile,
  isFolder,
  METADATA_KIND,
  DRIVE_SDK_CLIENT,
  uploadEncryptedFile,
  uploadFile,
  type BlossomTransport,
  type File,
  type FileEventStore,
  type FileSigner,
  type DriveKeyring,
} from "./index.js";

const PUBKEY = "a".repeat(64);
const SIGNATURE = "b".repeat(128);
const ENCRYPTION_KEY = "01".repeat(32);
const SHARING_KEY = "02".repeat(32);

function sha256Hex(bytes: Uint8Array): Promise<string> {
  return crypto.subtle.digest("SHA-256", bytes as BufferSource)
    .then((digest) => Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join(""));
}

function metadataKey(): Uint8Array {
  const secret = new Uint8Array(32).fill(3);
  return nip44.v2.utils.getConversationKey(secret, getPublicKey(secret));
}

/** The keyring whose active key's conversation key equals metadataKey(). */
function testKeyring(previousSecret?: string): DriveKeyring {
  return {
    active: driveKeyEntry("03".repeat(32)),
    previous: previousSecret ? [driveKeyEntry(previousSecret)] : [],
  };
}

function signedEvent(template: EventTemplate, id = "c".repeat(64), pubkey = PUBKEY): Event {
  return { ...template, id, pubkey, sig: SIGNATURE };
}

function signer(overrides: Partial<FileSigner> = {}): FileSigner {
  return {
    getPublicKey: async () => PUBKEY,
    signEvent: async (template) => signedEvent(template),
    ...overrides,
  };
}

function memoryTransport(): {
  transport: BlossomTransport;
  blobs: Map<string, Uint8Array>;
  uploads: Array<{ server: string; authorization?: string }>;
  downloads: Array<{ server: string; hash: string; expectedSize?: number; authorization?: string }>;
} {
  const blobs = new Map<string, Uint8Array>();
  const uploads: Array<{ server: string; authorization?: string }> = [];
  const downloads: Array<{ server: string; hash: string; expectedSize?: number; authorization?: string }> = [];
  return {
    blobs,
    uploads,
    downloads,
    transport: {
      async upload({ server, bytes, authorization, onBytes }) {
        blobs.set(await sha256Hex(bytes), new Uint8Array(bytes));
        uploads.push({ server, authorization });
        onBytes?.(bytes.byteLength, bytes.byteLength);
      },
      async download({ server, hash, expectedSize, authorization, onBytes }) {
        downloads.push({ server, hash, expectedSize, authorization });
        const bytes = blobs.get(hash);
        if (!bytes) throw new Error("missing blob");
        onBytes?.(bytes.byteLength, bytes.byteLength);
        return new Uint8Array(bytes);
      },
    },
  };
}

function memoryStore(resultOk = true): {
  store: FileEventStore;
  published: Event[];
  filters: Filter[][];
  emit(event: Event): void;
  eose(): void;
  isObserved(): boolean;
} {
  let handlers: { onEvent(event: Event): void; onEose?(): void } | undefined;
  const published: Event[] = [];
  const filters: Filter[][] = [];
  return {
    published,
    filters,
    store: {
      observe: (nextFilters, nextHandlers) => {
        filters.push(nextFilters);
        handlers = nextHandlers;
        return { unobserve: () => { handlers = undefined; } };
      },
      publishEvent: async (event) => {
        published.push(event);
        return { ok: resultOk, accepted: resultOk ? 1 : 0, total: 1, relayResults: [] };
      },
    },
    emit: (event) => handlers?.onEvent(event),
    eose: () => handlers?.onEose?.(),
    isObserved: () => Boolean(handlers),
  };
}

async function encryptedFixture(text = "NIP-FS fixture", chunkSize = 8): Promise<{ encrypted: Awaited<ReturnType<typeof encryptFile>>; file: File }> {
  const bytes = new TextEncoder().encode(text);
  const encrypted = await encryptFile(bytes, { chunkSize, encryptionKey: ENCRYPTION_KEY });
  return {
    encrypted,
    file: {
      name: "fixture.txt",
      unencryptedFileHash: encrypted.unencryptedFileHash,
      size: encrypted.size,
      type: "text/plain",
      parent: "root",
      uploadedAt: 1_700_000_000_000,
      servers: ["https://one.example"],
      encryptionKey: encrypted.encryptionKey,
      encryptionAlgorithm: "aes-gcm",
      blobHash: encrypted.blobHash,
      chunkSize: encrypted.chunkSize,
    },
  };
}

function decodeAuthorization(value: string): Event {
  return JSON.parse(atob(value.replace("Nostr ", ""))) as Event;
}

describe("NIP-FS encryption", () => {
  it.each([0, 1, 7, 8, 9, 16, 17])("round-trips a %i-byte file", async (size) => {
    const plaintext = Uint8Array.from({ length: size }, (_, index) => index % 251);
    const encrypted = await encryptFile(plaintext, { chunkSize: 8, encryptionKey: ENCRYPTION_KEY });
    const segmentCount = Math.max(1, Math.ceil(size / 8));
    const file: File = {
      name: "bytes.bin", unencryptedFileHash: encrypted.unencryptedFileHash, size, type: "application/octet-stream",
      parent: "", uploadedAt: 0, servers: ["https://one.example"], encryptionKey: encrypted.encryptionKey,
      encryptionAlgorithm: "aes-gcm", blobHash: encrypted.blobHash, chunkSize: 8,
    };

    expect(encrypted.bytes).toHaveLength(size + segmentCount * 16);
    expect(await decryptFileBytes(encrypted.bytes, file)).toEqual(plaintext);
  });

  it.each([65_535, 65_536, 65_537])("round-trips the default chunk boundary at %i bytes", async (size) => {
    const plaintext = new Uint8Array(size).fill(42);
    const encrypted = await encryptFile(plaintext, { encryptionKey: ENCRYPTION_KEY });
    const file: File = {
      name: "large.bin", unencryptedFileHash: encrypted.unencryptedFileHash, size, type: "application/octet-stream",
      parent: "", uploadedAt: 0, servers: ["https://one.example"], encryptionKey: encrypted.encryptionKey,
      encryptionAlgorithm: "aes-gcm", blobHash: encrypted.blobHash, chunkSize: encrypted.chunkSize,
    };
    expect(await decryptFileBytes(encrypted.bytes, file)).toEqual(plaintext);
  });

  it("encrypts raw bytes deterministically for a fixed ephemeral key", async () => {
    const encrypted = await encryptFile(new Blob(["hello"]), { chunkSize: 3, encryptionKey: ENCRYPTION_KEY });
    expect(encrypted.bytes).toHaveLength(37);
    expect(Array.from(encrypted.bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""))
      .toBe("e0a19ffa72a683c9d9f96e57ae9b7e8fa90afd7ce92981fa41ac3b5a055974294806d8d375");
    expect(encrypted.encryptionKey).toBe(ENCRYPTION_KEY);
    expect(encrypted.unencryptedFileHash).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    expect(encrypted.blobHash).toBe("1881bfdba20c0612db2af3841374455e4ae046ebacbecdd112bdb136090172e5");
    expect(new TextDecoder().decode(encrypted.bytes)).not.toContain("aGVsbG8=");
  });

  it.each([0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1])("rejects invalid chunk size %s", async (chunkSize) => {
    await expect(encryptFile(new Uint8Array(), { chunkSize })).rejects.toThrow("positive safe integer");
  });

  it.each(["", "0", "z".repeat(64)])("rejects invalid encryption key %s", async (encryptionKey) => {
    await expect(encryptFile(new Uint8Array(), { encryptionKey })).rejects.toThrow("32-byte hex private key");
  });

  it("generates a new ephemeral key by default", async () => {
    const first = await encryptFile(new Uint8Array([1]));
    const second = await encryptFile(new Uint8Array([1]));
    expect(first.encryptionKey).toMatch(/^[0-9a-f]{64}$/);
    expect(second.encryptionKey).not.toBe(first.encryptionKey);
  });

  it("rejects encrypted-blob and plaintext hash mismatches", async () => {
    const { encrypted, file } = await encryptedFixture();
    await expect(decryptFileBytes(encrypted.bytes, { ...file, blobHash: "0".repeat(64) })).rejects.toThrow("Encrypted blob hash");
    await expect(decryptFileBytes(encrypted.bytes, { ...file, unencryptedFileHash: "0".repeat(64) })).rejects.toThrow("Decrypted file hash");
  });

  it("rejects tampering, a wrong key, truncation, and trailing bytes", async () => {
    const { encrypted, file } = await encryptedFixture("0123456789abcdef", 8);
    const tampered = new Uint8Array(encrypted.bytes);
    tampered[0] ^= 1;
    await expect(decryptFileBytes(tampered, { ...file, blobHash: await sha256Hex(tampered) })).rejects.toThrow("segment 0");
    await expect(decryptFileBytes(encrypted.bytes, { ...file, encryptionKey: SHARING_KEY })).rejects.toThrow("segment 0");

    const truncated = encrypted.bytes.slice(0, -1);
    await expect(decryptFileBytes(truncated, { ...file, blobHash: await sha256Hex(truncated) })).rejects.toThrow("size does not match");
    const appended = new Uint8Array(encrypted.bytes.length + 1);
    appended.set(encrypted.bytes);
    await expect(decryptFileBytes(appended, { ...file, blobHash: await sha256Hex(appended) })).rejects.toThrow("size does not match");
  });

  it("authenticates segment order and the final-segment flag", async () => {
    const { encrypted, file } = await encryptedFixture("0123456789abcdef", 8);
    const reordered = new Uint8Array(encrypted.bytes.length);
    reordered.set(encrypted.bytes.subarray(24), 0);
    reordered.set(encrypted.bytes.subarray(0, 24), 24);
    await expect(decryptFileBytes(reordered, { ...file, blobHash: await sha256Hex(reordered) })).rejects.toThrow("segment 0");

    await expect(decryptFileBytes(encrypted.bytes, { ...file, size: 15, blobHash: encrypted.blobHash })).rejects.toThrow("size does not match");
  });
});

describe("file metadata schema and events", () => {
  it("derives runtime types and strict validation from one JSON Schema", async () => {
    const { file } = await encryptedFixture();
    expect(fileSchema.additionalProperties).toBe(false);
    expect(isFile(file)).toBe(true);
    expect(() => assertFile(file)).not.toThrow();

    for (const property of fileSchema.required ?? []) {
      const invalid = { ...file } as Record<string, unknown>;
      delete invalid[property];
      expect(isFile(invalid), property).toBe(false);
    }
    expect(isFile({ ...file, extra: true })).toBe(false);
  });

  it.each([
    ["name", ""], ["unencryptedFileHash", "bad"], ["size", -1], ["size", 1.5], ["type", ""],
    ["uploadedAt", -1], ["servers", []], ["servers", ["ftp://invalid"]], ["servers", ["https://same", "https://same"]],
    ["encryptionKey", "bad"], ["encryptionAlgorithm", "cbc"], ["previewHash", "bad"], ["blobHash", "bad"], ["chunkSize", 0],
  ])("rejects invalid %s", async (property, value) => {
    const { file } = await encryptedFixture();
    const invalid = { ...file, [property]: value };
    expect(isFile(invalid)).toBe(false);
    expect(() => assertFile(invalid)).toThrow(`/${property}`);
  });

  it.each(["0".repeat(64), "f".repeat(64)])("rejects invalid secp256k1 private scalar %s", async (encryptionKey) => {
    const { file } = await encryptedFixture();
    expect(isFile({ ...file, encryptionKey })).toBe(false);
    expect(() => assertFile({ ...file, encryptionKey })).toThrow("valid secp256k1 private key");
  });

  it("creates and decrypts exact file metadata event fields", async () => {
    const { encrypted, file } = await encryptedFixture();
    const key = metadataKey();
    const created = createFileMetadata({
      name: file.name, unencryptedFileHash: file.unencryptedFileHash, size: file.size, type: file.type,
      parent: file.parent, servers: file.servers, encryptionKey: file.encryptionKey, blobHash: file.blobHash,
      chunkSize: file.chunkSize, keyring: testKeyring(), previewHash: "4".repeat(64),
      d: "file1234", createdAt: 123, uploadedAt: 456, client: "test-client",
    });

    expect(created.event).toMatchObject({ kind: 34578, created_at: 123 });
    // Tag order is wire format: d, t, client, encrypted (matches the app).
    expect(created.event.tags).toEqual([["d", "file1234"], ["t", "files"], ["client", "test-client"], ["encrypted", "nip44"]]);
    // Signed by the Drive Key, not an identity signer.
    expect(created.event.pubkey).toBe(testKeyring().active.publicKey);
    expect(verifyEvent(created.event)).toBe(true);
    expect(created.file).not.toHaveProperty("folder");
    expect(created.file).not.toHaveProperty("chunks");
    expect(created.file).toMatchObject({ parent: "root", servers: ["https://one.example"], blobHash: encrypted.blobHash, chunkSize: 8 });
    expect(decryptFileMetadata(created.event.content, key)).toEqual(created.file);
  });

  it("rejects invalid metadata inputs and decrypted payloads with useful paths", async () => {
    const { file } = await encryptedFixture();
    expect(() => createFileMetadata({ ...file, keyring: testKeyring(), servers: [] })).toThrow("/servers");

    const key = metadataKey();
    const invalidContent = nip44.v2.encrypt(JSON.stringify({ ...file, chunkSize: 0 }), key);
    expect(() => decryptFileMetadata(invalidContent, key)).toThrow("/chunkSize");
  });
});

describe("folder metadata", () => {
  it("derives a strict Folder type from its JSON Schema", () => {
    expect(folderSchema.additionalProperties).toBe(false);
    expect(isFolder({ name: "Documents", parent: "" })).toBe(true);
    expect(isFolder({ name: "", parent: "" })).toBe(false);
    expect(isFolder({ name: "Documents", parent: "", extra: true })).toBe(false);
    expect(() => assertFolder({ name: "Documents" })).toThrow("/parent");
  });

  it("creates and decrypts folder events with the SDK client constant", () => {
    const key = metadataKey();
    const created = createFolderMetadata({
      name: "Documents",
      parent: "root",
      keyring: testKeyring(),
      d: "folder1",
      createdAt: 123,
    });
    expect(created.event).toMatchObject({
      kind: METADATA_KIND,
      created_at: 123,
      tags: [["d", "folder1"], ["t", "folder"], ["client", DRIVE_SDK_CLIENT], ["encrypted", "nip44"]],
      pubkey: testKeyring().active.publicKey,
    });
    expect(decryptFolderMetadata(created.event.content, key)).toEqual({ name: "Documents", parent: "root" });
    expect(() => createFolderMetadata({ name: "", parent: "", keyring: testKeyring() })).toThrow("/name");
  });

  it("fetches newest folder replacements and skips invalid events", () => {
    const key = metadataKey();
    const store = memoryStore();
    const received: Array<Array<{ id: string; name: string }>> = [];
    const onError = vi.fn();
    const handle = fetchFolders({
      store: store.store,
      keyring: testKeyring(),
      filter: { authors: [PUBKEY] },
      onFolders: (folders) => received.push(folders.map((folder) => ({ id: folder.id, name: folder.name }))),
      onError,
    });
    const old = createFolderMetadata({ name: "Old", parent: "", keyring: testKeyring(), d: "same", createdAt: 1 });
    const current = createFolderMetadata({ name: "Current", parent: "root", keyring: testKeyring(), d: "same", createdAt: 2 });
    store.emit({ ...old.event, id: "1".repeat(64) });
    store.emit({ ...current.event, id: "2".repeat(64) });
    expect(received.at(-1)).toEqual([{ id: "same", name: "Current" }]);
    store.emit({ ...current.event, content: "invalid", id: "3".repeat(64) });
    store.emit({ ...old.event, id: "0".repeat(64) });
    expect(store.filters[0]).toEqual([{ authors: [PUBKEY], kinds: [METADATA_KIND], "#t": ["folder"] }]);
    expect(received.at(-1)).toEqual([]);
    expect(onError).toHaveBeenCalledOnce();
    handle.stop();
  });
});

describe("file observation", () => {
  it("requests file events and keeps the newest event by timestamp then id", async () => {
    const key = metadataKey();
    const store = memoryStore();
    const received: string[][] = [];
    const onEose = vi.fn();
    const onError = vi.fn();
    const handle = fetchFiles({
      store: store.store, keyring: testKeyring(), filter: { authors: [PUBKEY] }, relayHints: ["wss://relay.example"],
      onFiles: (files) => received.push(files.map((file) => file.name)), onEose, onError,
    });
    expect(store.filters[0]).toEqual([{ authors: [PUBKEY], kinds: [34578] }]);

    const { file } = await encryptedFixture();
    const create = (name: string, createdAt: number) => createFileMetadata({ ...file, name, keyring: testKeyring(), d: "same", createdAt });
    store.emit({ ...create("old", 10).event, id: "1".repeat(64) });
    store.emit({ ...create("tie-winner", 10).event, id: "2".repeat(64) });
    store.emit({ ...create("tie-loser", 10).event, id: "0".repeat(64) });
    store.emit({ ...create("new", 20).event, id: "3".repeat(64) });
    expect(received.at(-1)).toEqual(["new"]);
    expect(onError).not.toHaveBeenCalled();

    store.eose();
    expect(onEose).toHaveBeenCalledOnce();
    handle.stop();
    expect(store.isObserved()).toBe(false);
  });

  it("skips wrong event subtypes and reports undecryptable file events", async () => {
    const store = memoryStore();
    const onFiles = vi.fn();
    const onError = vi.fn();
    fetchFiles({ store: store.store, keyring: testKeyring(), onFiles, onError });
    const wrongKind = signedEvent({ kind: 1, created_at: 1, tags: [["d", "x"], ["t", "files"]], content: "bad" });
    const wrongTag = signedEvent({ kind: 34578, created_at: 1, tags: [["d", "x"], ["t", "folder"]], content: "bad" });
    const noD = signedEvent({ kind: 34578, created_at: 1, tags: [["t", "files"]], content: "bad" });
    const invalid = signedEvent({ kind: 34578, created_at: 1, tags: [["d", "x"], ["t", "files"]], content: "bad" });
    store.emit(wrongKind);
    store.emit(wrongTag);
    store.emit(noD);
    store.emit(invalid);
    expect(onFiles).toHaveBeenLastCalledWith([]);
    expect(onError).toHaveBeenCalledOnce();
  });
});

describe("Blossom transport and authorization", () => {
  it("uploads and downloads bytes with fetch headers and normalized URLs", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { "content-length": "3" } }));
    const transport = createFetchBlossomTransport(fetchMock);
    const uploadProgress = vi.fn();
    await transport.upload({ server: "https://server.example///", bytes: new Uint8Array([1, 2, 3]), authorization: "Nostr auth", onBytes: uploadProgress });
    const downloadProgress = vi.fn();
    await expect(transport.download({ server: "https://server.example/", hash: "abc", authorization: "Nostr auth", onBytes: downloadProgress })).resolves.toEqual(new Uint8Array([1, 2, 3]));

    expect(fetchMock.mock.calls[0][0]).toBe("https://server.example/upload");
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ method: "PUT", headers: { Authorization: "Nostr auth", "Content-Type": "application/octet-stream" } });
    expect(fetchMock.mock.calls[1][0]).toBe("https://server.example/abc");
    expect(uploadProgress).toHaveBeenCalledWith(3, 3);
    expect(downloadProgress).toHaveBeenCalledWith(3, 3);
  });

  it("surfaces Blossom errors and aborts before fetch", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 403, headers: { "X-Reason": "denied" } }));
    const transport = createFetchBlossomTransport(fetchMock);
    await expect(transport.upload({ server: "https://s", bytes: new Uint8Array() })).rejects.toThrow("denied");
    await expect(transport.download({ server: "https://s", hash: "x" })).rejects.toThrow("denied");
    const controller = new AbortController();
    controller.abort();
    await expect(transport.upload({ server: "https://s", bytes: new Uint8Array(), signal: controller.signal })).rejects.toMatchObject({ name: "AbortError" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("bounds downloads by the expected encrypted file size", async () => {
    const declaredTooLarge = createFetchBlossomTransport(vi.fn().mockResolvedValue(
      new Response(new Uint8Array([1]), { status: 200, headers: { "content-length": "10" } }),
    ));
    await expect(declaredTooLarge.download({ server: "https://s", hash: "x", expectedSize: 1 })).rejects.toThrow("exceeds expected");

    const streamedTooLarge = createFetchBlossomTransport(vi.fn().mockResolvedValue(
      new Response(new Uint8Array([1, 2]), { status: 200 }),
    ));
    await expect(streamedTooLarge.download({ server: "https://s", hash: "x", expectedSize: 1 })).rejects.toThrow("exceeds expected");
  });

  it("creates one stable BUD authorization for the canonical blob hash", async () => {
    let now = 100;
    const authorization = await createBlossomAuthorization(signer(), "upload", ["f".repeat(64)], "upload", 300, () => now++);
    const event = decodeAuthorization(authorization);
    expect(event.created_at).toBe(100);
    expect(event.tags).toEqual([["t", "upload"], ["expiration", "400"], ["x", "f".repeat(64)]]);
  });

  it("rejects a signer that returns a different public key", async () => {
    await expect(createBlossomAuthorization(signer({
      signEvent: async (template) => signedEvent(template, "c".repeat(64), "d".repeat(64)),
    }), "get", [], "download", 1, () => 1)).rejects.toThrow("different pubkey");
  });
});

describe("upload and download workflows", () => {
  it("with strategy replicate, uploads one concatenated blob per server with one authorization", async () => {
    const { encrypted } = await encryptedFixture();
    const memory = memoryTransport();
    const progress = vi.fn();
    await uploadEncryptedFile(encrypted, {
      signer: signer(), transport: memory.transport, servers: ["https://one", "https://two"], strategy: "replicate", now: () => 100, onProgress: progress,
    });
    expect(memory.uploads.map(({ server }) => server)).toEqual(["https://one", "https://two"]);
    expect(new Set(memory.uploads.map(({ authorization }) => authorization)).size).toBe(1);
    const authorization = decodeAuthorization(memory.uploads[0].authorization ?? "");
    expect(authorization.tags.filter((tag) => tag[0] === "x")).toEqual([["x", encrypted.blobHash]]);
    expect(progress).toHaveBeenLastCalledWith({ operation: "upload", completedBytes: encrypted.bytes.length * 2, totalBytes: encrypted.bytes.length * 2 });
  });

  it("validates servers and honors upload cancellation", async () => {
    const { encrypted } = await encryptedFixture();
    const memory = memoryTransport();
    await expect(uploadEncryptedFile(encrypted, { signer: signer(), transport: memory.transport, servers: [] })).rejects.toThrow("At least one");
    const controller = new AbortController();
    controller.abort();
    await expect(uploadEncryptedFile(encrypted, {
      signer: signer(), transport: memory.transport, servers: ["https://one"], signal: controller.signal,
    })).rejects.toMatchObject({ name: "AbortError" });
    expect(memory.uploads).toHaveLength(0);
  });

  it("composes encryption, metadata validation, upload, and publication", async () => {
    const memory = memoryTransport();
    const store = memoryStore();
    const result = await uploadFile(new Blob(["complete upload"]), {
      name: "complete.txt", type: "text/plain", parent: "docs", servers: ["https://one.example"],
      chunkSize: 5, d: "upload1", createdAt: 50, uploadedAt: 60,
    }, { store: store.store, keyring: testKeyring(), signer: signer(), transport: memory.transport });
    expect(memory.uploads).toHaveLength(1);
    expect(store.published).toHaveLength(1);
    expect(result.metadata.file).toMatchObject({ parent: "docs", servers: ["https://one.example"], chunkSize: 5 });
    expect(result.event.kind).toBe(METADATA_KIND);
    expect(result.event.tags).toContainEqual(["client", DRIVE_SDK_CLIENT]);
  });

  it("does not upload invalid metadata and reports publication failure", async () => {
    const memory = memoryTransport();
    await expect(uploadFile(new Uint8Array([1]), {
      name: "bad", type: "x", parent: "", servers: [],
    }, { store: memoryStore().store, keyring: testKeyring(), signer: signer(), transport: memory.transport })).rejects.toThrow("/servers");
    expect(memory.uploads).toHaveLength(0);

    await expect(uploadFile(new Uint8Array([1]), {
      name: "ok", type: "x", parent: "", servers: ["https://one"],
    }, { store: memoryStore(false).store, keyring: testKeyring(), signer: signer(), transport: memory.transport })).rejects.toThrow("No relay accepted");
  });

  it("downloads once, authorizes the blob hash, verifies it, and preserves MIME type", async () => {
    const { encrypted, file } = await encryptedFixture("download test", 4);
    const memory = memoryTransport();
    await memory.transport.upload({ server: file.servers[0], bytes: encrypted.bytes });
    const progress = vi.fn();
    const blob = await downloadFile(file, { transport: memory.transport, signer: signer(), now: () => 100, onProgress: progress });
    expect(await blob.text()).toBe("download test");
    expect(blob.type).toBe("text/plain");
    expect(memory.downloads).toHaveLength(1);
    expect(memory.downloads[0].expectedSize).toBe(encrypted.bytes.byteLength);
    const authorization = decodeAuthorization(memory.downloads[0].authorization ?? "");
    expect(authorization.tags).toContainEqual(["t", "get"]);
    expect(authorization.tags).toContainEqual(["x", file.blobHash]);
    expect(progress).toHaveBeenCalled();
  });

  it("uses provided authorization and fails over from missing or corrupt replicas", async () => {
    const { encrypted, file } = await encryptedFixture("replicated");
    const corrupt = new Uint8Array(encrypted.bytes);
    corrupt[0] ^= 1;
    const transport: BlossomTransport = {
      upload: async () => undefined,
      download: vi.fn(async ({ server, authorization }) => {
        expect(authorization).toBe("provided");
        if (server === "https://missing") throw new Error("offline");
        if (server === "https://corrupt") return corrupt;
        return encrypted.bytes;
      }),
    };
    const blob = await downloadFile({ ...file, servers: ["https://missing", "https://corrupt", "https://good"] }, { transport, authorization: "provided" });
    expect(await blob.text()).toBe("replicated");
    expect(transport.download).toHaveBeenCalledTimes(3);
  });

  it("aggregates replica failures and honors download cancellation", async () => {
    const { file } = await encryptedFixture();
    const transport: BlossomTransport = {
      upload: async () => undefined,
      download: async () => { throw new Error("offline"); },
    };
    await expect(downloadFile({ ...file, servers: ["https://one", "https://two"] }, { transport })).rejects.toThrow("any Blossom server");
    const controller = new AbortController();
    controller.abort();
    await expect(downloadFile(file, { transport, signal: controller.signal })).rejects.toMatchObject({ name: "AbortError" });
  });
});
