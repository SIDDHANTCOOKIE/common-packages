import { nip44, verifyEvent, type Event } from "nostr-tools";
import { describe, expect, it, vi } from "vitest";
import {
  AllServersFailedError,
  AppShapedFileError,
  BlossomHttpError,
  createFetchBlossomTransport,
  createFileMetadata,
  createFolderMetadata,
  DEFINITIVE_REFUSAL_STATUSES,
  deleteFile,
  downloadFileStream,
  driveKeyEntry,
  encryptFile,
  fetchFiles,
  fetchFolders,
  findDuplicate,
  findHashesStillReferenced,
  isBlobLive,
  linkDuplicate,
  LegacyChunkedFileError,
  moveFile,
  moveFolder,
  RangeNotSatisfiedError,
  readFileMetadata,
  readFileRange,
  renameFile,
  renameFolder,
  UploadRefusedError,
  uploadEncryptedFile,
  uploadFile,
  type BlossomTransport,
  type DriveKeyring,
  type FileEntry,
  type FolderEntry,
} from "../src/index.js";
import { FakeRelay, makeIdentity } from "./helpers.js";

const KEY_NEW = "06".repeat(32);
const KEY_OLD = "05".repeat(32);
const keyring: DriveKeyring = { active: driveKeyEntry(KEY_NEW), previous: [driveKeyEntry(KEY_OLD)] };
const identity = makeIdentity(4);
const A = "https://a.example";
const B = "https://b.example";
const C = "https://c.example";

const specRaw = {
  name: "spec.txt",
  unencryptedFileHash: "a".repeat(64),
  size: 10,
  type: "text/plain",
  parent: "p1",
  uploadedAt: 1_700_000_000_000,
  servers: [A],
  encryptionKey: "07".repeat(32),
  encryptionAlgorithm: "aes-gcm",
  blobHash: "b".repeat(64),
  chunkSize: 4,
};

function entry(id: string, raw: Record<string, unknown> = specRaw, createdAt = 1, author = keyring.active.publicKey): FileEntry {
  return readFileMetadata(raw, { id, author, createdAt });
}

function uploadCtx(extra: Partial<Parameters<typeof uploadEncryptedFile>[1]> & { transport: BlossomTransport }) {
  return { signer: identity, servers: [A, B], sleep: async () => {}, retryDelayMs: 0, ...extra };
}

describe("BUD-06 canAccept classification (REGRESSION: only 403/413/415 refuse)", () => {
  const cases: Array<[number, boolean]> = [
    [200, true], [204, true], [401, true], [402, true], [403, false], [404, true], [405, true], [408, true],
    [409, true], [413, false], [415, false], [422, true], [429, true], [500, true], [501, true], [502, true], [503, true], [504, true],
  ];
  it.each(cases)("HEAD /upload answering %i → ok=%s", async (status, ok) => {
    const fetchMock = vi.fn(async () => new Response(null, { status, headers: status >= 400 ? { "X-Reason": "why" } : {} }));
    const transport = createFetchBlossomTransport(fetchMock as never);
    const verdict = await transport.canAccept!({ server: `${A}//`, size: 5, sha256: "c".repeat(64), type: "text/plain", authorization: "Nostr x" });
    expect(verdict.ok).toBe(ok);
    if (!ok) expect(verdict).toEqual({ ok: false, reason: "why", status });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${A}/upload`);
    expect(init.method).toBe("HEAD");
    expect(init.headers).toMatchObject({ Authorization: "Nostr x", "X-Content-Length": "5", "X-Content-Type": "text/plain", "X-SHA-256": "c".repeat(64) });
  });

  it("the refusal set is exactly {403, 413, 415}", () => {
    expect([...DEFINITIVE_REFUSAL_STATUSES].sort()).toEqual([403, 413, 415]);
  });

  it("network failures and timeouts are inconclusive, not refusals", async () => {
    const failing = createFetchBlossomTransport((async () => { throw new TypeError("network"); }) as never);
    expect(await failing.canAccept!({ server: A, size: 1, sha256: "c".repeat(64), type: "" })).toEqual({ ok: true });

    const hanging = createFetchBlossomTransport(
      ((_url: string, init: RequestInit) => new Promise((_resolve, reject) => {
        init.signal!.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      })) as never,
      { canAcceptTimeoutMs: 10 },
    );
    expect(await hanging.canAccept!({ server: A, size: 1, sha256: "c".repeat(64), type: "" })).toEqual({ ok: true });
  });

  it("a caller's own abort is not swallowed as inconclusive", async () => {
    const controller = new AbortController();
    controller.abort();
    const transport = createFetchBlossomTransport((async () => new Response(null)) as never);
    await expect(transport.canAccept!({ server: A, size: 1, sha256: "c".repeat(64), type: "", signal: controller.signal })).rejects.toMatchObject({ name: "AbortError" });

    const late = new AbortController();
    const slow = createFetchBlossomTransport(((_u: string, init: RequestInit) => new Promise((_r, reject) => {
      init.signal!.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      setTimeout(() => late.abort(), 0);
    })) as never);
    await expect(slow.canAccept!({ server: A, size: 1, sha256: "c".repeat(64), type: "", signal: late.signal })).rejects.toMatchObject({ name: "AbortError" });
  });

  it("falls back to the status text when the server sends no X-Reason", async () => {
    const transport = createFetchBlossomTransport((async () => new Response(null, { status: 413, statusText: "Payload Too Large" })) as never);
    expect(await transport.canAccept!({ server: A, size: 1, sha256: "c".repeat(64), type: "" })).toMatchObject({ ok: false, reason: "Payload Too Large" });
  });
});

describe("fetch transport: stream, range, exists, delete", () => {
  it("downloadStream returns a reader and surfaces HTTP errors with their status", async () => {
    const transport = createFetchBlossomTransport((async (url: string) => (url.endsWith("bad")
      ? new Response(null, { status: 404 })
      : new Response(new Uint8Array([1, 2, 3])))) as never);
    const reader = await transport.downloadStream!({ server: A, hash: "ok", authorization: "Nostr x" });
    const first = await reader.read();
    expect(first.value).toEqual(new Uint8Array([1, 2, 3]));
    await expect(transport.downloadStream!({ server: A, hash: "bad" })).rejects.toMatchObject({ status: 404 });
    const empty = createFetchBlossomTransport((async () => ({ ok: true, status: 200, body: null, headers: new Headers() })) as never);
    expect(await (await empty.downloadStream!({ server: A, hash: "x" })).read()).toEqual({ done: true });
  });

  it("downloadRange sends Range and reports 206 vs 200", async () => {
    const seen: Array<Record<string, string>> = [];
    const transport = createFetchBlossomTransport((async (_u: string, init: RequestInit) => {
      seen.push(init.headers as Record<string, string>);
      return new Response(new Uint8Array([9, 9]), { status: (init.headers as Record<string, string>).Range === "bytes=0-1" ? 206 : 200 });
    }) as never);
    expect(await transport.downloadRange!({ server: A, hash: "h", start: 0, end: 1, authorization: "Nostr x" })).toEqual({ bytes: new Uint8Array([9, 9]), satisfied: true });
    expect((await transport.downloadRange!({ server: A, hash: "h", start: 5, end: 6 })).satisfied).toBe(false);
    expect(seen[0]).toMatchObject({ Range: "bytes=0-1", Authorization: "Nostr x" });
    const failing = createFetchBlossomTransport((async () => new Response(null, { status: 416 })) as never);
    await expect(failing.downloadRange!({ server: A, hash: "h", start: 0, end: 1 })).rejects.toBeInstanceOf(BlossomHttpError);
  });

  it("exists: 200 true, 404 false, anything else throws instead of guessing", async () => {
    const statuses: Record<string, number> = { yes: 200, no: 404, weird: 503 };
    const transport = createFetchBlossomTransport((async (url: string) => new Response(null, { status: statuses[url.split("/").pop()!]! })) as never);
    expect(await transport.exists!({ server: A, hash: "yes", authorization: "Nostr x" })).toBe(true);
    expect(await transport.exists!({ server: A, hash: "no" })).toBe(false);
    await expect(transport.exists!({ server: A, hash: "weird" })).rejects.toMatchObject({ status: 503 });
  });

  it("delete: 2xx and 404 succeed, other statuses throw", async () => {
    const statuses: Record<string, number> = { ok: 200, gone: 404, denied: 403 };
    const calls: RequestInit[] = [];
    const transport = createFetchBlossomTransport((async (url: string, init: RequestInit) => {
      calls.push(init);
      return new Response(null, { status: statuses[url.split("/").pop()!]!, headers: { "X-Reason": "nope" } });
    }) as never);
    await transport.delete!({ server: A, hash: "ok", authorization: "Nostr x" });
    await transport.delete!({ server: A, hash: "gone", authorization: "Nostr x" });
    await expect(transport.delete!({ server: A, hash: "denied", authorization: "Nostr x" })).rejects.toThrow("nope");
    expect(calls[0]).toMatchObject({ method: "DELETE", headers: { Authorization: "Nostr x" } });
  });

  it("upload errors carry the HTTP status", async () => {
    const transport = createFetchBlossomTransport((async () => new Response(null, { status: 413, headers: { "X-Reason": "too big" } })) as never);
    await expect(transport.upload({ server: A, bytes: new Uint8Array(1) })).rejects.toMatchObject({ status: 413, message: "too big" });
  });
});

interface FakeServer { accept?: (call: number) => Error | undefined; canAccept?: { ok: boolean; reason?: string; status?: number } | Error }

function fakeTransport(servers: Record<string, FakeServer> = {}) {
  const log: string[] = [];
  const counts: Record<string, number> = {};
  const transport: BlossomTransport = {
    async canAccept({ server }) {
      log.push(`canAccept:${server}`);
      const verdict = servers[server]?.canAccept;
      if (verdict instanceof Error) throw verdict;
      return verdict ?? { ok: true };
    },
    async upload({ server, onBytes, bytes }) {
      counts[server] = (counts[server] ?? 0) + 1;
      log.push(`put:${server}`);
      const error = servers[server]?.accept?.(counts[server]!);
      if (error) throw error;
      onBytes?.(bytes.length, bytes.length);
    },
    async download() { throw new Error("unused"); },
  };
  return { transport, log, counts };
}

describe("uploadEncryptedFile: fallback and honest reporting", () => {
  async function blob() { return encryptFile(new Uint8Array([1, 2, 3, 4, 5]), { chunkSize: 4 }); }

  it("preflights, then PUTs, and stops at the first server that accepts (fallback)", async () => {
    const { transport, log } = fakeTransport();
    const outcome = await uploadEncryptedFile(await blob(), uploadCtx({ transport }));
    expect(outcome).toEqual({ landed: [A], failures: [] });
    expect(log).toEqual([`canAccept:${A}`, `put:${A}`]);
  });

  it("replicate uploads to every server", async () => {
    const { transport, log } = fakeTransport();
    const outcome = await uploadEncryptedFile(await blob(), uploadCtx({ transport, strategy: "replicate" }));
    expect(outcome.landed).toEqual([A, B]);
    expect(log.filter((l) => l.startsWith("put:"))).toEqual([`put:${A}`, `put:${B}`]);
  });

  it("a definitive refusal skips that server without sending the body, and is reported as refused", async () => {
    const { transport, log } = fakeTransport({ [A]: { canAccept: { ok: false, reason: "too large", status: 413 } } });
    const outcome = await uploadEncryptedFile(await blob(), uploadCtx({ transport }));
    expect(outcome.landed).toEqual([B]);
    expect(outcome.failures).toHaveLength(1);
    expect(outcome.failures[0]).toMatchObject({ server: A, refused: true });
    expect(outcome.failures[0]!.error).toBeInstanceOf(UploadRefusedError);
    expect((outcome.failures[0]!.error as UploadRefusedError).status).toBe(413);
    expect(log).not.toContain(`put:${A}`);
  });

  it("a refusal with no reason still reports something", async () => {
    const { transport } = fakeTransport({ [A]: { canAccept: { ok: false } } });
    const outcome = await uploadEncryptedFile(await blob(), uploadCtx({ transport }));
    expect((outcome.failures[0]!.error as Error).message).toBe("Server refused this upload");
  });

  it("an inconclusive probe (ok:true) still proceeds to the real PUT", async () => {
    const { transport, log } = fakeTransport({ [A]: { canAccept: { ok: true } } });
    await uploadEncryptedFile(await blob(), uploadCtx({ transport }));
    expect(log).toContain(`put:${A}`);
  });

  it("works with a transport that has no canAccept", async () => {
    const { transport } = fakeTransport();
    delete (transport as { canAccept?: unknown }).canAccept;
    expect((await uploadEncryptedFile(await blob(), uploadCtx({ transport }))).landed).toEqual([A]);
  });

  it("retries transient failures on a server, then moves on, reporting the last error", async () => {
    const boom = new BlossomHttpError("busy", 503);
    const { transport, counts } = fakeTransport({ [A]: { accept: () => boom } });
    const sleep = vi.fn(async () => {});
    const outcome = await uploadEncryptedFile(await blob(), uploadCtx({ transport, sleep, retryDelayMs: 7 }));
    expect(counts[A]).toBe(3);
    expect(sleep).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledWith(7);
    expect(outcome.landed).toEqual([B]);
    expect(outcome.failures).toEqual([{ server: A, refused: false, error: boom }]);
  });

  it("a transient failure that recovers on retry counts as landed", async () => {
    const { transport, counts } = fakeTransport({ [A]: { accept: (call) => (call < 2 ? new BlossomHttpError("blip", 502) : undefined) } });
    const outcome = await uploadEncryptedFile(await blob(), uploadCtx({ transport }));
    expect(outcome).toEqual({ landed: [A], failures: [] });
    expect(counts[A]).toBe(2);
  });

  it.each([401, 403, 413, 415])("a permanent %i is never retried on the same server", async (status) => {
    const { transport, counts } = fakeTransport({ [A]: { accept: () => new BlossomHttpError("no", status) } });
    await uploadEncryptedFile(await blob(), uploadCtx({ transport }));
    expect(counts[A]).toBe(1);
  });

  it("uses the default sleep and attempts when none are injected", async () => {
    const { transport, counts } = fakeTransport({ [A]: { accept: (call) => (call < 2 ? new Error("blip") : undefined) } });
    const outcome = await uploadEncryptedFile(await blob(), { signer: identity, servers: [A], transport, retryDelayMs: 1 });
    expect(outcome.landed).toEqual([A]);
    expect(counts[A]).toBe(2);
  });

  it("at least one success is required: otherwise every server's failure is reported", async () => {
    const { transport } = fakeTransport({
      [A]: { canAccept: { ok: false, reason: "type", status: 415 } },
      [B]: { accept: () => new BlossomHttpError("down", 500) },
    });
    const error = await uploadEncryptedFile(await blob(), uploadCtx({ transport, attempts: 1 })).catch((e) => e);
    expect(error).toBeInstanceOf(AllServersFailedError);
    expect(error.failures.map((f: { server: string; refused: boolean }) => [f.server, f.refused])).toEqual([[A, true], [B, false]]);
    expect(error.message).toContain(A);
    expect(error.message).toContain("down");
  });

  it("stringifies non-Error failures", () => {
    expect(new AllServersFailedError([{ server: A, refused: false, error: "plain" }]).message).toContain("plain");
  });

  it("rejects an empty server list and honors abort", async () => {
    const { transport } = fakeTransport();
    await expect(uploadEncryptedFile(await blob(), uploadCtx({ transport, servers: [] }))).rejects.toThrow("At least one");
    const controller = new AbortController();
    controller.abort();
    await expect(uploadEncryptedFile(await blob(), uploadCtx({ transport, signal: controller.signal }))).rejects.toMatchObject({ name: "AbortError" });

    const mid = new AbortController();
    const aborting: BlossomTransport = {
      async upload() { mid.abort(); throw new Error("interrupted"); },
      async download() { throw new Error("unused"); },
    };
    await expect(uploadEncryptedFile(await blob(), uploadCtx({ transport: aborting, signal: mid.signal }))).rejects.toThrow("interrupted");
  });

  it("reports progress against the strategy's total, and signs one authorization", async () => {
    const { transport } = fakeTransport();
    const progress = vi.fn();
    const file = await blob();
    await uploadEncryptedFile(file, uploadCtx({ transport, onProgress: progress, now: () => 100 }));
    expect(progress).toHaveBeenLastCalledWith({ operation: "upload", completedBytes: file.bytes.length, totalBytes: file.bytes.length });
    const provided = vi.fn();
    await uploadEncryptedFile(file, { ...uploadCtx({ transport }), authorization: "Nostr given", signer: { getPublicKey: identity.getPublicKey, signEvent: provided } });
    expect(provided).not.toHaveBeenCalled();
  });
});

describe("uploadFile records where the blob actually landed", () => {
  it("lists only the servers that took the blob in metadata.servers", async () => {
    const { transport } = fakeTransport({ [A]: { canAccept: { ok: false, status: 413 } } });
    const relay = new FakeRelay();
    const result = await uploadFile(new Uint8Array([1, 2, 3]), {
      name: "x.bin", type: "application/octet-stream", parent: "", servers: [A, B, C], d: "fixed1", uploadedAt: 5,
    }, { store: relay, keyring, signer: identity, transport, sleep: async () => {} });
    expect(result.upload.landed).toEqual([B]);
    expect(result.metadata.file.servers).toEqual([B]);
    expect(result.upload.failures.map((f) => f.server)).toEqual([A]);
    const plaintext = JSON.parse(nip44.v2.decrypt(result.event.content, keyring.active.conversationKey));
    expect(plaintext.servers).toEqual([B]);
    expect(result.event.tags[0]).toEqual(["d", "fixed1"]);
    expect(verifyEvent(result.event)).toBe(true);
  });

  it("uploads nothing when metadata is invalid, and publishes nothing when every server fails", async () => {
    const { transport, log } = fakeTransport();
    const relay = new FakeRelay();
    await expect(uploadFile(new Uint8Array([1]), { name: "", type: "x", parent: "", servers: [A] }, { store: relay, keyring, signer: identity, transport })).rejects.toThrow("/name");
    expect(log).toEqual([]);
    const dead = fakeTransport({ [A]: { accept: () => new BlossomHttpError("no", 403) } });
    await expect(uploadFile(new Uint8Array([1]), { name: "x", type: "x", parent: "", servers: [A] }, { store: relay, keyring, signer: identity, transport: dead.transport }))
      .rejects.toBeInstanceOf(AllServersFailedError);
    expect(relay.published).toHaveLength(0);
  });
});

describe("dedup helpers", () => {
  const hash = "a".repeat(64);
  const withHash = (id: string, createdAt: number, extra: Record<string, unknown> = {}) =>
    entry(id, { ...specRaw, unencryptedFileHash: hash, ...extra }, createdAt);
  const { blobHash: _b, chunkSize: _c, ...legacyBase } = specRaw;

  it("findDuplicate returns the newest live match by plaintext hash", () => {
    const files = [withHash("old", 1), withHash("new", 9), withHash("other", 20, { unencryptedFileHash: "c".repeat(64) })];
    expect(findDuplicate(files, hash)?.id).toBe("new");
    expect(findDuplicate(files, hash.toUpperCase())?.id).toBe("new");
    expect(findDuplicate(files, "d".repeat(64))).toBeUndefined();
    expect(findDuplicate([], hash)).toBeUndefined();
  });

  it("REGRESSION: a legacy chunked file is never reused, and never shadows a reusable one", async () => {
    const legacy = entry("legacy", { ...legacyBase, unencryptedFileHash: hash, chunks: ["c".repeat(64)] }, 99);
    const good = withHash("good", 1);
    expect(findDuplicate([legacy, good], hash)?.id).toBe("good");
    expect(findDuplicate([legacy], hash)).toBeUndefined();
    const exists = vi.fn(async () => true);
    expect(await isBlobLive(legacy, { exists } as never)).toBe(false);
    expect(exists).not.toHaveBeenCalled();
    await expect(linkDuplicate(legacy, { name: "n", parent: "" }, { store: new FakeRelay(), keyring })).rejects.toBeInstanceOf(LegacyChunkedFileError);
  });

  it("skips tombstones", () => {
    expect(findDuplicate([withHash("gone", 5, { deleted: true })], hash)).toBeUndefined();
  });

  it("isBlobLive: true if any server has it; uncertain, missing or absent all read false", async () => {
    const file = withHash("f", 1, { servers: [A, B] });
    const exists = vi.fn(async ({ server }: { server: string }) => server === B);
    expect(await isBlobLive(file, { exists } as never)).toBe(true);
    expect(exists).toHaveBeenCalledTimes(2);
    expect(await isBlobLive(file, { exists: async () => false } as never)).toBe(false);
    expect(await isBlobLive(file, { exists: async () => { throw new Error("cannot tell"); } } as never)).toBe(false);
    expect(await isBlobLive(file, {} as never)).toBe(false);
  });

  it("linkDuplicate publishes a new entry that shares the blob", async () => {
    const relay = new FakeRelay();
    const source = withHash("orig", 1, { previewHash: "e".repeat(64) });
    const { metadata } = await linkDuplicate(source, { name: "copy.txt", parent: "p2", d: "copy1", uploadedAt: 3, client: "c", createdAt: 77 }, { store: relay, keyring });
    expect(metadata.file).toMatchObject({ name: "copy.txt", parent: "p2", blobHash: "b".repeat(64), encryptionKey: specRaw.encryptionKey, previewHash: "e".repeat(64), servers: [A] });
    expect(metadata.event.tags[0]).toEqual(["d", "copy1"]);
    expect(metadata.event.created_at).toBe(77);
    await expect(linkDuplicate(entry("nohash", { ...specRaw, unencryptedFileHash: undefined }), { name: "n", parent: "" }, { store: relay, keyring })).rejects.toThrow("unencryptedFileHash");
    const dead = new FakeRelay({ publishResult: { ok: false, accepted: 0, total: 1, relayResults: [] } });
    await expect(linkDuplicate(source, { name: "n", parent: "" }, { store: dead, keyring })).rejects.toThrow("No relay accepted");
    expect((await linkDuplicate(source, { name: "n", parent: "" }, { store: relay, keyring })).metadata.file.type).toBe("text/plain");
  });

  it("findHashesStillReferenced counts blob, preview and legacy chunk hashes of OTHER live files", () => {
    const deleting = entry("del", { ...specRaw, blobHash: "1".repeat(64), previewHash: "2".repeat(64) });
    const sibling = entry("sib", { ...specRaw, blobHash: "1".repeat(64), previewHash: "3".repeat(64) });
    const legacy = entry("leg", { ...legacyBase, chunks: ["4".repeat(64)] });
    const tomb = entry("tomb", { ...specRaw, blobHash: "5".repeat(64), deleted: true });
    const refs = findHashesStillReferenced([deleting, sibling, legacy, tomb], [deleting]);
    expect([...refs].sort()).toEqual(["1".repeat(64), "3".repeat(64), "4".repeat(64)]);
  });
});

describe("rename / move republish the same d", () => {
  function ctx(relay: FakeRelay) { return { store: relay, keyring }; }

  it("renameFile republishes the same d, newer, under the active key, keeping every other field", async () => {
    const relay = new FakeRelay();
    const file = entry("f1", { ...specRaw, somethingNew: 1 }, 100, driveKeyEntry(KEY_OLD).publicKey);
    const { event } = await renameFile(file, "renamed.txt", ctx(relay));
    expect(event.tags[0]).toEqual(["d", "f1"]);
    expect(event.created_at).toBeGreaterThan(100);
    expect(event.pubkey).toBe(keyring.active.publicKey); // re-encrypted under the ACTIVE key
    expect(JSON.parse(nip44.v2.decrypt(event.content, keyring.active.conversationKey))).toEqual({ ...specRaw, somethingNew: 1, name: "renamed.txt" });
    expect(relay.publishedEvents).toEqual([event]);
  });

  it("beats a future-dated original", async () => {
    const relay = new FakeRelay();
    const { event } = await renameFile(entry("f1", specRaw, 4_000_000_000), "x", ctx(relay));
    expect(event.created_at).toBe(4_000_000_001);
  });

  it("moveFile changes parent; app-shaped files are refused instead of fabricating an id", async () => {
    const relay = new FakeRelay();
    const { event } = await moveFile(entry("f1"), "p9", ctx(relay));
    expect(JSON.parse(nip44.v2.decrypt(event.content, keyring.active.conversationKey)).parent).toBe("p9");
    const { parent: _p, servers: _s, ...rest } = specRaw;
    const appFile = entry("a1", { ...rest, server: A, folder: "/docs" });
    await expect(moveFile(appFile, "p9", ctx(relay))).rejects.toBeInstanceOf(AppShapedFileError);
    // …but an app-shaped file can still be renamed, losslessly.
    const renamed = await renameFile(appFile, "n.txt", ctx(relay));
    expect(JSON.parse(nip44.v2.decrypt(renamed.event.content, keyring.active.conversationKey))).toEqual({ ...rest, server: A, folder: "/docs", name: "n.txt" });
  });

  it("rejects an empty name and a failed publish", async () => {
    await expect(renameFile(entry("f1"), "", ctx(new FakeRelay()))).rejects.toThrow("empty");
    const dead = new FakeRelay({ publishResult: { ok: false, accepted: 0, total: 1, relayResults: [] } });
    await expect(renameFile(entry("f1"), "x", ctx(dead))).rejects.toThrow("No relay accepted");
  });

  it("rename/move folders keep the spec's parent ids", async () => {
    const relay = new FakeRelay();
    const created = createFolderMetadata({ name: "Docs", parent: "root", keyring: { active: driveKeyEntry(KEY_OLD), previous: [] }, d: "fold1", createdAt: 10 });
    relay.add(created.event);
    let folders: FolderEntry[] = [];
    fetchFolders({ store: relay, keyring, onFolders: (f) => { folders = f; } });
    await vi.waitFor(() => expect(folders).toHaveLength(1));
    expect(folders[0]).toMatchObject({ id: "fold1", createdAt: 10, parent: "root" });

    const renamed = await renameFolder(folders[0]!, "Documents", ctx(relay));
    expect(JSON.parse(nip44.v2.decrypt(renamed.event.content, keyring.active.conversationKey))).toEqual({ name: "Documents", parent: "root" });
    expect(renamed.event.tags[0]).toEqual(["d", "fold1"]);
    expect(renamed.event.created_at).toBeGreaterThan(10);
    const moved = await moveFolder(folders[0]!, "other", ctx(relay));
    expect(JSON.parse(nip44.v2.decrypt(moved.event.content, keyring.active.conversationKey))).toEqual({ name: "Documents", parent: "other" }); // listings are live: the rename above already landed
    await expect(moveFolder(folders[0]!, "fold1", ctx(relay))).rejects.toThrow("into itself");
    await expect(renameFolder(folders[0]!, "", ctx(relay))).rejects.toThrow("/name");
  });

  it("a rename after rotation replaces the old-key event in listings", async () => {
    const relay = new FakeRelay();
    const oldRing: DriveKeyring = { active: driveKeyEntry(KEY_OLD), previous: [] };
    const created = createFileMetadata({ ...specRaw, keyring: oldRing, d: "f1", createdAt: 5 } as never);
    relay.add(created.event);
    let files: FileEntry[] = [];
    const handle = fetchFiles({ store: relay, keyring, onFiles: (f) => { files = f; } });
    await vi.waitFor(() => expect(files).toHaveLength(1));
    await renameFile(files[0]!, "after-rotation.txt", ctx(relay));
    await vi.waitFor(() => expect(files[0]!.name).toBe("after-rotation.txt"));
    expect(files).toHaveLength(1);
    handle.stop();
  });
});

describe("deleteFile", () => {
  function deleteCtx(relay: FakeRelay, transport: BlossomTransport, signer = identity) {
    return { store: relay, keyring, signer, transport, now: () => 100 };
  }
  function deletingTransport() {
    const deleted: Array<{ server: string; hash: string; authorization: string }> = [];
    const transport: BlossomTransport = {
      async upload() {},
      async download() { throw new Error("unused"); },
      async delete({ server, hash, authorization }) { deleted.push({ server, hash, authorization }); },
    };
    return { transport, deleted };
  }

  it("tombstones, requests NIP-09 deletion, and deletes the blob and preview on each server", async () => {
    const relay = new FakeRelay();
    const { transport, deleted } = deletingTransport();
    const file = entry("f1", { ...specRaw, servers: [A, B], previewHash: "e".repeat(64) }, 50);
    const result = await deleteFile(file, deleteCtx(relay, transport), { stillReferenced: new Set() });

    const tombstone = result.tombstone.event;
    expect(tombstone.tags[0]).toEqual(["d", "f1"]);
    expect(tombstone.pubkey).toBe(keyring.active.publicKey);
    expect(tombstone.created_at).toBeGreaterThan(50);
    expect(JSON.parse(nip44.v2.decrypt(tombstone.content, keyring.active.conversationKey))).toMatchObject({ deleted: true, name: "spec.txt" });

    const deletion = relay.publishedEvents.find((e) => e.kind === 5)!;
    expect(deletion.tags).toContainEqual(["a", `34578:${keyring.active.publicKey}:f1`]);
    expect(deletion.tags).toContainEqual(["k", "34578"]);
    expect(result.deletionRequested).toBe(true);
    expect(deletion.pubkey).toBe(keyring.active.publicKey); // Drive Key, not identity

    expect(deleted.map((d) => `${d.hash.slice(0, 1)}@${d.server}`).sort()).toEqual([`b@${A}`, `b@${B}`, `e@${A}`, `e@${B}`]);
    expect(result.blobs.deleted).toHaveLength(4);
    // One identity-signed authorization covers every blob (verb: delete).
    const auth = JSON.parse(atob(deleted[0]!.authorization.replace("Nostr ", ""))) as Event;
    expect(auth.pubkey).toBe(identity.pubkey);
    expect(auth.tags).toContainEqual(["t", "delete"]);
    expect(auth.tags.filter((t) => t[0] === "x").map((t) => t[1])).toEqual(["b".repeat(64), "e".repeat(64)]);
    expect(new Set(deleted.map((d) => d.authorization)).size).toBe(1);
  });

  it("REGRESSION: never deletes a hash another file still references", async () => {
    const relay = new FakeRelay();
    const { transport, deleted } = deletingTransport();
    const file = entry("f1", { ...specRaw, previewHash: "e".repeat(64) });
    const result = await deleteFile(file, deleteCtx(relay, transport), { stillReferenced: new Set(["b".repeat(64)]) });
    expect(deleted.map((d) => d.hash)).toEqual(["e".repeat(64)]);
    expect(result.blobs.skipped).toEqual([{ hash: "b".repeat(64), reason: "still-referenced" }]);
    // The tombstone still lands: only THIS listing entry is deleted.
    expect(result.tombstone.event.tags[0]).toEqual(["d", "f1"]);

    const none = deletingTransport();
    const all = await deleteFile(file, deleteCtx(relay, none.transport), { stillReferenced: new Set(["b".repeat(64), "e".repeat(64)]) });
    expect(none.deleted).toEqual([]);
    expect(all.blobs.skipped.map((s) => s.reason)).toEqual(["still-referenced", "still-referenced"]);
  });

  it("does not touch any blob when the tombstone cannot be published", async () => {
    const dead = new FakeRelay({ publishResult: { ok: false, accepted: 0, total: 1, relayResults: [] } });
    const { transport, deleted } = deletingTransport();
    await expect(deleteFile(entry("f1"), deleteCtx(dead, transport), { stillReferenced: new Set() })).rejects.toThrow("No relay accepted");
    expect(deleted).toEqual([]);
  });

  it("one blob failing never blocks the rest; failures are reported per server", async () => {
    const relay = new FakeRelay();
    const attempts: string[] = [];
    const transport: BlossomTransport = {
      async upload() {},
      async download() { throw new Error("unused"); },
      async delete({ server }) { attempts.push(server); if (server === A) throw new BlossomHttpError("nope", 403); },
    };
    const file = entry("f1", { ...specRaw, servers: [A, B] });
    const result = await deleteFile(file, deleteCtx(relay, transport), { stillReferenced: new Set(), reason: "bye" });
    expect(attempts).toEqual([A, B]);
    expect(result.blobs.deleted).toEqual([{ hash: "b".repeat(64), server: B }]);
    expect(result.blobs.failed).toHaveLength(1);
    expect(result.blobs.failed[0]).toMatchObject({ server: A });
    expect(relay.publishedEvents.find((e) => e.kind === 5)!.content).toBe("bye");
  });

  it("reports blobs skipped when the transport cannot delete, and legacy chunk blobs as skipped", async () => {
    const relay = new FakeRelay();
    const noDelete: BlossomTransport = { async upload() {}, async download() { throw new Error("unused"); } };
    const result = await deleteFile(entry("f1"), deleteCtx(relay, noDelete), { stillReferenced: new Set() });
    expect(result.blobs.skipped).toEqual([{ hash: "b".repeat(64), reason: "transport-cannot-delete" }]);

    const { blobHash: _b, chunkSize: _c, ...legacyBase } = specRaw;
    const legacy = entry("old", { ...legacyBase, chunks: ["c".repeat(64), "d".repeat(64)] });
    const { transport, deleted } = deletingTransport();
    const legacyResult = await deleteFile(legacy, deleteCtx(relay, transport), { stillReferenced: new Set() });
    expect(deleted).toEqual([]);
    expect(legacyResult.blobs.skipped).toEqual([
      { hash: "c".repeat(64), reason: "legacy-chunked" },
      { hash: "d".repeat(64), reason: "legacy-chunked" },
    ]);
    expect(legacyResult.tombstone.event.tags[0]).toEqual(["d", "old"]);
  });

  it("a rejected NIP-09 request never fails the delete", async () => {
    let calls = 0;
    const relay = new FakeRelay({ publishResult: () => (++calls === 1 ? { ok: true, accepted: 1, total: 1, relayResults: [] } : { ok: false, accepted: 0, total: 1, relayResults: [] }) });
    const { transport } = deletingTransport();
    const result = await deleteFile(entry("f1"), deleteCtx(relay, transport), { stillReferenced: new Set() });
    expect(result.deletionRequested).toBe(false);
    expect(result.blobs.deleted).toHaveLength(1);
  });
});

describe("streaming and range glue", () => {
  async function stored(size = 30, chunkSize = 8) {
    const plaintext = Uint8Array.from({ length: size }, (_, i) => (i * 3 + 1) % 251);
    const enc = await encryptFile(plaintext, { chunkSize, encryptionKey: "07".repeat(32) });
    const file = entry("f1", { ...specRaw, size, chunkSize, blobHash: enc.blobHash, unencryptedFileHash: enc.unencryptedFileHash, servers: [A, B] });
    return { plaintext, enc, file };
  }

  it("downloadFileStream opens the first server that answers and streams plaintext", async () => {
    const { plaintext, enc, file } = await stored();
    const opened: string[] = [];
    const transport: BlossomTransport = {
      async upload() {},
      async download() { throw new Error("unused"); },
      async downloadStream({ server, authorization }) {
        opened.push(`${server}:${authorization ?? "-"}`);
        if (server === A) throw new BlossomHttpError("down", 503);
        let sent = false;
        return { read: async () => (sent ? { done: true } : ((sent = true), { done: false, value: enc.bytes })) };
      },
    };
    const parts: Uint8Array[] = [];
    for await (const part of downloadFileStream(file, { transport, signer: identity, now: () => 5 })) parts.push(part);
    expect(opened.map((o) => o.split(" ")[0]!.replace(/:Nostr$/, ""))).toEqual([A, B]);
    expect(opened.every((o) => o.includes("Nostr "))).toBe(true); // BUD-01 authorization was signed for the GET
    expect(new Uint8Array(parts.flatMap((p) => [...p]))).toEqual(plaintext);
  });

  it("downloadFileStream fails clearly when no server opens, when the transport cannot stream, and on abort", async () => {
    const { file } = await stored();
    const failing: BlossomTransport = { async upload() {}, async download() { throw new Error("x"); }, async downloadStream() { throw new Error("nope"); } };
    await expect((async () => { for await (const _ of downloadFileStream(file, { transport: failing, authorization: "Nostr x" })) { /* drain */ } })()).rejects.toThrow("Unable to open");
    const bare: BlossomTransport = { async upload() {}, async download() { throw new Error("x"); } };
    await expect((async () => { for await (const _ of downloadFileStream(file, { transport: bare })) { /* drain */ } })()).rejects.toThrow("cannot stream");
    const controller = new AbortController();
    controller.abort();
    await expect((async () => { for await (const _ of downloadFileStream(file, { transport: failing, signal: controller.signal })) { /* drain */ } })()).rejects.toMatchObject({ name: "AbortError" });
    const mid = new AbortController();
    const aborting: BlossomTransport = { async upload() {}, async download() { throw new Error("x"); }, async downloadStream() { mid.abort(); throw new Error("cut"); } };
    await expect((async () => { for await (const _ of downloadFileStream(file, { transport: aborting, signal: mid.signal })) { /* drain */ } })()).rejects.toThrow("cut");
  });

  it("readFileRange fetches only covering segments, tries the next server, and never decodes an ignored Range", async () => {
    const { plaintext, enc, file } = await stored();
    const seen: string[] = [];
    const transport: BlossomTransport = {
      async upload() {},
      async download() { throw new Error("unused"); },
      async downloadRange({ server, start, end }) {
        seen.push(`${server}:${start}-${end}`);
        if (server === A) return { bytes: enc.bytes, satisfied: false }; // ignores Range
        return { bytes: enc.bytes.slice(start, end + 1), satisfied: true };
      },
    };
    expect(await readFileRange(file, 10, 20, { transport, authorization: "Nostr x" })).toEqual(plaintext.subarray(10, 21));
    expect(seen).toEqual([`${A}:24-71`, `${B}:24-71`]);
  });

  it("readFileRange reports RangeNotSatisfiedError when every server ignores Range, and aggregates other failures", async () => {
    const { enc, file } = await stored();
    const ignoring: BlossomTransport = { async upload() {}, async download() { throw new Error("x"); }, async downloadRange() { return { bytes: enc.bytes, satisfied: false }; } };
    await expect(readFileRange(file, 0, 4, { transport: ignoring })).rejects.toBeInstanceOf(RangeNotSatisfiedError);
    const failing: BlossomTransport = { async upload() {}, async download() { throw new Error("x"); }, async downloadRange() { throw new Error("boom"); } };
    await expect(readFileRange(file, 0, 4, { transport: failing })).rejects.toThrow("Unable to read a valid range");
    const bare: BlossomTransport = { async upload() {}, async download() { throw new Error("x"); } };
    await expect(readFileRange(file, 0, 4, { transport: bare })).rejects.toThrow("cannot fetch ranges");
    await expect(readFileRange(file, 5, 4, { transport: ignoring })).rejects.toBeInstanceOf(RangeError);
    const controller = new AbortController();
    controller.abort();
    await expect(readFileRange(file, 0, 4, { transport: ignoring, signal: controller.signal })).rejects.toMatchObject({ name: "AbortError" });
    const mid = new AbortController();
    const aborting: BlossomTransport = { async upload() {}, async download() { throw new Error("x"); }, async downloadRange() { mid.abort(); throw new Error("cut"); } };
    await expect(readFileRange(file, 0, 4, { transport: aborting, signal: mid.signal })).rejects.toThrow("cut");
  });
});
