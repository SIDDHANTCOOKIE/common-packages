#!/usr/bin/env node
// Generates test/vectors/app-0064bff.json from formstr-drive's OWN code at the pinned commit.
//
// The vectors are what the app really produces, not what this SDK believes it produces: the script
// extracts `src/` at the pinned SHA out of a formstr-drive checkout, bundles the app modules it needs
// with esbuild (stubbing only the browser/worker plumbing around them), and calls the app's real
// functions — encryptSegment, buildShareEvent, encodeShareLink, publishSupersedingEvent,
// restoreDriveKey, getDriveKeyStatus, buildSignedMetadataEvent, deleteFileMetadata.
//
//   node scripts/generate-golden.mjs --app <path to a formstr-drive checkout with node_modules installed>
//
// The checkout only needs to CONTAIN the pinned commit (`git archive` reads it from history) and to
// have its dependencies installed (nostr-tools, @noble/hashes are bundled from its node_modules).
// Ciphertexts use random nonces, so a re-run produces different bytes; every re-run must still pass
// test/golden.test.ts, which is the point: the SDK must decode what the app writes, whatever the nonce.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const PINNED_SHA = "0064bffcef4ecf73ae153894cce6a75b674f014d";
const here = dirname(fileURLToPath(import.meta.url));
const appIndex = process.argv.indexOf("--app");
const appDir = resolve(appIndex === -1 ? (process.env.FORMSTR_DRIVE_DIR ?? "") : (process.argv[appIndex + 1] ?? ""));
if (!appDir || appDir === resolve("")) {
  console.error("usage: node scripts/generate-golden.mjs --app <formstr-drive checkout>");
  process.exit(2);
}

const work = mkdtempSync(join(tmpdir(), "drive-golden-"));
try {
  // 1. The app's source at the pinned commit, regardless of what the checkout has checked out.
  execFileSync("git", ["-C", appDir, "cat-file", "-e", `${PINNED_SHA}^{commit}`]);
  const tarball = join(work, "app.tar");
  execFileSync("git", ["-C", appDir, "archive", "--format=tar", "-o", tarball, PINNED_SHA, "src"]);
  // Relative names + cwd: GNU tar reads "C:\..." as a remote host.
  execFileSync("tar", ["-xf", "app.tar"], { cwd: work });
  const src = join(work, "src");

  // 2. Stubs for everything that is browser/worker plumbing rather than the logic under test.
  const stubs = {
    "@formstr/local-relay": `
      import { matchFilter } from "nostr-tools";
      export const dataLayer = {
        observe(filters, handlers) {
          const g = globalThis.__golden;
          const hits = g.relayEvents.filter((e) => filters.some((f) => matchFilter(f, e)));
          queueMicrotask(() => { for (const e of hits) handlers.onEvent(e); handlers.onEose?.(); });
          return { id: "stub", unobserve() {}, update() {} };
        },
        async publishEvent(event) {
          globalThis.__golden.published.push(event);
          return { ok: true, accepted: 1, total: 1, relayResults: [{ relay: "wss://relay.one", status: "accepted", latencyMs: 1 }] };
        },
        async seenOn() { return []; },
      };`,
    signer: `
      const listeners = [];
      export const signerManager = {
        async getSigner() { return globalThis.__golden.signer; },
        getPubkey() { return globalThis.__golden.signer.pubkey; },
        onChange(fn) { listeners.push(fn); return () => {}; },
        __logout() { listeners.forEach((fn) => fn(undefined)); },
      };
      globalThis.__signerManager = signerManager;`,
    persistence: `
      export const STORAGE_KEYS = {
        DRIVE_KEY_CACHE: "drive_key_cache",
        DRIVE_PUBKEY_CACHE: "drive_pubkey_cache",
        DRIVE_KEY_MINTED_MARKER: "drive_key_minted_marker",
      };
      export async function getStoredItem(key, fallback) { const v = globalThis.__golden.storage[key]; return v === undefined ? fallback : v; }
      export async function setStoredItem(key, value) { globalThis.__golden.storage[key] = value; }
      export async function removeStoredItem(key) { delete globalThis.__golden.storage[key]; }`,
    common: `
      export const APP_RELAYS = ["wss://relay.one"];
      export const defaultRelays = [];
      export const mergeRelayLists = (...lists) => Array.from(new Set(lists.flat()));
      export const normalizeRelayUrl = (u) => u.replace(/\\/+$/, "").toLowerCase();`,
    platform: `export const isNativePlatform = false;`,
    bootstrap: `export const getLocalRelayClient = () => null;`,
    outbox: `
      export async function enqueueMetadataEvent() {}
      export async function publishAndDequeue(event) {
        globalThis.__golden.outbox.push(event);
        return { ok: true, accepted: 1, total: 1, relayResults: [{ relay: "wss://relay.one", status: "accepted", latencyMs: 1 }] };
      }`,
    deletion: `export async function publishDeletionRequest(coordinates, reason) { globalThis.__golden.deletionRequests.push({ coordinates, reason }); }`,
    blossom: `export class BlossomClient {}`,
  };
  const stubFor = [
    [/^@formstr\/local-relay$/, "@formstr/local-relay"],
    [/\/signer\/manager$/, "signer"],
    [/\/utils\/persistence$/, "persistence"],
    [/\/utils\/common$/, "common"],
    [/\/utils\/platform$/, "platform"],
    [/\/dataLayer\/bootstrap$/, "bootstrap"],
    [/\/metadataOutbox$/, "outbox"],
    [/\/deletionRequest$/, "deletion"],
    [/\/blossom$/, "blossom"],
  ];

  const harness = `
    import { finalizeEvent, getPublicKey, nip44, verifyEvent } from "nostr-tools";
    import { bytesToHex, hexToBytes } from "nostr-tools/utils";
    import { sha256 } from "@noble/hashes/sha256";
    import * as appCrypto from ${JSON.stringify(join(src, "crypto.ts").replaceAll("\\", "/"))};
    import * as driveKey from ${JSON.stringify(join(src, "services/driveKey.ts").replaceAll("\\", "/"))};
    import * as fileIndex from ${JSON.stringify(join(src, "services/fileIndex.ts").replaceAll("\\", "/"))};
    import { buildShareEvent } from ${JSON.stringify(join(src, "services/sharing/event.ts").replaceAll("\\", "/"))};
    import { encodeShareLink } from ${JSON.stringify(join(src, "services/sharing/link.ts").replaceAll("\\", "/"))};
    import * as shareInfo from ${JSON.stringify(join(src, "services/sharing/shareInfo.ts").replaceAll("\\", "/"))};

    const hex = (byte) => byte.toString(16).padStart(2, "0").repeat(32);
    const IDENTITY = hex(0x11);
    const KEY_A = hex(0x21); // active Drive Key
    const KEY_B = hex(0x22); // previous Drive Key
    const FILE_KEY = hex(0x31);

    const identitySecret = hexToBytes(IDENTITY);
    const identityPubkey = getPublicKey(identitySecret);
    globalThis.__golden = {
      published: [], outbox: [], relayEvents: [], storage: {}, deletionRequests: [],
      signer: {
        pubkey: identityPubkey,
        async getPublicKey() { return identityPubkey; },
        async nip44Encrypt(peer, text) { return nip44.v2.encrypt(text, nip44.v2.utils.getConversationKey(identitySecret, peer)); },
        async nip44Decrypt(peer, text) { return nip44.v2.decrypt(text, nip44.v2.utils.getConversationKey(identitySecret, peer)); },
        async signEvent(template) { return finalizeEvent(template, identitySecret); },
      },
    };
    globalThis.window = { location: { origin: "https://drive.example", pathname: "/" } };
    const g = globalThis.__golden;
    const check = (event) => { if (!verifyEvent(event)) throw new Error("app produced an event with a bad signature"); return event; };

    // ---- Drive Key events, all three payload shapes ---------------------------------------------
    await driveKey.restoreDriveKey(KEY_A, [KEY_B]);
    const withPrevious = check(g.published.at(-1));
    await driveKey.restoreDriveKey(KEY_A, []);
    const objectOnly = check(g.published.at(-1));
    const legacyContent = await g.signer.nip44Encrypt(identityPubkey, JSON.stringify([["encryptionKey", KEY_A]]));
    const legacy = check(await g.signer.signEvent({
      kind: 34578, created_at: 1_700_000_000,
      tags: [["d", "0:" + identityPubkey], ["client", "formstr-drive"]], content: legacyContent,
    }));

    // What the app's OWN reader makes of each shape: feed it through the payload cache and read the keyring.
    async function appReads(event) {
      globalThis.__signerManager.__logout();
      g.storage.drive_key_cache = { pubkey: identityPubkey, payloads: [{ content: event.content, created_at: event.created_at }] };
      const status = await driveKey.getDriveKeyStatus();
      if (status.kind !== "ready") throw new Error("app could not read its own Drive Key payload: " + JSON.stringify(status));
      return { active: status.keyring[0].secretKeyHex, all: status.keyring.map((k) => k.secretKeyHex) };
    }
    const readWithPrevious = await appReads(withPrevious);
    const readObjectOnly = await appReads(objectOnly);
    const readLegacy = await appReads(legacy);

    // Load the two-key keyring, the state the rest of the vectors are produced in.
    await appReads(withPrevious);
    const activeKey = await driveKey.getActiveDriveKey();

    // ---- NIP-FS segment-encrypted blob, from the app's own encryptSegment ------------------------
    const chunkSize = 16;
    const plaintext = Uint8Array.from({ length: 40 }, (_, i) => (i * 7 + 3) % 251);
    const blobKey = appCrypto.deriveConversationKeyFromHex(FILE_KEY);
    const total = appCrypto.segmentCount(plaintext.length, chunkSize);
    const parts = [];
    for (let i = 0; i < total; i += 1) {
      parts.push(await appCrypto.encryptSegment(plaintext.subarray(i * chunkSize, Math.min(plaintext.length, (i + 1) * chunkSize)), blobKey, i, i === total - 1));
    }
    const blob = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) { blob.set(p, at); at += p.length; }
    const blobHash = bytesToHex(sha256(blob));
    const unencryptedFileHash = bytesToHex(sha256(plaintext));

    // ---- App-shaped file metadata events, from the app's buildSignedMetadataEvent ----------------
    const appMetadata = {
      id: "abcd1234", name: "report.txt", size: plaintext.length, type: "text/plain", folder: "/docs/reports",
      uploadedAt: 1_700_000_000_000, server: "https://blossom.one", encryptionKey: FILE_KEY, encryptionAlgorithm: "aes-gcm",
      servers: ["https://blossom.one"], blobHash, chunkSize, unencryptedFileHash,
    };
    const appFileEvent = check(await fileIndex.buildSignedMetadataEvent(appMetadata));
    const legacyMetadata = {
      id: "legacy01", name: "old.bin", size: 10, type: "application/octet-stream", folder: "/",
      uploadedAt: 1_600_000_000_000, server: "https://blossom.one", encryptionKey: FILE_KEY, encryptionAlgorithm: "aes-gcm",
      chunks: ["c".repeat(64), { hash: "d".repeat(64), server: "https://blossom.two" }],
    };
    const legacyChunkedEvent = check(await fileIndex.buildSignedMetadataEvent(legacyMetadata));
    // The delete happens later in real life. (The app stamps with the plain wall clock, so back-to-back
    // edits in one second tie and relays would keep whichever event has the lower id.)
    const realNow = Date.now;
    Date.now = () => realNow() + 5000;
    await fileIndex.deleteFileMetadata("ignored", appMetadata);
    Date.now = realNow;
    const tombstoneEvent = check(g.outbox.at(-1));

    // ---- A share: event, naddr link, bookkeeping; then its revoke ---------------------------------
    const ephemeral = shareInfo.generateEphemeralEncryptionKey();
    const shareD = "s-9f8e7d6c";
    const shareEvent = check(buildShareEvent({
      subtype: "shared-file", dTag: shareD, payload: appMetadata,
      conversationKey: ephemeral.conversationKey, signingKey: hexToBytes(activeKey.secretKeyHex),
    }));
    const link = encodeShareLink({ pubkey: activeKey.publicKey, dTag: shareD, relays: ["wss://relay.one", "wss://relay.two"], secretKeyHex: ephemeral.secretKeyHex });
    const coordinate = "34578:" + activeKey.publicKey + ":" + shareD;
    const infoPayload = {
      kind: "file", name: appMetadata.name, source: { type: "file", id: appMetadata.id }, coordinate,
      relays: ["wss://relay.one", "wss://relay.two"], members: [], encryptionKey: ephemeral.secretKeyHex,
    };
    await shareInfo.writeShareInfo(activeKey, "si-11223344", infoPayload);
    const infoEvent = check(g.outbox.at(-1));

    g.relayEvents.push(shareEvent);
    const at2 = Math.floor(Date.now() / 1000);
    await shareInfo.publishSupersedingEvent(activeKey, coordinate, "shared-file", ephemeral.conversationKey, { v: 1, revoked: true, at: at2, kind: "file" });
    const revokedEvent = check(g.outbox.at(-1));

    const out = {
      source: { repo: "formstr-hq/formstr-drive", sha: ${JSON.stringify(PINNED_SHA)}, note: "Generated by scripts/generate-golden.mjs from the app's own code. Nonces are random: a re-run changes the bytes." },
      identity: { secretHex: IDENTITY, pubkey: identityPubkey },
      driveKeys: { activeHex: KEY_A, previousHex: KEY_B, activePubkey: getPublicKey(hexToBytes(KEY_A)), previousPubkey: getPublicKey(hexToBytes(KEY_B)) },
      driveKeyEvents: {
        withPrevious: { event: withPrevious, appReads: readWithPrevious },
        objectOnly: { event: objectOnly, appReads: readObjectOnly },
        legacyArray: { event: legacy, appReads: readLegacy, note: "The app has no writer for this shape any more; it is the format every pre-keyring production key is stored in. Its own reader decodes it." },
      },
      segmentBlob: {
        fileKeyHex: FILE_KEY, chunkSize, plaintextHex: bytesToHex(plaintext), blobHex: bytesToHex(blob), blobHash, unencryptedFileHash,
        segmentFrames: parts.map((p) => bytesToHex(p)),
      },
      appFile: { metadata: appMetadata, event: appFileEvent },
      legacyChunkedFile: { metadata: legacyMetadata, event: legacyChunkedEvent },
      tombstone: { metadata: { ...appMetadata, deleted: true }, event: tombstoneEvent },
      share: {
        d: shareD, coordinate, link, k: ephemeral.secretKeyHex, relays: ["wss://relay.one", "wss://relay.two"],
        event: shareEvent, payload: appMetadata, info: { d: "si-11223344", event: infoEvent, payload: { v: 1, ...infoPayload } },
      },
      revokedShare: { event: revokedEvent, payload: { v: 1, revoked: true, at: at2, kind: "file" }, link },
    };
    process.stdout.write("\\n@@GOLDEN@@" + JSON.stringify(out) + "@@END@@\\n");
    process.exit(0);
  `;

  const bundle = join(work, "bundle.mjs");
  await build({
    stdin: { contents: harness, resolveDir: src, sourcefile: "harness.mjs", loader: "ts" },
    outfile: bundle,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node20",
    logLevel: "warning",
    nodePaths: [join(appDir, "node_modules")],
    banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
    plugins: [{
      name: "stubs",
      setup(b) {
        b.onResolve({ filter: /.*/ }, (args) => {
          for (const [pattern, name] of stubFor) if (pattern.test(args.path)) return { path: name, namespace: "stub" };
          return undefined;
        });
        b.onLoad({ filter: /.*/, namespace: "stub" }, (args) => ({ contents: stubs[args.path] ?? stubs[Object.keys(stubs).find((k) => k === args.path)], loader: "js", resolveDir: src }));
      },
    }],
  });

  const output = execFileSync(process.execPath, [bundle], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, cwd: appDir, stdio: ["ignore", "pipe", "inherit"] });
  const match = /@@GOLDEN@@(.*)@@END@@/s.exec(output);
  if (!match) throw new Error("generator produced no vectors:\n" + output.slice(-2000));
  const vectors = JSON.parse(match[1]);

  const target = join(here, "..", "test", "vectors", "app-0064bff.json");
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, JSON.stringify(vectors, null, 2) + "\n");
  console.log(`wrote ${target}`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
