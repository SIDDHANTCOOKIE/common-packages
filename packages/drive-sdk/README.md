# @formstr/drive-sdk

Headless TypeScript SDK for the Formstr Drive protocol (NIP-FS): encrypted file metadata on Nostr,
encrypted single blobs on Blossom, and ephemeral-key file sharing — byte-compatible with
[formstr-drive](https://github.com/formstr-hq/formstr-drive) at
[`0064bff`](docs/adr/0001-protocol-source-of-truth.md).

No UI, no relay connection, no key storage. The host injects an event store, an identity signer and a
Blossom transport.

```sh
pnpm add @formstr/drive-sdk
```

| | |
|---|---|
| [`docs/protocol.md`](docs/protocol.md) | the wire format, as implemented |
| [`docs/adr/`](docs/adr) | why it is the way it is — read before changing behaviour |

## What you inject

```ts
import type { FileEventStore, IdentitySigner, BlossomTransport } from "@formstr/drive-sdk";
import { createFetchBlossomTransport } from "@formstr/drive-sdk";

const store: FileEventStore = dataLayer;               // structural: see below
const signer: IdentitySigner = /* getPublicKey, signEvent, nip44Encrypt, nip44Decrypt */;
const transport: BlossomTransport = createFetchBlossomTransport();
```

`FileEventStore` is the slice of [`@formstr/local-relay`](../local-relay) `DataLayer` (>= 0.6) this package
uses: `observe(filters, handlers, { localOnly?, relays? })`, `publishEvent(event, { relays? })`, and
optionally `seenOn(id)`. `relays` are per-call hints — nothing here mutates the host's global routing.
`@formstr/drive-sdk/local-relay` (optional peer) type-checks that hand-off and keeps a class-based
DataLayer's `this`:

```ts
import { localRelayStore } from "@formstr/drive-sdk/local-relay";
const store = localRelayStore(dataLayer);
```

**Who signs what.** Metadata, shares and share bookkeeping are encrypted and signed with the **Drive
Key** — no signer prompt. The **identity** signer is used only for the Drive Key event itself and for
Blossom authorization (upload / get / delete).

## Drive Key

The Drive Key is a secp256k1 secret in the user's own replaceable event at `d=0:<pubkey>`. It is a
**keyring**: an active key plus every previous key, so files written before a rotation stay readable.

```ts
import { resolveDriveKeyStatus, mintDriveKey, rotateDriveKey } from "@formstr/drive-sdk";

const status = await resolveDriveKeyStatus({ store, signer, relays, configuredRelays });
switch (status.kind) {
  case "ready":           // status.keyring.active / .previous
  case "empty-confirmed": // proven: no key exists. The only status that permits mintDriveKey.
  case "unresolved":      // status.reason — timeout, unreachable relays, unreadable event…
}
```

`unresolved` is **never** "empty". A timeout, an unreachable relay, an event this build cannot read, or a
store that cannot prove relay coverage all resolve to `unresolved`, and nothing in the package creates a
key on that verdict.

> **The mint hazard.** There is one Drive Key event per identity and it is replaceable: publishing a second
> does not sit beside the first, it replaces it on every relay that accepts it, orphaning every file under
> the original key. Do not write `current ?? await mintDriveKey(…)` — a missing answer is not evidence that
> no key exists. `mintDriveKey` re-resolves uncached and throws `DriveKeyMintRefusedError` unless the
> verdict is `empty-confirmed`. See [ADR 0003](docs/adr/0003-drive-key-mint-hazard.md).

- `mintDriveKey(ctx)` — first key only; optional durable `marker` refuses a second mint for an identity.
- `rotateDriveKey(ctx, { encryptionKey? })` — needs a `ready` keyring; the old active key moves into
  `previousKeys`. Nothing can publish a keyring that drops a key.
- `healDriveKey(ctx)` — republishes the union when a relay's newest event is narrower than the keys you hold.
- `createDriveKeyStatusCache(ctx)` — `ready` cached, `empty-confirmed` for 30 s, `unresolved` never.

`empty-confirmed` requires `configuredRelays` **and** a store with `seenOn`. Without both it is never
emitted and the host decides what a first-time user is.

## List, upload, download

```ts
import { fetchFiles, uploadFile, downloadFile } from "@formstr/drive-sdk";

const handle = fetchFiles({ store, keyring, onFiles: render, onEose });   // FileEntry[]
handle.stop();

const uploaded = await uploadFile(file, {
  name: file.name, type: file.type || "application/octet-stream", parent: "folder-id",
  servers: ["https://blossom.example", "https://backup.example"],
}, { store, keyring, signer, transport, onProgress });

uploaded.upload.landed;     // servers that took the blob → also what `servers` in the metadata says
uploaded.upload.failures;   // every server that did not, and why (refused vs failed)

const blob = await downloadFile(entry, { transport, signer });
```

`fetchFiles` reads the spec shape **and** the app's shape (see [ADR 0002](docs/adr/0002-deliberate-parity.md)):
`folder` surfaces as `folderPath` (a path, not a parent id), `server` becomes `servers`, `deleted` is a
tombstone and is hidden. Legacy per-chunk files list but `downloadFile` throws `LegacyChunkedFileError`.

Upload: with `transport.canAccept` the SDK runs a BUD-06 preflight — **only 403/413/415 are refusals**;
404/501/429/5xx and timeouts proceed to the real PUT. `strategy: "fallback"` (default) stops at the first
server that accepts; `"replicate"` uploads to all. At least one must succeed.

### Streaming and ranges

```ts
import { downloadFileStream, readFileRange, streamDecrypt, decryptRange } from "@formstr/drive-sdk";

for await (const segment of downloadFileStream(entry, { transport, signer })) sink.write(segment);
const bytes = await readFileRange(entry, 1_000_000, 1_500_000, { transport, signer });
```

`streamDecrypt(reader, file)` (bring your own reader — e.g. a service worker's) throws on truncation
(`BlobTruncatedError`) **and** on trailing bytes (`BlobOverrunError`), and verifies `unencryptedFileHash`
incrementally — anything yielded before an `IntegrityError` is unverified, so discard it. `decryptRange`
fetches only the covering segments and throws `RangeNotSatisfiedError` if the server ignored `Range`
(200, not 206); misaligned bytes are never decoded. The pure `encryptSegment` / `decryptSegment` /
`segmentCount` are exported for hosts that stream.

## Rename, move, delete, dedup

```ts
import { renameFile, moveFile, deleteFile, findDuplicate, isBlobLive, linkDuplicate,
         findHashesStillReferenced, renameFolder, moveFolder } from "@formstr/drive-sdk";

await renameFile(entry, "new name", { store, keyring });   // same d, newer created_at, active key
await moveFile(entry, folderId, { store, keyring });        // refuses app-shaped files (no parent id to give)

const dup = findDuplicate(entries, unencryptedFileHash);
if (dup && await isBlobLive(dup, transport)) await linkDuplicate(dup, { name, parent }, { store, keyring });
else await uploadFile(/* … */);

await deleteFile(entry, { store, keyring, signer, transport }, {
  stillReferenced: findHashesStillReferenced(entries, [entry]),
});
```

`deleteFile` tombstones first (and stops if that fails), sends a best-effort NIP-09 request, then deletes
blobs — skipping every hash in `stillReferenced`.

> **Only call `deleteFile` after a full sync.** The SDK cannot tell whether your list is complete, and an
> incomplete one reads exactly like "nothing else uses this blob": the shared blob is destroyed and the
> surviving copies list normally, then 404 at download. The app gates on the index reaching **EOSE** — not
> on "the store is non-empty", because a partially loaded store looks complete to this check. Do the same.

## Sharing

```ts
import { ensureFileShare, resolveShare, revokeShare, listShares } from "@formstr/drive-sdk";

const { url } = await ensureFileShare(entry, { store, keyring, baseUrl: "https://drive.example/" });
// → https://drive.example/#shared=<naddr>&k=<64 hex>

const resolved = await resolveShare(url, { store });            // no signer, no identity
//   { kind: "file", file } | { kind: "revoked", target, at }

const [mine] = await listShares({ store, keyring });            // the app's "Shared by me"
await revokeShare(mine, { store, keyring });
```

`ensureFileShare` is idempotent: a live share for the same file id returns its link instead of
publishing a duplicate, and concurrent calls share one in-flight request. Relay hints in the link come from
the publish result (accepted relays only). Resolving a folder share (`t=container`) throws
`FolderShareUnsupportedError`. SDK shares appear in the app's "Shared by me" because the same
`shared-container` bookkeeping event is written.

## Folders

```ts
import { createFolderMetadata, fetchFolders } from "@formstr/drive-sdk";

const { event } = createFolderMetadata({ name: "Documents", parent: "", keyring });
await store.publishEvent(event);
fetchFolders({ store, keyring, onFolders });  // each folder has its d tag as `id`, plus createdAt
```

Folders use spec `parent` ids (the app has no folder events yet).

## Timestamps

Every addressable publish goes through `nextCreatedAt()`: strictly increasing within a burst, clamped to
`now + 60 s`. Past 61 stamps in one second it holds at the clamp rather than running ahead of the clock.

## Upgrading from 0.1

Breaking. `fetchEncryptionKey` / `updateEncryptionKey` are gone (see the hazard above); contexts take
`store` and `keyring` instead of `dataLayer` and `metadataConversationKey`; the store contract is
`publishEvent(event)`, not `publish(template)`; `shareFile` / `createSharedFileMetadata` are replaced by
the sharing API; `uploadFile` defaults to fallback rather than uploading to every server; tag order is now
`d, t, client, encrypted`.

## Reference

`createFileMetadata`, `decryptFileMetadata` (strict) and `decryptFileEntry` / `readFileMetadata` (lenient),
`fileSchema` / `isFile` / `assertFile`, `buildEvent`, `encodeShareLink` / `decodeShareLink`,
`createFetchBlossomTransport`, `createBlossomAuthorization`, `publishDeletionRequest`.
