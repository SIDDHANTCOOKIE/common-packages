# @formstr/drive-sdk

`@formstr/drive-sdk` implements the file portion of NIP-FS: encrypted file metadata on Nostr, encrypted blobs on Blossom, and ephemeral-key file sharing.

The package has no UI, relay connection, or key-storage policy. Applications inject a Nostr event store, signer, drive metadata conversation key, and Blossom transport.

## Drive Key

The Drive Key is a secp256k1 secret kept in the user's own kind `34578` event at `d=0:<pubkey>`, encrypted to the identity key. It is a **keyring**: an active key plus every previous key, so files written before a rotation stay readable.

```ts
import { resolveDriveKeyStatus } from "@formstr/drive-sdk";

const status = await resolveDriveKeyStatus({ store, signer, relays, configuredRelays });
switch (status.kind) {
  case "ready":           // status.keyring.active / status.keyring.previous
  case "empty-confirmed": // proven: no key exists. The only status that permits mintDriveKey.
  case "unresolved":      // status.reason — timeout, unreachable relays, unreadable event…
}
```

`unresolved` is **never** "empty". A timeout, an unreachable relay, an event this build cannot read, or a store that cannot prove relay coverage all resolve to `unresolved`, and nothing in this package creates a key on that verdict.

> **The mint hazard.** There is exactly one Drive Key event per identity, and it is replaceable: publishing a second one does not sit beside the first, it replaces it on every relay that accepts it, orphaning every file under the original key. Never write `current ?? await mintDriveKey(...)`: a `null`/failed lookup is not evidence that no key exists. See [ADR 0003](docs/adr/0003-drive-key-mint-hazard.md).

`mintDriveKey` re-resolves uncached and refuses unless the verdict is `empty-confirmed`. `rotateDriveKey` needs a `ready` keyring and always carries the old active key into `previousKeys`. `healDriveKey` republishes the union when a relay's newest event is narrower than the keys you provably hold. Nothing in the package can publish a keyring that drops a key.

`empty-confirmed` requires the host to pass `configuredRelays` and a store with `seenOn` (local-relay has it): the proof is that every configured relay answered a control query. Without both it is never emitted, and the host decides how to treat a first-time user.

## Install

```sh
pnpm add @formstr/drive-sdk
```

## Upload

```ts
import { createFetchBlossomTransport, uploadFile } from "@formstr/drive-sdk";

const result = await uploadFile(file, {
  name: file.name,
  type: file.type || "application/octet-stream",
  parent: "folder-id",
  servers: ["https://blossom.example"],
  metadataConversationKey,
}, {
  dataLayer,
  signer,
  transport: createFetchBlossomTransport(),
  onProgress: console.log,
});
```

`uploadFile` encrypts raw file segments with AES-256-GCM, concatenates them into one blob, uploads that blob to each declared server, and publishes encrypted kind `34578` metadata. The default plaintext segment size is 64 KiB and can be overridden with `chunkSize`.

## List And Download

```ts
const subscription = fetchFiles({ authors: [pubkey] }, {
  dataLayer,
  metadataConversationKey,
  onFiles: renderFiles,
});

const blob = await downloadFile(fileMetadata, {
  transport: createFetchBlossomTransport(),
  signer, // Optional BUD-01 authorization for protected servers.
});

subscription.stop();
```

Downloads try the metadata servers in order and verify both the encrypted blob hash and decrypted file hash.

## Share A File

```ts
const shared = await shareFile(fileMetadata, { dataLayer });

// Send the event coordinate and this key using a channel chosen by the app.
sendShare(shared.signedEvent, shared.sharingKey);
```

Sharing publishes a duplicate metadata event under `t=shared-file`, encrypted to a new ephemeral keypair. It does not upload another blob. The recipient can decrypt the event with `decryptSharedFileMetadata(event.content, sharingKey)` and then use `downloadFile` normally. Key delivery and folder sharing are intentionally outside this SDK.

## Folders

```ts
const created = createFolderMetadata({
  name: "Documents",
  parent: "",
  metadataConversationKey,
});
await dataLayer.publish(created.event);

const folders = fetchFolders({ authors: [pubkey] }, {
  dataLayer,
  metadataConversationKey,
  onFolders: (folders) => renderFolders(folders), // Each folder includes its d tag as `id`.
});
```

Folder events use kind `34578`, `t=folder`, and the same decoupled drive conversation key as file metadata. Renames and moves publish a replacement event with the same `d` tag.

## Lower-Level APIs

- `encryptFile` and `decryptFileBytes` implement the NIP-FS single-blob wire format.
- `createFileMetadata` and `decryptFileMetadata` handle drive-key metadata events.
- `createFolderMetadata`, `decryptFolderMetadata`, and `fetchFolders` handle virtual folders.
- `fetchEncryptionKey`, `updateEncryptionKey`, and `deriveMetadataConversationKey` implement decoupled drive keys.
- `createSharedFileMetadata` handles unpublished shared-file events.
- `fileSchema`, `isFile`, and `assertFile` expose the authoritative JSON Schema and runtime validation.
- `createFetchBlossomTransport` provides a fetch-based Blossom transport; applications may inject another implementation.
