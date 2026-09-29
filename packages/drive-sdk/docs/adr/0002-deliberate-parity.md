# ADR 0002 — Read leniently, write the spec

**Status:** accepted, 2026-09-29

## Context

A drive is shared between this SDK and the app, and the two do not write the same file
metadata. The NIP-FS spec shape, which the SDK writes:

```json
{ "name", "unencryptedFileHash", "size", "type", "parent", "uploadedAt", "servers": [],
  "encryptionKey", "encryptionAlgorithm", "blobHash", "chunkSize", "previewHash?" }
```

The shape the app writes today (`src/types/metadata.ts`):

```json
{ "id", "name", "size", "type", "folder": "/a/b", "uploadedAt", "server", "servers?",
  "encryptionKey", "encryptionAlgorithm", "blobHash?", "chunkSize?", "chunks?",
  "unencryptedFileHash?", "previewHash?", "deleted?" }
```

The app's `folder` is a **path string**; the spec's `parent` is a **folder id**. There is no
mapping between them that does not invent data.

## Decision

**Write the spec shape. Read both.** `readFileMetadata` (`src/file-entry.ts`) is the one
place the two are reconciled:

| Read | Becomes |
|---|---|
| `server` (no `servers`) | `servers = [server]` |
| `folder` | `folderPath` — **never** a `parent` id; `parent` stays `undefined` |
| `deleted: true` | tombstone, excluded from listings (but it still blocks older versions from resurrecting the file) |
| `id` in the payload | ignored; the event's `d` tag is the id |
| `unencryptedFileHash` absent | fine; integrity is verified only when it is there |
| `chunks`, no `blobHash` | `legacyChunked: true` — parses and lists |

A `FileEntry` also keeps the exact decrypted JSON as `raw`. Rename, move and delete republish
`{...raw, changed}`, so touching an app-written file does not silently drop fields this SDK
does not understand.

### Kept on purpose

**1. Legacy per-chunk files list but do not download.** The per-chunk layout used a different
cipher (`aesGcmDecryptBytes`, HKDF per chunk, random nonces). The SDK does not implement it.
`downloadFile`, `streamDecrypt`, `decryptRange` and `linkDuplicate` throw
`LegacyChunkedFileError` — never a partial or garbled read — and `isBlobLive` /
`findDuplicate` never offer one for reuse. `deleteFile` tombstones them but reports their chunk
blobs as skipped.

**2. App-shaped files cannot be moved.** `moveFile` throws `AppShapedFileError`. Renames work
and are lossless. Moving would mean turning a path into a parent id.

**3. Folders keep the spec's parent ids.** The SDK's folders (`t=folder`, `parent` ids) are ahead
of the app, which has no folder events. They are not regressed to paths.

**4. Shares carry the file's own payload.** `createFileShare` encrypts `file.raw`, so a share of
an app-shaped file stays app-shaped and a share of a spec-shaped file stays spec-shaped.
`resolveShare` reads either.

### Known interop gap

The app's shared-file viewer downloads from `file.server`. A share of a **spec-shaped** file has
`servers[]` and no `server`, so the app may not be able to open it until it dual-reads. This
follows directly from "write the spec shape", is an app-side fix, and is out of scope here.
Shares of app-written files are unaffected.

### Deviations from the app, all in the direction of safety

- **Tombstone before blobs.** `deleteFile` publishes the tombstone first and stops if it fails,
  so a failure never leaves a listed file whose blob is already gone. The app deletes blobs
  first.
- **Revoke does not request deletion of the bookkeeping event.** The app's NIP-09 courtesy
  request includes the info coordinate; on relays that honor kind-5 for addressable events that
  makes the revoked entry vanish from "Shared by me", which is the handle for retrying a
  failed revoke. The SDK asks only for the share coordinate.
- **Listing tie-break is the lowest event id**, as relays keep (NIP-01).
- **Bookkeeping is deduplicated by `d`**, newest wins; the app lists every event it is handed.
