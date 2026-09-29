# ADR 0004 — Scope: the drive protocol, not the drive app

**Status:** accepted, 2026-09-29

## Context

formstr-drive does a great deal that is application plumbing rather than protocol: service
workers, a native Android upload service, a persistent index, an outbox. Two clients have to
agree on the bytes on the wire; they do not have to share any of that.

## Decision

**In scope — what two clients must agree on:**

| | |
|---|---|
| Drive Key | keyring, three-state resolve, mint / rotate / heal, all payload shapes |
| Metadata | file and folder events, signed and encrypted with the Drive Key, lenient read |
| NIP-FS blob | per-segment crypto, `streamDecrypt`, `decryptRange`, buffered encrypt/decrypt |
| Upload | BUD-06 preflight, fallback / replicate, per-server failure report |
| Dedup | `findDuplicate`, `isBlobLive`, `linkDuplicate`, `findHashesStillReferenced` |
| Edit | rename / move (files, folders), delete (tombstone + NIP-09 + guarded blob delete) |
| File sharing | link codec, share / ensure / resolve / revoke, bookkeeping, `listShares` |

**Out of scope, and why:**

- **Folder sharing (`t=container`).** The app has set it aside itself ("Folder sharing is TBD" in
  NIP-FS). The SDK reads the subtype only to refuse it: `resolveShare` throws
  `FolderShareUnsupportedError`, `revokeShare` on a folder entry does too, and `buildEvent` will
  not author a `container`. Bookkeeping entries for folders written by the app are still listed.
- **Service-worker download wiring.** The SDK provides `streamDecrypt` / `downloadFileStream`;
  the host wires its own service worker to them.
- **Transfer queues and native upload drivers.** Retry policy above a single call, progress UI,
  background uploads.
- **A persistent file index.** The host owns its cache. The SDK's helpers take a list.
- **A durable publish outbox.** local-relay's `DeliveryOutbox` already owns retry; the SDK
  publishes through the store it is given.
- **Preview generation and encryption.** `previewHash` is carried through metadata and deleted
  with the file; producing or fetching a preview is the host's.
- **BUD-03 server discovery.** A reasonable follow-up. It predates #69–#72 and is not part of
  this parity pass.
- **Key delivery UI.** How a share link or a Drive Key reaches another person or device.

## The host's responsibilities, stated plainly

**`deleteFile` needs a complete index.** It takes a required `stillReferenced` set and never
deletes a hash in it, but the SDK cannot know whether the list the host built that set from is
complete. An incomplete list looks exactly like "nothing else uses this hash": the shared blob is
destroyed, and every surviving copy keeps listing normally and fails later with a 404. Only call
it after a full sync. The app gates on the index reaching **EOSE** — not on "the store is
non-empty", because a partially loaded store is indistinguishable from a complete one to this
check (`isFileIndexReady` in `fileIndex.ts`). Do the same.

**`ensureFileShare` needs a completed share list.** If `knownEntries` is passed it must have
finished its first load; an unloaded empty list looks like "never shared" and creates a
duplicate.

**Hosts decide first-run.** See ADR 0003: without `configuredRelays` + `seenOn` the SDK never
says a drive is empty.
