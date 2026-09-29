# ADR 0003 — The Drive Key mint hazard

**Status:** accepted, 2026-09-29

## Context

The Drive Key is one secp256k1 secret, stored in one **replaceable** event per identity
(kind `34578`, `d=0:<pubkey>`). Everything else — file metadata, shares — is encrypted and
signed with it.

Replaceable means a second Drive Key event does not sit beside the first. It **replaces** it
on every relay that accepts it. Every file under the original key is then unreadable, and
nothing the SDK or the app can do brings the key back.

SDK 0.1.0 made this easy to do by accident. `fetchEncryptionKey` returned `null` on a timeout,
and its README recommended:

```ts
const created = current ?? await updateEncryptionKey({ dataLayer, signer });
```

`null` there means *"I did not hear an answer"*. On a cold cache, a flaky mobile relay or a
relay-list the store had not learned yet, that is exactly what an existing user looks like.
formstr-drive's own source documents an incident of exactly this shape and now guards against it
heavily; this SDK had none of those guards.

## Decision

**Nothing creates a Drive Key unless absence has been proven, right now, by a lookup that
started at the decision.**

1. **Three states, not a nullable.** `resolveDriveKeyStatus` returns `ready`,
   `empty-confirmed` or `unresolved`. A timeout, an unreachable relay, or an event that exists
   but cannot be read is `unresolved` — *"a key exists but I can't read it"* is not *"no key
   exists"*.
2. **`empty-confirmed` needs a positive proof, or it is never emitted.** The proof is ported
   from the app's `identityHistory.ts`: (a) the identity has published nothing under kinds
   `0/3/10002/34578`, and (b) **every** relay in `configuredRelays` answered an
   identity-independent control query just now, established through `store.seenOn`. Without
   both a `seenOn` on the store and the host's `configuredRelays`, the SDK cannot prove
   coverage and returns `unresolved` — the host decides what a first-time user is. A cache-only
   (`localOnly`) lookup proves nothing about relays and can never be `empty-confirmed`.
3. **Minting re-resolves, uncached.** `mintDriveKey` takes no status argument. It resolves
   from scratch immediately before publishing and refuses (`DriveKeyMintRefusedError`) unless
   that verdict is `empty-confirmed`. A cached verdict cannot authorize it, of any age. The
   optional durable `marker` (host-owned storage) refuses a second mint for an identity that
   already minted, and is not recorded when the publish fails, so a new user can retry.
4. **The cache is bounded.** `createDriveKeyStatusCache` keeps `ready` (keys are only ever
   added), keeps `empty-confirmed` for 30 s (`EMPTY_CONFIRMED_TTL_MS` — a proof about a moment,
   not the identity), and never keeps `unresolved` (a statement about right-now connectivity).
5. **Nothing may drop a key.** One internal function publishes Drive Key events, and it throws
   `DriveKeyDroppedError` unless every already-known secret is in the event. Rotation moves the
   old active key into `previousKeys`; `healDriveKey` republishes the union when a relay's
   newest event is narrower than what is provably held (an earlier accidental mint).
6. **Reading never writes.** Only `mintDriveKey`, `rotateDriveKey` and `healDriveKey` publish.
   Signing is identity-signed and uses the shared `nextCreatedAt`, and must also beat the
   `created_at` of the event being replaced.

## What the proof is worth

`seenOn` in local-relay is documented as *"NOT an inventory of who has the event … usually ONE
relay (the source)"*. The control query asks for up to five events and unions the relays that
delivered each, so full coverage of a large relay set is a demanding test: it fails safe
(`unresolved`) far more often than it wrongly passes. That is the intended direction of error.
It is still only as good as `configuredRelays`: if the host lists fewer relays than its lookups
actually fan out to, the proof covers fewer relays than it should. Pass the real set.

Identity history is **never cached** here. The app caches `"new"` for the life of the page; a
stale `"new"` is precisely what would authorize a wrong mint.

## Consequences

- A host that cannot supply `configuredRelays` + `seenOn` never gets `empty-confirmed` and must
  decide itself (for example, by asking the user to confirm "I have never used Formstr Drive").
  That is a feature: the SDK will not guess.
- First-run latency is real: the lookup waits out the network settle window, then an existence
  query, then the control query.
- `mintDriveKey` throws on refusal rather than returning `null`, so `current ?? mint(...)` cannot
  be written by mistake.
