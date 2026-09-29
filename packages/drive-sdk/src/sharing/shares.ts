import { bytesToHex, hexToBytes } from "nostr-tools/utils";
import { nextCreatedAt } from "../clock.js";
import { METADATA_KIND } from "../constants.js";
import { conversationKeyFromSecret } from "../crypto.js";
import { publishDeletionRequest } from "../deletion.js";
import { keyringEntries, type DriveKeyEntry } from "../drive-key.js";
import {
  FolderShareUnsupportedError,
  InvalidShareLinkError,
  LegacyChunkedFileError,
  ShareKeyMissingError,
  ShareNotFoundError,
} from "../errors.js";
import { buildEvent, decryptWithKeys, tagValue } from "../events.js";
import { readFileMetadata, type FileEntry } from "../file-entry.js";
import { keyringConversationKeys } from "../metadata.js";
import { buildCoordinate, decodePointer, decodeShareLink, encodeShareLink, parseCoordinate } from "./link.js";
import { collectEvents, fetchEventByCoordinate, mergeRelays, relaysFromPublish } from "./relay.js";
import type {
  ResolvedShare,
  ResolveShareContext,
  RevokedSharePayload,
  RevokeResult,
  ShareContext,
  ShareLinkPayload,
  ShareMember,
  ShareResult,
  ShareSource,
  SharedByMeEntry,
} from "./types.js";

// Sharing, ported from formstr-drive src/services/sharing/* at 0064bff. The app's version leans on
// four things this package does not have — metadataOutbox, getActiveDriveKey, the bootstrap
// LocalRelayClient, and hints.ts's global routing mutation. They are replaced by the injected store
// and keyring, and by local-relay >=0.6's per-observe `relays`; nothing here mutates shared state.

const SHARE_D_PREFIX = "s-"; // the shared-file event
const INFO_D_PREFIX = "si-"; // the owner's bookkeeping event

function shortId(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(4)));
}

/** Ephemeral pair per NIP-FS sharing: the conversation key is the secret paired with its OWN pubkey. */
function generateEphemeral(): { secretKeyHex: string; conversationKey: Uint8Array } {
  const secretKeyHex = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  return { secretKeyHex, conversationKey: conversationKeyFromSecret(secretKeyHex) };
}

// -----------------------------------------------------------------------------
// Bookkeeping ("Shared by me"): a `shared-container` event encrypted to the Drive Key. Despite the
// name (the spec's, not ours) it is written for file shares too — it is the one place that can
// enumerate "shares I've made", and the app's "Shared by me" list reads exactly this.
// -----------------------------------------------------------------------------

interface ShareInfoPayload {
  v: 1;
  kind: "file" | "folder";
  name: string;
  source: ShareSource;
  /** Container coordinate (folder) or the shared-file coordinate (file). */
  coordinate: string;
  /** Relays the coordinate's event actually landed on — rebuilds a working link from this record alone. */
  relays: string[];
  members: ShareMember[];
  encryptionKey: string;
  revokedAt?: number;
}

async function writeShareInfo(
  context: ShareContext,
  d: string,
  payload: Omit<ShareInfoPayload, "v">,
): Promise<void> {
  const active = context.keyring.active;
  const event = buildEvent({
    subtype: "shared-container",
    d,
    payload: { v: 1, ...payload } satisfies ShareInfoPayload,
    conversationKey: active.conversationKey,
    signingKey: hexToBytes(active.secretKeyHex),
    ...(context.client ? { client: context.client } : {}),
  });
  const result = await context.store.publishEvent(event);
  if (!result.ok) throw new Error("No relay accepted the share bookkeeping event");
}

function parseInfoEvent(
  event: { content: string; pubkey: string; created_at: number; tags: string[][] },
  keys: Uint8Array[],
  baseUrl?: string,
): SharedByMeEntry | null {
  const infoD = tagValue(event, "d");
  if (!infoD) return null;
  let parsed: Record<string, unknown>;
  try {
    const value = decryptWithKeys(event.content, keys);
    if (!value || typeof value !== "object") return null;
    parsed = value as Record<string, unknown>;
  } catch {
    return null; // encrypted to a key we do not hold
  }
  const { name, coordinate, encryptionKey, source } = parsed;
  if (typeof name !== "string" || typeof coordinate !== "string" || typeof encryptionKey !== "string" || !source || typeof source !== "object") return null;
  const kind: "file" | "folder" = parsed.kind === "folder" ? "folder" : "file";
  const relays = Array.isArray(parsed.relays) ? parsed.relays.filter((r): r is string => typeof r === "string") : [];
  let pointer: ReturnType<typeof parseCoordinate>;
  try {
    pointer = parseCoordinate(coordinate);
  } catch {
    return null;
  }
  let url: string;
  try {
    url = encodeShareLink({ pubkey: pointer.pubkey, d: pointer.d, relays, secretKeyHex: encryptionKey, ...(baseUrl ? { baseUrl } : {}) });
  } catch {
    return null; // not a usable share key
  }
  return {
    kind,
    name,
    source: source as ShareSource,
    sharedAtSeconds: event.created_at,
    url,
    infoD,
    infoCoordinate: buildCoordinate(event.pubkey, infoD),
    coordinate,
    relays,
    encryptionKey,
    members: kind === "folder" && Array.isArray(parsed.members) ? (parsed.members as ShareMember[]) : [],
    ...(typeof parsed.revokedAt === "number" ? { revokedAt: parsed.revokedAt } : {}),
  };
}

/**
 * Every share the user has made, newest first. Revoked shares stay listed (`revokedAt` set): a vanished
 * entry would be indistinguishable from a relay read failure, and it is the handle a caller needs to
 * retry a revoke. Bookkeeping events are addressable, so only the newest event per `d` counts.
 */
export async function listShares(context: ShareContext): Promise<SharedByMeEntry[]> {
  const events = await collectEvents(
    context.store,
    [{ kinds: [METADATA_KIND], authors: keyringEntries(context.keyring).map((k) => k.publicKey), "#t": ["shared-container"] }],
    { relays: context.relays, timeoutMs: context.timeoutMs, quietMs: context.quietMs },
  );
  const newest = new Map<string, (typeof events)[number]>();
  for (const event of events) {
    const d = tagValue(event, "d");
    if (!d) continue;
    const key = `${event.pubkey}:${d}`;
    const current = newest.get(key);
    if (!current || event.created_at > current.created_at || (event.created_at === current.created_at && event.id < current.id)) newest.set(key, event);
  }
  const keys = keyringConversationKeys(context.keyring);
  return [...newest.values()]
    .map((event) => parseInfoEvent(event, keys, context.baseUrl))
    .filter((entry): entry is SharedByMeEntry => entry !== null)
    .sort((a, b) => b.sharedAtSeconds - a.sharedAtSeconds);
}

// -----------------------------------------------------------------------------
// Creating
// -----------------------------------------------------------------------------

/** Always publishes a new share. Prefer {@link ensureFileShare}, which will not duplicate one. */
export async function createFileShare(file: FileEntry, context: ShareContext): Promise<ShareResult> {
  if (file.deleted) throw new Error("Cannot share a deleted file");
  // A recipient could not download a per-chunk file either — refuse before publishing anything.
  if (file.legacyChunked) throw new LegacyChunkedFileError(file.id);

  const active = context.keyring.active;
  const ephemeral = generateEphemeral();
  const d = `${SHARE_D_PREFIX}${shortId()}`;

  // The payload is the file's own decrypted JSON, so a share of an app-shaped file stays app-shaped
  // and a share of a spec-shaped one stays spec-shaped.
  const event = buildEvent({
    subtype: "shared-file",
    d,
    payload: file.raw,
    conversationKey: ephemeral.conversationKey,
    signingKey: hexToBytes(active.secretKeyHex),
    ...(context.client ? { client: context.client } : {}),
  });
  const result = await context.store.publishEvent(event, context.relays ? { relays: context.relays } : undefined);
  if (!result.ok) throw new Error("No relay accepted the shared file event");

  // Hints are the relays that accepted the event — never an assumed default set.
  const relays = relaysFromPublish(result);
  const coordinate = buildCoordinate(active.publicKey, d);
  const url = encodeShareLink({ pubkey: active.publicKey, d, relays, secretKeyHex: ephemeral.secretKeyHex, ...(context.baseUrl ? { baseUrl: context.baseUrl } : {}) });

  // The link already works without this; a failure is reported, not thrown, so the caller still gets the URL.
  let infoError: unknown;
  try {
    await writeShareInfo(context, `${INFO_D_PREFIX}${shortId()}`, {
      kind: "file",
      name: file.name,
      source: { type: "file", id: file.id },
      coordinate,
      relays,
      members: [],
      encryptionKey: ephemeral.secretKeyHex,
    });
  } catch (error) {
    infoError = error;
  }
  return { url, reused: false, coordinate, infoWritten: infoError === undefined, ...(infoError !== undefined ? { infoError } : {}) };
}

// One in-flight request per (drive key, file). Every caller that arrives while one is running awaits
// the same promise instead of each seeing "not shared yet" and publishing its own copy (a double
// click, a strict-mode double effect, two views of one file). The check-and-set has no `await`
// between them, so it is atomic against JS interleaving. Mirrors formstr-drive's dedupe.ts.
const inFlightShares = new Map<string, Promise<ShareResult>>();

/**
 * Idempotent: returns the file's live share link if the "Shared by me" bookkeeping already holds one,
 * otherwise creates it. `knownEntries` may be a list the host already loaded — pass it only once that
 * load has completed, since an unloaded empty list looks identical to "never shared" and would create
 * a duplicate.
 */
export function ensureFileShare(
  file: FileEntry,
  context: ShareContext,
  options: { knownEntries?: SharedByMeEntry[] } = {},
): Promise<ShareResult> {
  const key = `${context.keyring.active.publicKey}:file:${file.id}`;
  const running = inFlightShares.get(key);
  if (running) return running;

  const attempt = (async () => {
    const entries = options.knownEntries ?? (await listShares(context));
    const existing = entries.find((e) => !e.revokedAt && e.kind === "file" && e.source.type === "file" && e.source.id === file.id);
    if (existing) return { url: existing.url, reused: true, coordinate: existing.coordinate, infoWritten: true };
    return createFileShare(file, context);
  })();
  inFlightShares.set(key, attempt);
  void attempt.then(
    () => { if (inFlightShares.get(key) === attempt) inFlightShares.delete(key); },
    () => { if (inFlightShares.get(key) === attempt) inFlightShares.delete(key); },
  );
  return attempt;
}

// -----------------------------------------------------------------------------
// Resolving
// -----------------------------------------------------------------------------

function isRevokedPayload(value: unknown): value is RevokedSharePayload {
  return !!value && typeof value === "object" && (value as RevokedSharePayload).revoked === true;
}

/**
 * Resolves a share link back to file metadata. No signer or identity is needed — NIP-FS: "no signer
 * or identity is required to view or download a shared file". Accepts a link string or a decoded payload.
 *
 * File-versus-folder is read from the event's OWN `t` tag, not the link. A revoked marker is checked
 * on the plaintext tag BEFORE decrypting, so a revoked link renders as revoked even if the
 * re-encrypted payload were malformed.
 */
export async function resolveShare(link: string | ShareLinkPayload, context: ResolveShareContext): Promise<ResolvedShare> {
  const payload = typeof link === "string" ? decodeShareLink(link) : link;
  if (!payload) throw new InvalidShareLinkError("Malformed share link");
  const pointer = decodePointer(payload.naddr);
  if (!pointer) throw new InvalidShareLinkError("Share link does not point at a drive event");
  let conversationKey: Uint8Array;
  try {
    conversationKey = conversationKeyFromSecret(payload.k);
  } catch (error) {
    throw new InvalidShareLinkError("Share link has an invalid key", { cause: error });
  }

  const event = await fetchEventByCoordinate(context.store, pointer.kind, pointer.pubkey, pointer.d, {
    relays: mergeRelays(pointer.relays, context.relays),
    timeoutMs: context.timeoutMs,
    quietMs: context.quietMs,
  });
  if (!event) throw new ShareNotFoundError();

  const subtype = tagValue(event, "t");
  if (subtype === "container") throw new FolderShareUnsupportedError("resolve");
  if (subtype !== "shared-file") throw new InvalidShareLinkError(`Link points at a ${subtype ?? "untyped"} event, not a shared file`);

  if (event.tags.some((tag) => tag[0] === "revoked" && tag[1] === "1")) {
    return { kind: "revoked", target: "file", at: event.created_at };
  }

  let parsed: unknown;
  try {
    parsed = decryptWithKeys(event.content, conversationKey);
  } catch (error) {
    throw new InvalidShareLinkError("Could not decrypt this share: wrong key or corrupted event", { cause: error });
  }
  if (isRevokedPayload(parsed)) return { kind: "revoked", target: parsed.kind, at: parsed.at };

  // The share's d is `s-…`, not the file id. An app-shaped payload carries its own `id`; otherwise the share d.
  const id = typeof (parsed as { id?: unknown } | null)?.id === "string" ? (parsed as { id: string }).id : pointer.d;
  return { kind: "file", file: readFileMetadata(parsed, { id, author: event.pubkey, createdAt: event.created_at }) };
}

// -----------------------------------------------------------------------------
// Revoking
// -----------------------------------------------------------------------------

/**
 * Supersedes the share's coordinate so the link stops resolving: same `d`, same `t`, the same
 * ephemeral key (so it discloses nothing new and viewers see an authenticated "revoked" rather than a
 * generic decrypt failure), and a created_at strictly newer than whatever is published there so a
 * revoke in the same second as the share still wins the relay tie-break. It cannot un-disclose what a
 * recipient already fetched. Also sends a best-effort NIP-09 request for the share coordinate.
 *
 * The share coordinate's supersede must land or this throws; the bookkeeping update is reported.
 */
export async function revokeShare(entry: SharedByMeEntry, context: ShareContext): Promise<RevokeResult> {
  if (entry.kind === "folder") throw new FolderShareUnsupportedError("revoke");
  const { kind, pubkey, d } = parseCoordinate(entry.coordinate);
  const key: DriveKeyEntry | undefined = keyringEntries(context.keyring).find((k) => k.publicKey === pubkey);
  if (!key) throw new ShareKeyMissingError(pubkey);

  const original = await fetchEventByCoordinate(context.store, kind, pubkey, d, {
    relays: mergeRelays(entry.relays, context.relays),
    timeoutMs: context.timeoutMs,
    quietMs: context.quietMs,
  });
  const createdAt = original ? Math.max(nextCreatedAt(), original.created_at + 1) : nextCreatedAt();
  const at = Math.floor(Date.now() / 1000);

  const superseding = buildEvent({
    subtype: "shared-file",
    d,
    payload: { v: 1, revoked: true, at, kind: "file" } satisfies RevokedSharePayload,
    conversationKey: conversationKeyFromSecret(entry.encryptionKey),
    signingKey: hexToBytes(key.secretKeyHex),
    createdAt,
    extraTags: [["revoked", "1"]],
    ...(context.client ? { client: context.client } : {}),
  });
  const result = await context.store.publishEvent(superseding, { relays: mergeRelays(entry.relays, context.relays) });
  if (!result.ok) throw new Error("No relay accepted the revoking event");

  let infoError: unknown;
  try {
    await writeShareInfo(context, entry.infoD, {
      kind: entry.kind,
      name: entry.name,
      source: entry.source,
      coordinate: entry.coordinate,
      relays: entry.relays,
      members: entry.members,
      encryptionKey: entry.encryptionKey,
      revokedAt: at,
    });
  } catch (error) {
    infoError = error;
  }

  // Courtesy only, and only for the share coordinate: requesting deletion of the bookkeeping event
  // would, on relays that honor NIP-09 for addressable events, make the revoked entry vanish from the list.
  void publishDeletionRequest(context.store, key, [entry.coordinate], `Revoked share: ${entry.name}`);

  return { at, infoWritten: infoError === undefined, ...(infoError !== undefined ? { infoError } : {}) };
}
