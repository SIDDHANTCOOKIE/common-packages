import type { Event, Filter } from "nostr-tools";
import type { FileEventStore, FilePublishResult } from "../types.js";

/**
 * The relays a publish actually landed on — the honest source for a share's relay hints, as opposed
 * to assuming a default set (the assumption that makes links resolve for the sender and nobody else).
 * Only "accepted" counts: a relay that rejected, timed out or failed is not somewhere the event can
 * be found.
 */
export function relaysFromPublish(result: FilePublishResult): string[] {
  return Array.from(new Set(result.relayResults.filter((r) => r.status === "accepted").map((r) => r.relay)));
}

export interface CollectOptions {
  /** Per-call read hints (local-relay >=0.6 `observe({ relays })`) — no global routing is touched. */
  relays?: string[];
  timeoutMs?: number;
  quietMs?: number;
}

const DEFAULT_TIMEOUT_MS = 8_000;
const DEFAULT_QUIET_MS = 1_200;

/**
 * Collects every event matching `filters`, settling once results look complete or `timeoutMs` passes.
 *
 * EOSE is a checkpoint, not a terminator: local-relay fires it after replaying its own store, which
 * on a cold cache is empty while the network answer streams in afterwards. So this waits for the
 * first event (or the timeout), then for `quietMs` of silence — long enough that a NEWER version of a
 * replaceable coordinate (a revoke, a republish) from a slower relay beats the first one to arrive.
 * Never rejects: an unresponsive relay is a normal outcome, callers get what arrived.
 */
export function collectEvents(store: FileEventStore, filters: Filter[], options: CollectOptions = {}): Promise<Event[]> {
  return new Promise((resolve) => {
    const found = new Map<string, Event>();
    let quietTimer: ReturnType<typeof setTimeout> | undefined;
    let settled = false;
    let handle: { unobserve(): void } | undefined;

    const settle = () => {
      if (settled) return;
      settled = true;
      clearTimeout(quietTimer);
      clearTimeout(deadline);
      handle?.unobserve();
      resolve([...found.values()]);
    };
    const bump = () => {
      clearTimeout(quietTimer);
      quietTimer = setTimeout(settle, options.quietMs ?? DEFAULT_QUIET_MS);
    };
    const deadline = setTimeout(settle, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

    handle = store.observe(
      filters,
      {
        onEvent(event) {
          if (found.has(event.id)) return;
          found.set(event.id, event);
          bump();
        },
        onEose() {
          if (found.size > 0 && quietTimer === undefined) bump();
        },
      },
      options.relays && options.relays.length > 0 ? { relays: options.relays } : undefined,
    );
    if (settled) handle.unobserve();
  });
}

/** Newest event at a coordinate (ties: lowest id, as relays keep), or null. */
export async function fetchEventByCoordinate(
  store: FileEventStore,
  kind: number,
  pubkey: string,
  d: string,
  options: CollectOptions = {},
): Promise<Event | null> {
  const events = await collectEvents(store, [{ kinds: [kind], authors: [pubkey], "#d": [d] }], options);
  return events.reduce<Event | null>((latest, event) => {
    if (!latest) return event;
    if (event.created_at !== latest.created_at) return event.created_at > latest.created_at ? event : latest;
    return event.id < latest.id ? event : latest;
  }, null);
}

export function mergeRelays(...lists: Array<readonly string[] | undefined>): string[] {
  return Array.from(new Set(lists.flatMap((list) => list ?? [])));
}
