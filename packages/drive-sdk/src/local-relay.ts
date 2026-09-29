/**
 * `@formstr/drive-sdk/local-relay` — the optional `@formstr/local-relay` adapter.
 *
 * The core API is the structural `FileEventStore` contract, so nothing here is required: a host that
 * already holds a local-relay `dataLayer` can hand it to any function taking a `store`. This entry
 * exists so that hand-off is type-checked against local-relay >=0.6 (per-observe `relays`,
 * `publishEvent(event, { relays })`, `seenOn`), and so a class-based DataLayer keeps its `this`.
 * Kept out of the main entry so importing the SDK never pulls in the optional peer; it imports no
 * runtime code from local-relay either.
 *
 * ```ts
 * import { dataLayer } from "@formstr/local-relay";
 * import { localRelayStore } from "@formstr/drive-sdk/local-relay";
 *
 * const store = localRelayStore(dataLayer);
 * ```
 */
import type { Event, Filter } from "nostr-tools";
import type { FileEventStore, FilePublishResult } from "./types.js";

/** The slice of local-relay's `DataLayer` this package uses — structural, so no import. */
export interface LocalRelayDataLayer {
  observe(
    filters: Filter[],
    handlers: { onEvent: (event: Event) => void; onEose?: () => void },
    options?: { localOnly?: boolean; relays?: string[] },
  ): { unobserve: () => void };
  publishEvent(event: Event, options?: { relays?: string[] }): Promise<FilePublishResult>;
  seenOn?(eventId: string): Promise<string[]>;
}

export function localRelayStore(dataLayer: LocalRelayDataLayer): FileEventStore {
  const store: FileEventStore = {
    observe: (filters, handlers, options) => dataLayer.observe(filters, handlers, options),
    publishEvent: (event, options) => dataLayer.publishEvent(event, options),
  };
  if (dataLayer.seenOn) store.seenOn = (eventId) => dataLayer.seenOn!(eventId);
  return store;
}
