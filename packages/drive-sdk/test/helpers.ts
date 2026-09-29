import { finalizeEvent, getPublicKey, matchFilter, nip44, type Event, type EventTemplate, type Filter } from "nostr-tools";
import { bytesToHex } from "nostr-tools/utils";
import type { FileEventStore, FilePublishResult, IdentitySigner } from "../src/index.js";

/** A real identity signer (real NIP-44, real Schnorr) so tests exercise the actual crypto. */
export function makeIdentity(seed = 1): IdentitySigner & { pubkey: string; secretHex: string } {
  const secret = new Uint8Array(32).fill(seed);
  const pubkey = getPublicKey(secret);
  return {
    pubkey,
    secretHex: bytesToHex(secret),
    getPublicKey: async () => pubkey,
    signEvent: async (template: EventTemplate) => finalizeEvent(template, secret),
    nip44Encrypt: async (peer, plaintext) => nip44.v2.encrypt(plaintext, nip44.v2.utils.getConversationKey(secret, peer)),
    nip44Decrypt: async (peer, ciphertext) => nip44.v2.decrypt(ciphertext, nip44.v2.utils.getConversationKey(secret, peer)),
  };
}

export function okResult(...relays: string[]): FilePublishResult {
  const list = relays.length > 0 ? relays : ["wss://relay.one"];
  return {
    ok: true,
    accepted: list.length,
    total: list.length,
    relayResults: list.map((relay) => ({ relay, status: "accepted" })),
  };
}

export interface Observation {
  filters: Filter[];
  options?: { localOnly?: boolean; relays?: string[] };
  unobserved: boolean;
}

export interface FakeRelayOptions {
  /** Never EOSE and never deliver anything — a dead network. */
  silent?: boolean;
  publishResult?: FilePublishResult | (() => FilePublishResult);
  seenOn?: (eventId: string) => string[];
}

/**
 * In-memory stand-in for local-relay: replays stored events then EOSEs (the "local cache" replay),
 * and delivers `arrivals` after the EOSE like an upstream relay would.
 */
export class FakeRelay implements FileEventStore {
  readonly events = new Map<string, Event>();
  readonly published: Array<{ event: Event; relays?: string[] }> = [];
  readonly observations: Observation[] = [];
  /** Events that show up only after the local replay's EOSE, i.e. from the network. */
  arrivals: Event[] = [];
  private live: Array<{ filters: Filter[]; onEvent(e: Event): void; obs: Observation }> = [];
  seenOn?: (eventId: string) => Promise<string[]>;

  constructor(private readonly options: FakeRelayOptions = {}) {
    if (options.seenOn) {
      const fn = options.seenOn;
      this.seenOn = async (id) => fn(id);
    }
  }

  add(...events: Event[]): this {
    for (const event of events) this.events.set(event.id, event);
    return this;
  }

  observe(
    filters: Filter[],
    handlers: { onEvent(event: Event): void; onEose?(): void },
    options?: { localOnly?: boolean; relays?: string[] },
  ): { unobserve(): void } {
    const obs: Observation = { filters, options, unobserved: false };
    this.observations.push(obs);
    if (this.options.silent) return { unobserve: () => { obs.unobserved = true; } };
    const matches = (e: Event) => filters.some((f) => matchFilter(f, e));
    const entry = { filters, onEvent: (e: Event) => { if (!obs.unobserved && matches(e)) handlers.onEvent(e); }, obs };
    this.live.push(entry);
    queueMicrotask(() => {
      if (obs.unobserved) return;
      for (const e of this.events.values()) entry.onEvent(e);
      handlers.onEose?.();
      if (!options?.localOnly) {
        for (const e of this.arrivals) entry.onEvent(e);
      }
    });
    return { unobserve: () => { obs.unobserved = true; } };
  }

  async publishEvent(event: Event, options?: { relays?: string[] }): Promise<FilePublishResult> {
    this.published.push({ event, relays: options?.relays });
    const result = typeof this.options.publishResult === "function"
      ? this.options.publishResult()
      : this.options.publishResult ?? okResult();
    if (result.ok) {
      this.events.set(event.id, event);
      for (const l of this.live) l.onEvent(event);
    }
    return result;
  }

  get publishedEvents(): Event[] {
    return this.published.map((p) => p.event);
  }
}

/** Resolves once the microtask queue and any zero-delay timers have drained. */
export const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

export function eventBy(secret: Uint8Array, template: EventTemplate): Event {
  return finalizeEvent(template, secret);
}
