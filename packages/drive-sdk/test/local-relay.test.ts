import { describe, expect, it, vi } from "vitest";
import { localRelayStore, type LocalRelayDataLayer } from "../src/local-relay.js";
import { okResult } from "./helpers.js";

class ClassDataLayer implements LocalRelayDataLayer {
  calls: string[] = [];
  observe(_filters: unknown[], handlers: { onEvent: (e: never) => void; onEose?: () => void }, options?: { relays?: string[] }) {
    this.calls.push(`observe:${options?.relays?.join(",") ?? ""}`);
    handlers.onEose?.();
    return { unobserve: () => { this.calls.push("unobserve"); } };
  }
  async publishEvent(_event: unknown, options?: { relays?: string[] }) {
    this.calls.push(`publish:${options?.relays?.join(",") ?? ""}`);
    return okResult("wss://a");
  }
}

describe("localRelayStore", () => {
  it("keeps `this` for class-based data layers and forwards per-call relays", async () => {
    const layer = new ClassDataLayer();
    const store = localRelayStore(layer as never);
    const onEose = vi.fn();
    store.observe([], { onEvent: () => {}, onEose }, { relays: ["wss://x"] }).unobserve();
    await store.publishEvent({} as never, { relays: ["wss://y"] });
    expect(layer.calls).toEqual(["observe:wss://x", "unobserve", "publish:wss://y"]);
    expect(onEose).toHaveBeenCalled();
    expect(store.seenOn).toBeUndefined();
  });

  it("exposes seenOn only when the data layer has it", async () => {
    const layer = Object.assign(new ClassDataLayer(), { seenOn: vi.fn(async () => ["wss://a"]) });
    const store = localRelayStore(layer as never);
    await expect(store.seenOn!("id")).resolves.toEqual(["wss://a"]);
  });
});
