import { describe, expect, it } from "vitest";
import { MAX_CREATED_AT_DRIFT_SECONDS, nextCreatedAt } from "../src/index.js";

describe("nextCreatedAt", () => {
  it("is strictly increasing within one second, up to the drift clamp", () => {
    const now = 4_000_000_000;
    let previous = nextCreatedAt(now);
    expect(previous).toBeGreaterThanOrEqual(now);
    for (let i = 0; i < MAX_CREATED_AT_DRIFT_SECONDS; i += 1) {
      const next = nextCreatedAt(now);
      expect(next).toBeGreaterThan(previous);
      previous = next;
    }
  });

  it("never exceeds now+60 over 1000 calls and never goes backwards", () => {
    const now = 4_100_000_000;
    let previous = 0;
    for (let i = 0; i < 1000; i += 1) {
      const stamp = nextCreatedAt(now);
      expect(stamp).toBeLessThanOrEqual(now + MAX_CREATED_AT_DRIFT_SECONDS);
      expect(stamp).toBeGreaterThanOrEqual(previous);
      previous = stamp;
    }
    // Past the clamp the stamp holds at now+60: monotonic, no longer strictly increasing (see clock.ts).
    expect(nextCreatedAt(now)).toBe(now + MAX_CREATED_AT_DRIFT_SECONDS);
  });

  it("stays strictly increasing for 1000 calls when publishes are no faster than the clock", () => {
    let now = 4_200_000_000;
    let previous = nextCreatedAt(now);
    for (let i = 0; i < 1000; i += 1) {
      if (i % 20 !== 0) now += 1; // ~1 publish per second: the clock keeps pace, drift stays bounded
      const stamp = nextCreatedAt(now);
      expect(stamp).toBeGreaterThan(previous);
      expect(stamp).toBeLessThanOrEqual(now + MAX_CREATED_AT_DRIFT_SECONDS);
      previous = stamp;
    }
  });

  it("uses the wall clock by default and catches up when the wall clock jumps ahead", () => {
    const wall = Math.floor(Date.now() / 1000);
    expect(nextCreatedAt()).toBeGreaterThanOrEqual(wall);
    expect(nextCreatedAt(4_300_000_000)).toBe(4_300_000_000);
  });
});
