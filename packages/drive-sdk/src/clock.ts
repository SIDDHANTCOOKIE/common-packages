/**
 * The one `created_at` clock for every addressable (replaceable) publish this
 * package makes — Drive Key, file/folder metadata, shares, share bookkeeping.
 *
 * Relays break equal-timestamp ties on a replaceable event by lowest id, so two
 * publishes at one coordinate inside the same second (share, then immediately
 * revoke; rename, then rename again) are a coin flip on which one wins. Each
 * stamp is therefore strictly greater than the previous one while that is
 * possible.
 *
 * It is also clamped to MAX_DRIFT_SECONDS ahead of the wall clock (formstr-drive
 * PR #71 review). A burst of publishes would otherwise bake a far-future
 * timestamp into signed events, and a future-dated event wins the replaceable
 * tiebreak against another device's legitimate real-time edit — its rename or
 * revoke silently loses until the wall clock catches up. The consequence: past
 * MAX_DRIFT_SECONDS + 1 stamps inside one second the value holds at now+60
 * (non-decreasing, no longer strictly increasing). That trade is deliberate.
 */
export const MAX_CREATED_AT_DRIFT_SECONDS = 60;

let lastStamp = 0;

/** `nowSeconds` is injectable for tests; production callers omit it. */
export function nextCreatedAt(nowSeconds: number = Math.floor(Date.now() / 1000)): number {
  lastStamp = Math.max(nowSeconds, Math.min(lastStamp + 1, nowSeconds + MAX_CREATED_AT_DRIFT_SECONDS));
  return lastStamp;
}
