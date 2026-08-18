import type { Identity } from 'jmap-rfc-types'

// Same partitioning problem messages.ts already solved: a single flat list
// overwritten wholesale on every account's sync pass meant a multi-account
// setup only ever showed whichever account synced last — a display-name
// change on one account would appear to silently "not persist" the moment
// any OTHER account's sync ran afterward and clobbered the shared list.
// Keyed by account (context.ts's accountKey), like messages.ts/threads.ts.
const store = new Map<string, Identity[]>()

// Every identity across every account, or just one account's own.
export function all(account?: string): Identity[] {
  if (account !== undefined) return store.get(account) ?? []
  return [...store.values()].flat()
}

export function set(account: string, list: Identity[]): void {
  store.set(account, list)
}

export function clear(): void {
  store.clear()
}

// Persistence stamps each identity with the account it belongs to (mirrors
// messages.ts's `_account`), so a flat array on disk still round-trips into
// the right per-account bucket on load.
export function toStamped(): (Identity & { _account: string })[] {
  return [...store.entries()].flatMap(([account, list]) =>
    list.map(i => ({ ...i, _account: account })))
}

export function loadStamped(stamped: (Identity & { _account?: string })[]): void {
  store.clear()
  for (const { _account, ...identity } of stamped) {
    if (!_account) continue
    const list = store.get(_account) ?? []
    list.push(identity as Identity)
    store.set(_account, list)
  }
}
