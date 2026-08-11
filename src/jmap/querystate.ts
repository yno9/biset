import { vaultHandle } from '../context.ts'
import { readJson, writeJson } from '../vault/fs.ts'
import * as idb from '../store/idb.ts'

export interface QueryState {
  emailQueryState?: string | null
  emailState?: string | null
  threadState?: string | null
  mailboxState?: string | null
  submissionState?: string | null
  submissionQueryState?: string | null
}

type AllQueryStates = Record<string, QueryState>

const PATH = ['.data', 'querystate.json']

let cache: AllQueryStates = {}

export async function loadFromVault(): Promise<void> {
  if (!vaultHandle) return
  try {
    cache = await readJson(PATH) as AllQueryStates
  } catch {
    cache = {}
  }
}

// Browser-local (IndexedDB) load — always runs at startup, independent of the
// vault, so a plain refresh has the previous sync cursor available and
// sync/session.ts does a delta sync instead of refetching full history.
export async function loadFromIDB(): Promise<void> {
  try {
    const rows = await idb.getAll(idb.STORES.querystate) as (QueryState & { acctKey: string })[]
    for (const row of rows) {
      const { acctKey, ...state } = row
      cache[acctKey] = state
    }
  } catch (e) { console.warn('[querystate] loadFromIDB failed', e) }
}

export function get(user: string): QueryState {
  return cache[user] ?? {}
}

export async function save(user: string, state: QueryState): Promise<void> {
  cache[user] = { ...cache[user], ...state }
  try { await idb.put(idb.STORES.querystate, { acctKey: user, ...cache[user] }) } catch { /* best-effort */ }
  if (!vaultHandle) return
  await writeJson(PATH, cache)
}
