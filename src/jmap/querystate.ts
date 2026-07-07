import { vaultHandle } from '../context.ts'
import { readJson, writeJson } from '../vault/fs.ts'

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

export function get(user: string): QueryState {
  return cache[user] ?? {}
}

export async function save(user: string, state: QueryState): Promise<void> {
  cache[user] = { ...cache[user], ...state }
  if (!vaultHandle) return
  await writeJson(PATH, cache)
}
