import type { AccountSession } from '../types.ts'
import { isDidCommRelay } from '../context.ts'
import { sync } from './session.ts'

export async function start(sessions: AccountSession[]): Promise<void> {
  // DIDComm sessions have no real jmapClient (did/didcomm/channel.ts) — sync()
  // unconditionally speaks JMAP, so it would throw on one. They have their own
  // poll loop (startDidCommPolling, wired from ui/shell.ts).
  await Promise.allSettled(sessions.filter(s => !isDidCommRelay(s.account.serverUrl)).map(sync))
}

export function stop(): void {}

export { sync } from './session.ts'
