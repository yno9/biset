import type { AccountSession } from '../types.ts'
import { sync } from './session.ts'

export async function start(sessions: AccountSession[]): Promise<void> {
  await Promise.allSettled(sessions.map(sync))
}

export function stop(): void {}

export { sync } from './session.ts'
