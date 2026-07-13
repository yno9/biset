// Self-resolution (DID.md "biset verse" follow-up): the account holder's own
// reconnection should follow their DID's current service list, exactly as
// discovery.ts already does for contacts — instead of trusting only the
// relay(s) explicitly requested at login. Without this, a relay added from
// another device (or via "Move to another relay…") stays invisible here until
// manually re-added: StoredAccount.serverUrl is a snapshot, never re-checked.
//
// Requires masterSecret (available right after a password unseal or restore),
// since connecting to a newly-discovered host needs a fresh relay-scoped token
// — there is no way to derive one from a cached token alone.
import { resolve, PUBLIC_PKARR_FALLBACKS } from './resolver.ts'
import { relayAuth } from '../cryptenv.ts'
import type { AccountSession } from '../types.ts'

export interface SyncResult { session: AccountSession; server: string; token: string }

// Resolves `did`'s current document and connects to any service not already
// among `alreadyConnected` (matched by host). Best-effort throughout: gateway
// failures and per-relay connect failures are swallowed — this only ever heals
// drift opportunistically, never blocks or fails the surrounding login flow.
export async function syncRelaysFromDid(
  did: string, email: string, masterSecret: Uint8Array, alreadyConnected: string[],
): Promise<SyncResult[]> {
  const gateways = [...new Set([
    ...alreadyConnected.map(u => u.replace(/\/$/, '') + '/pkarr'),
    ...PUBLIC_PKARR_FALLBACKS,
  ])]
  const doc = await resolve(did, gateways).catch(() => null)
  if (!doc) return []

  const known = new Set(alreadyConnected.map(u => u.replace(/\/$/, '')))
  const { initSession } = await import('../jmap/client.ts')
  const out: SyncResult[] = []
  for (const svc of doc.service) {
    const server = svc.serviceEndpoint[0]?.replace(/\/$/, '')
    if (!server || known.has(server)) continue
    known.add(server)
    const svcEmail = svc.address || email
    const { password } = await relayAuth(masterSecret, server)
    const session = await initSession({ serverUrl: server, email: svcEmail, password, did }).catch(() => null)
    if (!session) continue
    session.account.did = did
    out.push({ session, server, token: password })
  }
  return out
}
