// Self-resolution (DID.md "biset verse" follow-up): the account holder's own
// reconnection should follow their DID's current service list, exactly as
// discovery.ts already does for contacts — instead of trusting only the
// relay(s) explicitly requested at login. Without this, a relay added from
// another device (or via "Move to another relay…") stays invisible here until
// manually re-added: StoredAccount.serverUrl is a snapshot, never re-checked.
//
// Requires masterSecret (available right after a restore, to derive the root
// key) since connecting to a newly-discovered relay needs THIS device vouched
// there — a per-device credential (this session's account-model redesign,
// src/did/devicebind.ts), not a cached token.
import { resolveAny } from './resolver.ts'
import { firstServiceEndpoint } from '../utils.ts'
import { deriveRootKey } from './keys.ts'
import type { AccountSession } from '../types.ts'

export interface SyncResult { session: AccountSession; server: string }

// Resolves `did`'s current document and connects to any service not already
// among `alreadyConnected` (matched by host). Best-effort throughout: gateway
// failures and per-relay connect failures are swallowed — this only ever heals
// drift opportunistically, never blocks or fails the surrounding login flow.
export async function syncRelaysFromDid(
  did: string, email: string, masterSecret: Uint8Array, alreadyConnected: string[],
): Promise<SyncResult[]> {
  const doc = await resolveAny(did).catch(() => null)
  if (!doc) return []

  const known = new Set(alreadyConnected.map(u => u.replace(/\/$/, '')))
  const { initSession } = await import('../jmap/client.ts')
  const { vouchThisDevice, deviceLabel } = await import('./provision.ts')
  const rootPrivateKey = deriveRootKey(masterSecret).privateKey
  const label = deviceLabel()
  const out: SyncResult[] = []
  for (const svc of doc.service) {
    const server = firstServiceEndpoint(svc.serviceEndpoint).replace(/\/$/, '')
    if (!server || known.has(server)) continue
    known.add(server)
    const svcEmail = svc.address || email
    const at = svcEmail.lastIndexOf('@')
    if (at <= 0) continue
    await vouchThisDevice({ serverUrl: server, username: svcEmail.slice(0, at), domain: svcEmail.slice(at + 1), did, rootPrivateKey, label }).catch(() => {})
    const session = await initSession({ serverUrl: server, email: svcEmail, password: '', did }).catch(() => null)
    if (!session) continue
    session.account.did = did
    out.push({ session, server })
  }
  return out
}
