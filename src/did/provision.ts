// Unified account provisioning (DID.md third-party portability). One request
// shape for own and third-party relays:
//
//   POST /account/provision
//   { username, did, bind_ts, did_sig, auth_token_hash, envelope? }
//
// - did_sig proves DID control (root-key signature) → relay records localpart→did
// - auth_token_hash lets the relay verify future scoped-token logins
// - envelope (wrapped master secret) is sent ONLY to trusted own relays — a
//   third-party relay never receives offline-crackable recovery material.
//
// Nothing secret leaves: the relay gets a public DID, a signature, a token HASH,
// and (own relays only) the already-public wrapped envelope.
import { relayAuth, hostOf, fetchEnvelope, unsealEnvelope, type Envelope } from '../cryptenv.ts'
import { signBinding } from './binding.ts'
import { getDidRecord } from './store.ts'
import { hexToBytes } from '../utils.ts'

export interface ProvisionParams {
  serverUrl: string
  username: string
  did: string
  rootPrivateKey: Uint8Array
  masterSecret: Uint8Array
  envelope?: Envelope // include only for trusted own relays
  domain?: string // target domain (routing); default = the relay's open domain
  provisionSecret?: string // required for gated (privileged) domains
}

export interface ProvisionResult {
  ok: boolean
  status: number
  email?: string
  password?: string // base64 scoped auth token, for the follow-up login
  conflict?: boolean
}

export interface UnsealedIdentity {
  did: string
  rootPrivateKey: Uint8Array
  masterSecret: Uint8Array
  kek: Uint8Array
  envelope: Envelope
}

// Recovers the CURRENTLY LOGGED IN identity's DID + master secret via
// password — the common first step behind "add a relay/address to me"
// (whether the target is an arbitrary relay URL or a BYO domain on biset's
// own relay; see ARC.md 2026-07-14): unseal that identity's EXISTING
// envelope (fetched from one of its already-connected sessions), rather than
// building a brand new one. Not identity creation — this only ever operates
// on an identity that already has a connected session and a local DID
// record; callers needing a fresh identity use buildEnvelope()+initDid()
// instead (see account-create.ts's #new flow).
export async function unsealCurrentIdentity(
  identityEmail: string, password: string,
): Promise<{ ok: true; identity: UnsealedIdentity } | { ok: false; error: string }> {
  const { relaysFor } = await import('../context.ts')
  const existing = relaysFor(identityEmail)[0]
  if (!existing) return { ok: false, error: 'No connected session for this identity' }
  const rec = await getDidRecord(identityEmail)
  if (!rec) return { ok: false, error: 'No DID for this identity' }
  const envelope = await fetchEnvelope(existing.account.serverUrl, existing.account.email)
  if (!envelope) return { ok: false, error: 'Could not read the account envelope' }
  try {
    const unsealed = await unsealEnvelope(envelope, password)
    return {
      ok: true,
      identity: {
        did: rec.did, rootPrivateKey: hexToBytes(rec.rootPrivateKey),
        masterSecret: unsealed.masterSecret, kek: unsealed.kek, envelope,
      },
    }
  } catch {
    return { ok: false, error: 'Incorrect password' }
  }
}

export async function provisionAccount(p: ProvisionParams): Promise<ProvisionResult> {
  const url = p.serverUrl.replace(/\/$/, '')
  const host = hostOf(url)
  const { password, hash } = await relayAuth(p.masterSecret, url)
  const proof = signBinding(p.rootPrivateKey, p.did, p.username, host)
  const body = {
    username: p.username,
    did: p.did,
    bind_ts: proof.ts,
    did_sig: proof.sig,
    auth_token_hash: hash,
    ...(p.domain ? { domain: p.domain } : {}),
    ...(p.provisionSecret ? { provision_secret: p.provisionSecret } : {}),
    ...(p.envelope ? { envelope: p.envelope } : {}),
  }
  try {
    const resp = await fetch(`${url}/account/provision`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    let email: string | undefined
    try { email = ((await resp.json()) as { email?: string }).email } catch { /* no body */ }
    return { ok: resp.ok, status: resp.status, email, password, conflict: resp.status === 409 }
  } catch {
    return { ok: false, status: 0 }
  }
}
