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
  const rec = await getDidRecord(identityEmail)
  if (!rec) return { ok: false, error: 'No DID for this identity' }
  // A relay-less identity (DID⊥relay) keeps its envelope locally — there is no
  // relay to fetch it from. A normal identity fetches it from its relay.
  let envelope = rec.envelope ?? null
  if (!envelope) {
    const { relaysFor } = await import('../context.ts')
    const existing = relaysFor(identityEmail)[0]
    if (!existing) return { ok: false, error: 'No connected session for this identity' }
    envelope = await fetchEnvelope(existing.account.serverUrl, existing.account.email)
  }
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

// Registers/confirms this identity's DID with an already-provisioned account's
// relay — DID.md's lazy migration, for identities that predate DID support.
//
//   PUT /account/did  { did, bind_ts, did_sig }   (Basic Auth)
//
// The proof is the point. Basic Auth only proves the caller owns *this account*,
// which says nothing about whether they own the DID they are naming: without a
// signature the relay would take any DID on the caller's word, and anyone with a
// self-service account could have the anchor bind a stranger's DID to their own
// address — and publish a DNS record saying so. So this signs the same statement
// provisionAccount does, over the same host, with the same root key. It lives
// here rather than in cryptenv.ts because that would import this layer back.
//
// Best-effort by design: the caller ignores failure (a relay in single-relay
// mode 204s trivially, a pre-DID relay 404s), so a rejected proof costs the DID
// registration, never the login.
export async function registerDid(serverUrl: string, email: string, authTokenB64: string, did: string, rootPrivateKey: Uint8Array): Promise<boolean> {
  const url = serverUrl.replace(/\/$/, '')
  // The localpart, matching what the relay derives from the credential and
  // passes to the anchor as the claim's name. Signing the full address instead
  // would produce a statement the anchor never reconstructs.
  const username = email.slice(0, email.lastIndexOf('@'))
  const proof = signBinding(rootPrivateKey, did, username, hostOf(url))
  try {
    const resp = await fetch(`${url}/account/did`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Basic ' + btoa(email + ':' + authTokenB64) },
      body: JSON.stringify({ did, bind_ts: proof.ts, did_sig: proof.sig }),
    })
    return resp.ok
  } catch { return false }
}
