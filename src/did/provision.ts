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
import { relayAuth, hostOf, type Envelope } from '../cryptenv.ts'
import { signBinding } from './binding.ts'

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
