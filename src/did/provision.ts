// Unified account provisioning (DID.md third-party portability; per-device
// credential since this session's account-model redesign). One request
// shape for own and third-party relays:
//
//   POST /account/provision
//   { username, did, bind_ts, did_sig,
//     device_pub_key, device_label, device_vouch_ts, device_vouch_sig,
//     envelope? }
//
// - did_sig proves DID control (root-key signature) → relay records localpart→did
// - device_vouch_sig establishes THIS device's own login credential, atomically
//   with the account itself — no more auth_token_hash, no masterSecret-derived
//   password at any point (devicebind.ts's file header has the full rationale;
//   go-jmapap/go-jmapsmtp provision.go verify it the same way devices.go's
//   POST /account/devices does, did:dht locally / others via the anchor)
// - envelope (wrapped master secret) is sent ONLY to trusted own relays — a
//   third-party relay never receives offline-crackable recovery material, and
//   it's unrelated to login now anyway (masterSecret recovery convenience only)
//
// Nothing secret leaves: the relay gets a public DID, two signatures, and
// (own relays only) the already-public wrapped envelope. There is nothing
// for the relay to hand back afterward — this device already holds its own
// private key — so a successful provision returns no credential at all.
import { hostOf, fetchEnvelope, unsealEnvelope, type Envelope } from '../cryptenv.ts'
import { signBinding } from './binding.ts'
import { generateDeviceKey, signVouch, signSessionLogin } from './devicebind.ts'
import { getDidRecord, storeDidRecord, withDidLock } from './store.ts'
import { hexToBytes } from '../utils.ts'
import { scidToLocalpart } from './webvh/scid-localpart.ts'

const bytesToHex = (b: Uint8Array): string => [...b].map(x => x.toString(16).padStart(2, '0')).join('')

// Best-effort device label for a fresh vouch — a UI nicety (shown in the
// Devices modal), never security-relevant (devicebind.ts's statement never
// trusts the label for anything but display). Exported so every vouch call
// site (this file's own provisionAccount, restore.ts, sync.ts) uses the
// same label instead of each computing its own.
export function deviceLabel(): string {
  try { return (navigator as any).userAgentData?.platform || navigator.platform || 'Browser' }
  catch { return 'Browser' }
}

/** The address this device should authenticate AS at a relay, for a
 * `publishedAddress` learned from somewhere that only ever carries the
 * human-facing alias (a resolved DID document's `service.address`/
 * `alsoKnownAs`, this session's `svcEmail`) — never the relay's own
 * `/account/provision` response, which already returns the right thing
 * directly (PLANSCID.md).
 *
 * A SCID-primary account's login identity is the DID's permanent SCID
 * segment's z-base-32 projection, computed straight from the DID string —
 * never from what the document happens to be advertising, which is the delivery ALIAS
 * (PLANSCID.md's whole point: the alias can be renamed freely without ever
 * touching the account it points at). Falls back to `publishedAddress`'s own
 * localpart when the DID doesn't read as biset's own did:webvh shape (a
 * different method, an apex DID, a foreign convention) — those never went
 * through SCID-primary provisioning in the first place, so their published
 * address already IS their login identity, same as before this existed.
 *
 * The DOMAIN half always comes from `publishedAddress`, never the DID's own
 * domain segment — a relay can serve mail for an identity whose DID lives
 * elsewhere entirely, and the two are not required to match. */
export async function scidLoginAddress(did: string, publishedAddress: string): Promise<{ email: string; username: string; domain: string } | null> {
  const at = publishedAddress.lastIndexOf('@')
  if (at <= 0) return null
  const domain = publishedAddress.slice(at + 1)
  let username = publishedAddress.slice(0, at)
  try {
    const { parseWebvhDid } = await import('./webvh/identifier.ts')
    const parsed = parseWebvhDid(did)
    // The relay's permanent account localpart is not the base58 SCID made
    // lowercase. It is a z-base-32 encoding of the SCID bytes. Using the old
    // lowercase form makes a restore vouch and then log into a non-existent
    // account, leaving only the DID record behind with no StoredAccount.
    const scidLocalpart = scidToLocalpart(parsed.scid)
    if (scidLocalpart) username = scidLocalpart
  } catch { /* not a biset-shaped did:webvh — publishedAddress's own localpart already is the login identity */ }
  return { email: `${username}@${domain}`, username, domain }
}

export interface ProvisionParams {
  serverUrl: string
  username: string
  did: string
  rootPrivateKey: Uint8Array
  envelope?: Envelope // include only for trusted own relays
  domain?: string // target domain (routing); default = the relay's open domain
  provisionSecret?: string // required for gated (privileged) domains
}

export interface ProvisionResult {
  ok: boolean
  status: number
  email?: string
  conflict?: boolean
  // Present only when `did` was sent. false on a relay with no anchor
  // configured: the account was still created (plain JMAP), the DID just
  // wasn't bound/claimed there — the relay says so rather than refusing the
  // whole provision (go-jmapsmtp/go-jmapap provision.go).
  didBound?: boolean
  // The relay's own refusal text on failure (jmapsmtp's provision.rs's
  // Refusal::message()) — plain text, not JSON, so the old body-as-JSON
  // parse silently discarded it on every failure and left callers with
  // nothing but a status code. `conflict` alone can't distinguish jmapsmtp's
  // TWO different 409 causes (UsernameTaken vs. IdentityOwnedByAnother —
  // "this account already exists, log in instead" vs. a genuine identity
  // conflict), which is exactly the distinction that mattered live,
  // 2026-08-17: a UI showing "owned by a different key" for both sent
  // someone hunting for a key mismatch that was never there.
  error?: string
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
// envelope (its own DidRecord keeps one now regardless of relay —
// account-create.ts — falling back to fetching one from a connected relay
// for an identity that predates that), rather than building a brand new one.
// Not identity creation — this only ever operates on an identity that
// already has a local DID record; callers needing a fresh identity use
// buildEnvelope()+initDid() instead (see account-create.ts's #new flow).
export async function unsealCurrentIdentity(
  identityDid: string, password: string,
): Promise<{ ok: true; identity: UnsealedIdentity } | { ok: false; error: string }> {
  const rec = await getDidRecord(identityDid)
  if (!rec) return { ok: false, error: 'No DID for this identity' }
  let envelope = rec.envelope ?? null
  if (!envelope) {
    const { relaysForId } = await import('../context.ts')
    const existing = relaysForId(identityDid)[0]
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
  const bindProof = signBinding(p.rootPrivateKey, p.did, p.username, host)
  const device = await ensureJmapDeviceKey(p.did)
  const vouchProof = signVouch(p.rootPrivateKey, p.did, device.publicKey, deviceLabel())
  const body = {
    username: p.username,
    did: p.did,
    bind_ts: bindProof.ts,
    did_sig: bindProof.sig,
    device_pub_key: vouchProof.devicePubKey,
    device_label: vouchProof.label,
    device_vouch_ts: vouchProof.ts,
    device_vouch_sig: vouchProof.sig,
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
    let didBound: boolean | undefined
    let error: string | undefined
    const raw = await resp.text().catch(() => '')
    if (resp.ok) {
      try {
        const j = JSON.parse(raw) as { email?: string; did_bound?: boolean }
        email = j.email
        didBound = j.did_bound
      } catch { /* no body */ }
    } else {
      error = raw.trim() || undefined
    }
    return { ok: resp.ok, status: resp.status, email, conflict: resp.status === 409, didBound, error }
  } catch {
    return { ok: false, status: 0 }
  }
}

// ── per-device JMAP credential (this session's account-model redesign) ─────
//
// Two operations, mirroring devicebind.ts's own split:
//   - vouchThisDevice: root-key-signed, one-time, DID-touching (the relay
//     forwards it to the anchor — src/anchor/server.ts's /devices/vouch).
//   - deviceSessionLogin: device-key-signed, routine, never touches DID
//     material — this is what makes ordinary login immune to a later
//     root-key rotation (devicebind.ts's file header has the full rationale).
//
// Both are additive: go-jmapap/go-jmapsmtp's authenticate() still accepts the
// legacy masterSecret-derived password too, so nothing here is required for
// an existing account to keep working — see jmap/client.ts's initSession,
// which tries this first and falls back to the stored password untouched.

/** This device's own JMAP signing key for `did`, minted once and persisted —
 * mirrors didcomm-devices.ts's ensureDeviceKey (random, never derived from
 * the seed; see devicebind.ts's file header for why a shared key would break
 * per-device revocation). */
async function ensureJmapDeviceKey(did: string): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  // Locked (store.ts's withDidLock, its own note names exactly this class of
  // bug) — this used to be a bare read-modify-write, racing any OTHER
  // read-modify-write on the same DidRecord (chiefly restore.ts's fire-and-
  // forget registerWithMediator, which runs concurrently with THIS call
  // during restore and is itself lock-protected, but that protects nothing
  // if the OTHER side of the race isn't holding the same lock). Found live
  // (2026-07-27): registerWithMediator's network-bound flow (webvh publish +
  // mediate-request, several round trips) reads a DidRecord snapshot from
  // BEFORE this function's write, then writes it back AFTER — silently
  // erasing the jmapDevicePrivateKey/PublicKey this function had just
  // minted and persisted moments earlier. The device key used to sign the
  // vouch (still in memory, `kp`) stayed valid and the vouch itself
  // genuinely succeeded — but the NEXT read of the DidRecord (deviceSessionLogin,
  // moments later) found no jmapDevicePrivateKey at all, returned null, and
  // initSession logged "device session login failed (never vouched here, or
  // revoked)" — a false diagnosis, since the device WAS vouched; the local
  // record just lost the key that proved it. This is why retrying
  // connectAndPersist (even with a long backoff) never helped: no amount of
  // waiting fixes a key that isn't there any more, only vouching again does
  // — which is also why a second, fully separate restore attempt "worked".
  return withDidLock(did, async () => {
    const rec = await getDidRecord(did)
    if (!rec) throw new Error('ensureJmapDeviceKey: no local DID record for ' + did)
    if (rec.jmapDevicePublicKey && rec.jmapDevicePrivateKey) {
      return { publicKey: hexToBytes(rec.jmapDevicePublicKey), privateKey: hexToBytes(rec.jmapDevicePrivateKey) }
    }
    const kp = generateDeviceKey()
    rec.jmapDevicePublicKey = bytesToHex(kp.publicKey)
    rec.jmapDevicePrivateKey = bytesToHex(kp.privateKey)
    await storeDidRecord(rec)
    return kp
  })
}

export interface VouchDeviceParams {
  serverUrl: string
  username: string
  domain: string // the address domain provisionAccount created the account under
  did: string
  rootPrivateKey: Uint8Array
  label: string
}

/** Registers THIS device as authorized to log into `serverUrl` for `did` —
 * the per-device model's one DID-touching step. Requires the account already
 * exist there (a prior provisionAccount); best-effort by design, same as
 * every other identity-layer side effect in account-create.ts — a failure
 * here still leaves a perfectly usable account behind (the legacy password
 * keeps working), it just can't ALSO use the new per-device login yet. */
export async function vouchThisDevice(p: VouchDeviceParams): Promise<{ ok: boolean; status: number }> {
  const device = await ensureJmapDeviceKey(p.did)
  const proof = signVouch(p.rootPrivateKey, p.did, device.publicKey, p.label)
  try {
    const resp = await fetch(`${p.serverUrl.replace(/\/$/, '')}/account/devices`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: p.username, domain: p.domain, did: p.did,
        device_pub_key: proof.devicePubKey, label: proof.label, bind_ts: proof.ts, sig: proof.sig,
      }),
    })
    return { ok: resp.ok, status: resp.status }
  } catch {
    return { ok: false, status: 0 }
  }
}

/** Logs THIS device into `serverUrl` with its own signing key — no password,
 * no masterSecret, and (devicebind.ts's file header) unaffected by any later
 * root-key rotation, since the relay checks purely against the device pubkey
 * it already has on file. `null` whenever this device has no key yet (never
 * vouched) or the relay doesn't recognize it (never vouched THERE, or
 * revoked) — callers fall back to the account's stored password, which the
 * relay still accepts unconditionally (auth_env.go's authenticate).
 *
 * Two round trips, not one (SPEC.md §11.28): first a `GET /account/session/
 * challenge` for a single-use nonce, then the signed `POST /account/session`
 * that spends it. The nonce closes what `relayHost` alone left open — a
 * captured-and-replayed POST of the identical signed statement against the
 * SAME relay, inside the freshness window `ts` alone would still accept. */
export async function deviceSessionLogin(serverUrl: string, username: string, domain: string, did: string): Promise<string | null> {
  const rec = await getDidRecord(did)
  if (!rec?.jmapDevicePrivateKey) return null
  const base = serverUrl.replace(/\/$/, '')
  try {
    const challengeResp = await fetch(`${base}/account/session/challenge`)
    if (!challengeResp.ok) return null
    const { nonce } = (await challengeResp.json()) as { nonce?: string }
    if (!nonce) return null

    const proof = signSessionLogin(hexToBytes(rec.jmapDevicePrivateKey), did, hostOf(serverUrl), nonce)
    const resp = await fetch(`${base}/account/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, domain, did, device_pub_key: proof.devicePubKey, host: proof.relayHost, nonce: proof.nonce, ts: proof.ts, sig: proof.sig }),
    })
    if (!resp.ok) return null
    const j = (await resp.json()) as { token?: string }
    return j.token ?? null
  } catch {
    return null
  }
}
