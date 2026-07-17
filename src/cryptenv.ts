// Client-side counterpart of jmapsmtp's cryptenv (Go) package.
//
//   password ─Argon2id(salt)─> wrap_key
//   wrap_key ─AES-GCM-open──> master_secret (32B, server-stored wrapped)
//   master_secret ─HKDF("auth/v1")─> auth_token (sent to server)
//   master_secret ─HKDF("enc/v1") ─> KEK        (AES-GCM key for PGP privkey)

import { argon2id } from 'hash-wasm'

// Auth tokens are RELAY-SCOPED: HKDF info = "auth/v1/<relay-host>", so the token
// you present to one relay is useless at another (a hostile relay can't replay
// it). Still fully seed-derived, so recovery-phrase login re-derives each relay's
// token from the master secret (the relay list comes from the DID document).
const HKDF_INFO_AUTH_PREFIX = 'biset-jmapsmtp/auth/v1/'
const HKDF_INFO_KEK = 'biset-jmapsmtp/enc/v1'
const ENVELOPE_VERSION = 2 // v2: recovery-only (no auth_token_hash; tokens are per-relay, stored relay-side)

export interface KDFParams { t: number; m: number; p: number }
// The envelope is now RECOVERY MATERIAL ONLY — the password-wrapped master
// secret. The per-relay auth_token_hash lives relay-side (sent at provision),
// not here, so the envelope stays identical across an identity's relays and is
// only ever stored on relays the user trusts with their (offline-crackable)
// wrapped secret.
export interface Envelope {
  v: number
  salt: string
  kdf: KDFParams
  wrapped_secret: string
}
// masterSecret is exposed so callers can derive the DID identity (src/did/) AND
// per-relay auth tokens. Like kek, use immediately then discard; never persist.
export interface Unsealed { kek: Uint8Array; masterSecret: Uint8Array }

const DEFAULT_KDF: KDFParams = { t: 3, m: 64 * 1024, p: 4 }

function rnd(n: number): Uint8Array { return crypto.getRandomValues(new Uint8Array(n)) }

function b64(buf: ArrayBuffer | Uint8Array): string {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let s = ''; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i])
  return btoa(s)
}

function b64d(s: string): Uint8Array {
  const bin = atob(s); const u = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i)
  return u
}

async function deriveWrapKey(pw: string, salt: Uint8Array, kdf: KDFParams): Promise<Uint8Array> {
  return (await argon2id({
    password: pw, salt, iterations: kdf.t, memorySize: kdf.m,
    parallelism: kdf.p, hashLength: 32, outputType: 'binary',
  })) as Uint8Array
}

async function hkdfBytes(secret: Uint8Array, info: string, len: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', secret as BufferSource, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(info) },
    key, len * 8,
  )
  return new Uint8Array(bits)
}

const ab = (u: Uint8Array): ArrayBuffer => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer

async function aesGcmSeal(key: Uint8Array, pt: Uint8Array): Promise<Uint8Array> {
  const ck = await crypto.subtle.importKey('raw', ab(key), 'AES-GCM', false, ['encrypt'])
  const nonce = rnd(12)
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ab(nonce) }, ck, ab(pt)))
  const out = new Uint8Array(nonce.length + ct.length)
  out.set(nonce, 0); out.set(ct, nonce.length)
  return out
}

async function aesGcmOpen(key: Uint8Array, sealed: Uint8Array): Promise<Uint8Array> {
  if (sealed.length < 12) throw new Error('sealed too short')
  const ck = await crypto.subtle.importKey('raw', ab(key), 'AES-GCM', false, ['decrypt'])
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ab(sealed.slice(0, 12)) }, ck, ab(sealed.slice(12)),
  ))
}

async function sha256(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', b as BufferSource))
}

export async function buildEnvelope(password: string): Promise<{ envelope: Envelope } & Unsealed> {
  const salt = rnd(16)
  const masterSecret = rnd(32)
  const wrapKey = await deriveWrapKey(password, salt, DEFAULT_KDF)
  const wrapped = await aesGcmSeal(wrapKey, masterSecret)
  const kek = await hkdfBytes(masterSecret, HKDF_INFO_KEK, 32)
  return {
    envelope: { v: ENVELOPE_VERSION, salt: b64(salt), kdf: DEFAULT_KDF, wrapped_secret: b64(wrapped) },
    kek, masterSecret,
  }
}

export async function unsealEnvelope(env: Envelope, password: string): Promise<Unsealed> {
  if (env.v !== ENVELOPE_VERSION) throw new Error(`unsupported envelope version ${env.v}`)
  const wrapKey = await deriveWrapKey(password, b64d(env.salt), env.kdf)
  const masterSecret = await aesGcmOpen(wrapKey, b64d(env.wrapped_secret))
  const kek = await hkdfBytes(masterSecret, HKDF_INFO_KEK, 32)
  return { kek, masterSecret }
}

export async function rewrapEnvelope(env: Envelope, oldPw: string, newPw: string): Promise<Envelope> {
  const masterSecret = await aesGcmOpen(await deriveWrapKey(oldPw, b64d(env.salt), env.kdf), b64d(env.wrapped_secret))
  const newSalt = rnd(16)
  const wrapped = await aesGcmSeal(await deriveWrapKey(newPw, newSalt, DEFAULT_KDF), masterSecret)
  return { v: ENVELOPE_VERSION, salt: b64(newSalt), kdf: DEFAULT_KDF, wrapped_secret: b64(wrapped) }
}

// The relay host an auth token is scoped to (hostname of the relay's base URL).
export function hostOf(serverUrl: string): string {
  try { return new URL(serverUrl).host } catch { return serverUrl.replace(/^https?:\/\//, '').replace(/\/.*$/, '') }
}

// Per-relay auth token: HKDF(masterSecret, "auth/v1/<host>"). Present base64(this)
// as the JMAP password to the relay `host`.
export async function deriveAuthToken(masterSecret: Uint8Array, host: string): Promise<Uint8Array> {
  return hkdfBytes(masterSecret, HKDF_INFO_AUTH_PREFIX + host, 32)
}

export async function deriveKek(masterSecret: Uint8Array): Promise<Uint8Array> {
  return hkdfBytes(masterSecret, HKDF_INFO_KEK, 32)
}

export function authTokenToBasicAuth(authToken: Uint8Array): string {
  return b64(authToken)
}

// base64(SHA-256(token)) — sent to the relay at provision so it can verify future
// logins (the relay stores this per account; the token itself never leaves as a
// stored secret, only its hash).
export async function authTokenHashB64(authToken: Uint8Array): Promise<string> {
  return b64(await sha256(authToken))
}

// Convenience for a relay login/provision: unseal (or take masterSecret) → the
// scoped token for `serverUrl` + its hash + the kek.
export async function relayAuth(masterSecret: Uint8Array, serverUrl: string): Promise<{ token: Uint8Array; password: string; hash: string; kek: Uint8Array }> {
  const token = await deriveAuthToken(masterSecret, hostOf(serverUrl))
  return { token, password: b64(token), hash: await authTokenHashB64(token), kek: await deriveKek(masterSecret) }
}

function trim(url: string): string { return url.replace(/\/$/, '') }

export async function fetchEnvelope(serverUrl: string, email: string): Promise<Envelope | null> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/auth/envelope?email=${encodeURIComponent(email)}`)
    return resp.ok ? (await resp.json()) as Envelope : null
  } catch { return null }
}

export async function putEnvelope(serverUrl: string, email: string, authTokenB64: string, env: Envelope): Promise<boolean> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/auth/envelope`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Basic ' + btoa(email + ':' + authTokenB64) },
      body: JSON.stringify(env),
    })
    return resp.ok
  } catch { return false }
}

// Registering a DID with a relay's anchor lives in src/did/provision.ts
// (registerDid), not here: it has to sign a binding proof with the root key,
// and this module is a dependency of that layer rather than the other way
// round. It used to live here and sent the DID unproven.

// Permanently deletes the account's data ON THIS RELAY (messages, mailbox,
// envelope — see go-jmapsmtp/go-jmapap's /account/delete). Distinct from
// forgetting local credentials (left-pane.ts's "Log out") — this actually
// destroys server-side data and cannot be undone. `did`, if known, lets the
// relay drop this address from that DID's local index too; harmless to omit
// (the server derives which account to delete purely from the Basic Auth
// credential, never from anything in the body).
export async function deleteAccountOnRelay(serverUrl: string, email: string, authTokenB64: string, did?: string): Promise<boolean> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/account/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Basic ' + btoa(email + ':' + authTokenB64) },
      body: JSON.stringify(did ? { did } : {}),
    })
    return resp.ok
  } catch { return false }
}

// "How your data is stored" (biset issue #7) — GET/export/purge over the
// account's own on-disk data, see go-jmapserver's storage.go.
export interface StorageEntry { name: string; type: 'file' | 'dir'; count?: number; sizeBytes: number }

export async function fetchAccountStorage(serverUrl: string, email: string, authTokenB64: string): Promise<{ entries: StorageEntry[]; totalSizeBytes: number } | null> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/account/storage`, {
      headers: { 'Authorization': 'Basic ' + btoa(email + ':' + authTokenB64) },
    })
    return resp.ok ? (await resp.json()) as { entries: StorageEntry[]; totalSizeBytes: number } : null
  } catch { return null }
}

// Drill-down into the summarized "messages" entry from fetchAccountStorage —
// the individual files inside messages/.
export async function fetchMessageFiles(serverUrl: string, email: string, authTokenB64: string): Promise<StorageEntry[] | null> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/account/storage/messages`, {
      headers: { 'Authorization': 'Basic ' + btoa(email + ':' + authTokenB64) },
    })
    return resp.ok ? ((await resp.json()) as { files: StorageEntry[] }).files : null
  } catch { return null }
}

export async function exportAccountStorage(serverUrl: string, email: string, authTokenB64: string): Promise<{ email: string; files: Record<string, string> } | null> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/account/storage/export`, {
      headers: { 'Authorization': 'Basic ' + btoa(email + ':' + authTokenB64) },
    })
    return resp.ok ? (await resp.json()) as { email: string; files: Record<string, string> } : null
  } catch { return null }
}

// Purges ONLY messages/ on this relay (see storage.go) — distinct from
// deleteAccountOnRelay, which destroys the whole account. Returns the number
// of messages removed, or null on failure.
export async function purgeAccountMessages(serverUrl: string, email: string, authTokenB64: string): Promise<number | null> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/account/storage/purge-messages`, {
      method: 'POST',
      headers: { 'Authorization': 'Basic ' + btoa(email + ':' + authTokenB64) },
    })
    if (!resp.ok) return null
    return ((await resp.json()) as { purged: number }).purged
  } catch { return null }
}

export async function loginViaEnvelope(serverUrl: string, email: string, password: string): Promise<Unsealed | null> {
  const env = await fetchEnvelope(serverUrl, email)
  if (!env) return null
  try { return await unsealEnvelope(env, password) } catch { return null }
}
