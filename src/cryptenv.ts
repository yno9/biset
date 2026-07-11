// Client-side counterpart of jmapsmtp's cryptenv (Go) package.
//
//   password ─Argon2id(salt)─> wrap_key
//   wrap_key ─AES-GCM-open──> master_secret (32B, server-stored wrapped)
//   master_secret ─HKDF("auth/v1")─> auth_token (sent to server)
//   master_secret ─HKDF("enc/v1") ─> KEK        (AES-GCM key for PGP privkey)

import { argon2id } from 'hash-wasm'

const HKDF_INFO_AUTH = 'biset-jmapsmtp/auth/v1'
const HKDF_INFO_KEK = 'biset-jmapsmtp/enc/v1'
const ENVELOPE_VERSION = 1

export interface KDFParams { t: number; m: number; p: number }
export interface Envelope {
  v: number
  salt: string
  kdf: KDFParams
  wrapped_secret: string
  auth_token_hash: string
}
// masterSecret is exposed alongside authToken/kek so callers can derive the
// DID identity (src/did/) — it's the same one-way root the HKDF diagram above
// already derives auth_token and kek from, not a new secret. Like kek, it is
// meant to be used immediately and then discarded, never persisted as-is.
export interface Unsealed { authToken: Uint8Array; kek: Uint8Array; masterSecret: Uint8Array }

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
  const authToken = await hkdfBytes(masterSecret, HKDF_INFO_AUTH, 32)
  const kek = await hkdfBytes(masterSecret, HKDF_INFO_KEK, 32)
  const authHash = await sha256(authToken)
  return {
    envelope: { v: ENVELOPE_VERSION, salt: b64(salt), kdf: DEFAULT_KDF, wrapped_secret: b64(wrapped), auth_token_hash: b64(authHash) },
    authToken, kek, masterSecret,
  }
}

export async function unsealEnvelope(env: Envelope, password: string): Promise<Unsealed> {
  if (env.v !== ENVELOPE_VERSION) throw new Error(`unsupported envelope version ${env.v}`)
  const wrapKey = await deriveWrapKey(password, b64d(env.salt), env.kdf)
  const masterSecret = await aesGcmOpen(wrapKey, b64d(env.wrapped_secret))
  const authToken = await hkdfBytes(masterSecret, HKDF_INFO_AUTH, 32)
  const kek = await hkdfBytes(masterSecret, HKDF_INFO_KEK, 32)
  return { authToken, kek, masterSecret }
}

export async function rewrapEnvelope(env: Envelope, oldPw: string, newPw: string): Promise<Envelope> {
  const masterSecret = await aesGcmOpen(await deriveWrapKey(oldPw, b64d(env.salt), env.kdf), b64d(env.wrapped_secret))
  const newSalt = rnd(16)
  const wrapped = await aesGcmSeal(await deriveWrapKey(newPw, newSalt, DEFAULT_KDF), masterSecret)
  const authToken = await hkdfBytes(masterSecret, HKDF_INFO_AUTH, 32)
  const authHash = await sha256(authToken)
  return { v: ENVELOPE_VERSION, salt: b64(newSalt), kdf: DEFAULT_KDF, wrapped_secret: b64(wrapped), auth_token_hash: b64(authHash) }
}

export function authTokenToBasicAuth(authToken: Uint8Array): string {
  return b64(authToken)
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

// Registers/confirms this identity's DID with the relay's anchor (DID.md's
// lazy migration — see src/did/). Best-effort: a relay in single-relay mode
// (no anchor configured) 204s trivially; a stale/pre-DID relay 404s and the
// caller just ignores it.
export async function putDid(serverUrl: string, email: string, authTokenB64: string, did: string): Promise<boolean> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/account/did`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Basic ' + btoa(email + ':' + authTokenB64) },
      body: JSON.stringify({ did }),
    })
    return resp.ok
  } catch { return false }
}

export async function loginViaEnvelope(serverUrl: string, email: string, password: string): Promise<Unsealed | null> {
  const env = await fetchEnvelope(serverUrl, email)
  if (!env) return null
  try { return await unsealEnvelope(env, password) } catch { return null }
}
