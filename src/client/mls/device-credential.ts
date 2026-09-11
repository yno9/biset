import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base58 } from '@scure/base'
import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes } from '../../protocol/canonical.ts'

export interface CredentialLike { credentialType: string }

/** Root-authorized binding between one identity and one MLS leaf signing
 * key. It lives inside the MLS BasicCredential; it is not published as a DID
 * verificationMethod and therefore does not turn the DID document into a
 * device roster. */
export interface MlsDeviceCredentialV2 {
  version: 2 | 3
  identityId: string
  generation: string
  deviceKid: string
  signaturePublicKey: Uint8Array
  rootSignature: Uint8Array
  signSignature: Uint8Array
  audience?: string
  subject?: string
  issuedAt?: string
  expiresAt?: string
}

const KID_BYTES = 16

export function mlsDeviceKid(identityId: string, signaturePublicKey: Uint8Array): string {
  if (!identityId.startsWith('did:') || signaturePublicKey.length !== 32) throw new TypeError('MLS device identity/key is invalid')
  return `${identityId}#device-${base58.encode(sha256(signaturePublicKey).slice(0, KID_BYTES))}`
}

function mlsDeviceCredentialSigningBytes(value: Omit<MlsDeviceCredentialV2, 'rootSignature' | 'signSignature'>): Uint8Array {
  if (value.version === 3) return canonicalBytes({
    label: 'did.md/key-authorization/v1', type: 'did.md/KeyAuthorizationCredential', version: 1,
    issuer: value.identityId, audience: value.audience!, subject: value.subject!, generation: value.generation,
    publicKey: { type: 'Multikey', publicKeyMultibase: encodeEd25519Multikey(value.signaturePublicKey) },
    purposes: ['signing'], issuedAt: value.issuedAt!, expiresAt: value.expiresAt!,
  })
  return canonicalBytes({
    label: 'biset/mls-device-credential/v2', version: value.version,
    identityId: value.identityId, generation: value.generation, deviceKid: value.deviceKid,
    signaturePublicKey: bytesToBase64url(value.signaturePublicKey),
  })
}

export function createMlsDeviceCredential(
  identityId: string,
  generation: string,
  signaturePublicKey: Uint8Array,
  rootPrivateKey: Uint8Array,
  signPrivateKey: Uint8Array,
): MlsDeviceCredentialV2 {
  const unsigned = { version: 2 as const, identityId, generation, deviceKid: mlsDeviceKid(identityId, signaturePublicKey), signaturePublicKey: signaturePublicKey.slice() }
  const bytes = mlsDeviceCredentialSigningBytes(unsigned)
  return { ...unsigned, rootSignature: ed25519.sign(bytes, rootPrivateKey), signSignature: ed25519.sign(bytes, signPrivateKey) }
}

export function encodeMlsDeviceCredential(value: MlsDeviceCredentialV2): Uint8Array {
  assertMlsDeviceCredential(value)
  return canonicalBytes({
    version: 2, identityId: value.identityId, generation: value.generation, deviceKid: value.deviceKid,
    signaturePublicKey: bytesToBase64url(value.signaturePublicKey),
    rootSignature: bytesToBase64url(value.rootSignature),
    signSignature: bytesToBase64url(value.signSignature),
    ...(value.version === 3 ? { version: 3, audience: value.audience, subject: value.subject, issuedAt: value.issuedAt, expiresAt: value.expiresAt } : {}),
  })
}

export function decodeMlsDeviceCredential(bytes: Uint8Array): MlsDeviceCredentialV2 {
  let parsed: unknown
  try { parsed = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new TypeError('MLS device credential is not JSON') }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new TypeError('MLS device credential must be an object')
  const input = parsed as Record<string, unknown>
  const keys = Object.keys(input).sort()
  const v2Keys = ['deviceKid', 'generation', 'identityId', 'rootSignature', 'signSignature', 'signaturePublicKey', 'version']
  const v3Keys = [...v2Keys, 'audience', 'subject', 'issuedAt', 'expiresAt']
  if (keys.join(',') !== (input.version === 3 ? v3Keys : v2Keys).sort().join(',')) throw new TypeError('MLS device credential has unexpected fields')
  if ((input.version !== 2 && input.version !== 3) || typeof input.identityId !== 'string' || typeof input.generation !== 'string' || typeof input.deviceKid !== 'string' || typeof input.signaturePublicKey !== 'string' || typeof input.rootSignature !== 'string' || typeof input.signSignature !== 'string') throw new TypeError('MLS device credential fields are invalid')
  const value: MlsDeviceCredentialV2 = {
    version: input.version, identityId: input.identityId, generation: input.generation, deviceKid: input.deviceKid,
    signaturePublicKey: base64urlToBytes(input.signaturePublicKey), rootSignature: base64urlToBytes(input.rootSignature), signSignature: base64urlToBytes(input.signSignature),
    ...(input.version === 3 ? { audience: String(input.audience), subject: String(input.subject), issuedAt: String(input.issuedAt), expiresAt: String(input.expiresAt) } : {}),
  }
  assertMlsDeviceCredential(value)
  if (!equalBytes(bytes, encodeMlsDeviceCredential(value))) throw new TypeError('MLS device credential is not canonical')
  return value
}

export function credentialForMlsDevice(value: MlsDeviceCredentialV2): { credentialType: 'basic'; identity: Uint8Array } {
  return { credentialType: 'basic', identity: encodeMlsDeviceCredential(value) }
}

export function mlsDeviceCredentialOf(credential: CredentialLike): MlsDeviceCredentialV2 {
  if (credential.credentialType !== 'basic') throw new TypeError(`unsupported MLS credential type ${credential.credentialType}`)
  const identity = (credential as CredentialLike & { identity?: unknown }).identity
  if (!(identity instanceof Uint8Array)) throw new TypeError('MLS BasicCredential has no identity bytes')
  return decodeMlsDeviceCredential(identity)
}

export function verifyMlsDeviceCredential(
  value: MlsDeviceCredentialV2,
  signPublicKey: Uint8Array,
  expectedLeafPublicKey: Uint8Array = value.signaturePublicKey,
): boolean {
  try {
    assertMlsDeviceCredential(value)
    return signPublicKey.length === 32
      && equalBytes(value.signaturePublicKey, expectedLeafPublicKey)
      && ed25519.verify(value.signSignature, mlsDeviceCredentialSigningBytes(value), signPublicKey)
  } catch {
    return false
  }
}

/** Stable Root verification. MLS admission additionally resolves the full
 * DID log and checks the Sign signature against the recorded generation. */
export function verifyMlsDeviceCredentialRoot(
  value: MlsDeviceCredentialV2,
  rootPublicKey: Uint8Array,
  expectedLeafPublicKey: Uint8Array = value.signaturePublicKey,
): boolean {
  try {
    assertMlsDeviceCredential(value)
    return rootPublicKey.length === 32 && equalBytes(value.signaturePublicKey, expectedLeafPublicKey)
      && ed25519.verify(value.rootSignature, mlsDeviceCredentialSigningBytes(value), rootPublicKey)
  } catch { return false }
}

function assertMlsDeviceCredential(value: MlsDeviceCredentialV2): void {
  if ((value.version !== 2 && value.version !== 3) || !value.identityId.startsWith('did:') || !/^[1-9][0-9]*-[A-Za-z0-9_-]{20,200}$/.test(value.generation) || value.signaturePublicKey.length !== 32 || value.rootSignature.length !== 64 || value.signSignature.length !== 64) throw new TypeError('MLS device credential is invalid')
  if (value.version === 3 && (!value.audience || !/^urn:uuid:[0-9a-f-]{36}$/i.test(value.subject ?? '') || !Number.isFinite(Date.parse(value.issuedAt ?? '')) || Date.parse(value.expiresAt ?? '') <= Date.parse(value.issuedAt ?? ''))) throw new TypeError('MLS key authorization credential is invalid')
  if (value.deviceKid !== mlsDeviceKid(value.identityId, value.signaturePublicKey)) throw new TypeError('MLS device kid does not match its leaf key')
}

function encodeEd25519Multikey(key: Uint8Array): string {
  const prefixed = new Uint8Array(34); prefixed.set([0xed, 0x01]); prefixed.set(key, 2)
  return `z${base58.encode(prefixed)}`
}

export function mlsCredentialFromKeyAuthorization(value: {
  issuer: string; audience: string; subject: string; generation: string; signaturePublicKey: Uint8Array;
  issuedAt: string; expiresAt: string; rootSignature: Uint8Array; signSignature: Uint8Array;
}): MlsDeviceCredentialV2 {
  const result: MlsDeviceCredentialV2 = { version: 3, identityId: value.issuer, generation: value.generation,
    deviceKid: mlsDeviceKid(value.issuer, value.signaturePublicKey), signaturePublicKey: value.signaturePublicKey,
    rootSignature: value.rootSignature, signSignature: value.signSignature, audience: value.audience,
    subject: value.subject, issuedAt: value.issuedAt, expiresAt: value.expiresAt }
  assertMlsDeviceCredential(result)
  return result
}
