import * as openpgp from 'openpgp'
import type { IdentityId } from '../protocol/ids.ts'
import type { OpenPgpPrivateCredentialV1 } from '../vault/openpgp-credential.ts'

export interface GenerateOpenPgpCredentialOptions {
  identityId: IdentityId
  userIDs: Array<{ name?: string; email?: string }>
  createdAt: string
  supersedesFingerprint?: string
}

/** Public representation suitable for a DID binding, WKD, or Autocrypt adapter. */
export interface OpenPgpPublicKeyPublicationV1 {
  version: 1
  identityId: IdentityId
  fingerprint: string
  armoredPublicKey: string
  createdAt: string
  supersedesFingerprint?: string
}

/**
 * Endpoint-only OpenPGP key generation. The generated private packet is
 * returned for immediate vault encryption; this module never contacts core or
 * any mail relay.
 */
export async function generateOpenPgpPrivateCredential(options: GenerateOpenPgpCredentialOptions): Promise<OpenPgpPrivateCredentialV1> {
  if (!options.identityId || options.userIDs.length === 0 || Number.isNaN(Date.parse(options.createdAt))) throw new TypeError('OpenPGP credential generation options are invalid')
  // openpgp.js v6 names the interoperable RFC 9580 transition curve
  // `ed25519Legacy`; do not reuse a DID/MLS key for this mail identity.
  const generated = await openpgp.generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: options.userIDs })
  const key = await openpgp.readPrivateKey({ armoredKey: generated.privateKey })
  return {
    version: 1,
    kind: 'credential.openpgp.private',
    identityId: options.identityId,
    fingerprint: key.getFingerprint().toUpperCase(),
    privateKey: new TextEncoder().encode(generated.privateKey),
    createdAt: options.createdAt,
    ...(options.supersedesFingerprint === undefined ? {} : { supersedesFingerprint: options.supersedesFingerprint }),
  }
}

/** Parses a vault-decoded credential and rejects a substituted key packet. */
export async function readOpenPgpPrivateCredential(credential: OpenPgpPrivateCredentialV1): Promise<openpgp.PrivateKey> {
  let armoredKey: string
  try { armoredKey = new TextDecoder('utf-8', { fatal: true }).decode(credential.privateKey) } catch { throw new TypeError('OpenPGP credential private key is not UTF-8 armor') }
  let key: openpgp.PrivateKey
  try { key = await openpgp.readPrivateKey({ armoredKey }) } catch { throw new TypeError('OpenPGP credential private key packet is invalid') }
  if (key.getFingerprint().toUpperCase() !== credential.fingerprint.toUpperCase()) throw new TypeError('OpenPGP credential fingerprint does not match private key')
  return key
}

/**
 * Derives only the public OpenPGP certificate from a verified credential.
 * Transport adapters may publish this result, but must never retain or return
 * `credential.privateKey`.
 */
export async function publishableOpenPgpPublicKey(credential: OpenPgpPrivateCredentialV1): Promise<OpenPgpPublicKeyPublicationV1> {
  const privateKey = await readOpenPgpPrivateCredential(credential)
  const publicKey = privateKey.toPublic()
  const fingerprint = publicKey.getFingerprint().toUpperCase()
  if (fingerprint !== credential.fingerprint.toUpperCase()) throw new TypeError('OpenPGP public key fingerprint does not match credential')
  return {
    version: 1,
    identityId: credential.identityId,
    fingerprint,
    armoredPublicKey: publicKey.armor(),
    createdAt: credential.createdAt,
    ...(credential.supersedesFingerprint === undefined ? {} : { supersedesFingerprint: credential.supersedesFingerprint.toUpperCase() }),
  }
}
