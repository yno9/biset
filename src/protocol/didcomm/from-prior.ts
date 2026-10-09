// DID Rotation's `from_prior` header (DIDComm Messaging v2.1, "DID Rotation"):
// a compact JWS, `iss` the DID being rotated away from, `sub` the new DID,
// signed by a key the prior DID's document authorizes. biset reads
// "authorizes" as DIDComm's convention for signing keys: referenced from
// `authentication` (PLAN-refactor.md §7-7).
//
// Official implementations check little of this on unpack (didcomm-rust and
// -python only that the kid is in `authentication`; neither compares `iss` or
// `sub`), so a receiver here checks all of it (PLAN-refactor.md §4.4):
//   1. `typ` is JWT, `alg` one DIDComm v2.1 requires verifying (EdDSA, ES256,
//      ES256K: jws.ts);
//   2. the `kid` is a DID URL of `iss`;
//   3. `iss`'s document lists `kid` under `authentication`, as a key of that
//      algorithm, and the signature verifies -- and, for a did:webvh `iss`, no
//      log entry after the one that published the key removed a device key
//      (§7-2: a device removed from the Wallet itself left the key in place,
//      and the removed device may hold what it signs with);
//   4. `sub` is the message's `from`, and differs from `iss`;
//   5. (the message itself is authcrypted by `sub`'s key: the caller's check)
//   6. `exp` and `nbf` are honoured when present.
import { ed25519 } from '@noble/curves/ed25519.js'
import { b64url, b64urlToBytes } from './crypto.ts'
import { authenticationMethodOf, authenticationSigningKey, JWS_ALGORITHMS, SignatureError, verifyJwsSignature, type JwsAlgorithm, type SigningKey } from './jws.ts'
import { parseLog, type LogEntry } from '../webvh/log.ts'
import { resolveEntries } from '../webvh/resolver.ts'
import { didToHttpsUrl } from '../webvh/identifier.ts'
import { resolveDidWeb } from './did-web.ts'
import { decodePeerDid2 } from './peer.ts'

export interface FromPriorClaims {
  iss: string
  sub: string
  iat: number
  exp?: number
  nbf?: number
}

/** A verified rotation: `sub` now speaks for `iss`. */
export interface DidRotation { prior: string; current: string; kid: string; iat: number }

/** Why a `from_prior` was refused. Never a network failure: retrying the same
 * header against the same documents gives the same answer. */
export class FromPriorError extends Error {
  constructor(message: string) {
    super(`from_prior: ${message}`)
    this.name = 'FromPriorError'
  }
}

const encodeJson = (value: unknown) => b64url(new TextEncoder().encode(JSON.stringify(value)))

/** Signs a rotation from `iss` to `sub` with the Ed25519 key `kid` of `iss`. */
export function createFromPrior(claims: { iss: string; sub: string; iat?: number }, kid: string, privateKey: Uint8Array): string {
  if (claims.iss === claims.sub) throw new TypeError('from_prior: iss and sub must differ')
  if (kid.split('#', 1)[0] !== claims.iss || !kid.includes('#')) throw new TypeError('from_prior: kid must be a DID URL of iss')
  const header = encodeJson({ typ: 'JWT', alg: 'EdDSA', crv: 'Ed25519', kid })
  const payload = encodeJson({ iss: claims.iss, sub: claims.sub, iat: claims.iat ?? Math.floor(Date.now() / 1000) })
  const signature = ed25519.sign(new TextEncoder().encode(`${header}.${payload}`), privateKey)
  return `${header}.${payload}.${b64url(signature)}`
}

interface Parsed { kid: string; alg: JwsAlgorithm; claims: FromPriorClaims; signingInput: Uint8Array; signature: Uint8Array }

function parse(jwt: string): Parsed {
  const parts = jwt.split('.')
  if (parts.length !== 3) throw new FromPriorError('not a compact JWS')
  let header: Record<string, unknown>, payload: Record<string, unknown>, signature: Uint8Array
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0]!)))
    payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1]!)))
    signature = b64urlToBytes(parts[2]!)
  } catch { throw new FromPriorError('not a compact JWS') }
  if (header?.typ !== 'JWT' || !JWS_ALGORITHMS.includes(header.alg as JwsAlgorithm)) throw new FromPriorError('typ must be JWT and alg EdDSA, ES256 or ES256K')
  if (header.alg === 'EdDSA' && header.crv !== undefined && header.crv !== 'Ed25519') throw new FromPriorError('EdDSA is supported on Ed25519 only')
  const { iss, sub, iat, exp, nbf } = payload ?? {}
  if (typeof iss !== 'string' || typeof sub !== 'string' || !iss.startsWith('did:') || !sub.startsWith('did:')) throw new FromPriorError('iss and sub must be DIDs')
  if (typeof iat !== 'number' || (exp !== undefined && typeof exp !== 'number') || (nbf !== undefined && typeof nbf !== 'number')) throw new FromPriorError('iat, exp and nbf must be numbers')
  if (typeof header.kid !== 'string' || header.kid.split('#', 1)[0] !== iss || !header.kid.includes('#')) throw new FromPriorError('kid must be a DID URL of iss')
  return {
    kid: header.kid,
    alg: header.alg as JwsAlgorithm,
    claims: { iss, sub, iat, ...(exp === undefined ? {} : { exp }), ...(nbf === undefined ? {} : { nbf }) },
    signingInput: new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    signature,
  }
}

/** The `iss` and `sub` a header claims, unverified -- to know whose document
 * to resolve before verifying. */
export function fromPriorClaims(jwt: string): FromPriorClaims & { kid: string } {
  const { kid, claims } = parse(jwt)
  return { ...claims, kid }
}

/** Resolves `kid` (a key of `iss`) to the signing key `iss` authorizes (one
 * its `authentication` references), or throws FromPriorError. */
export type FromPriorKeyResolver = (iss: string, kid: string) => Promise<SigningKey>

/** Verifies `jwt` as the `from_prior` of a message whose `from` is `from`. */
export async function verifyFromPrior(jwt: string, from: string, resolveKey: FromPriorKeyResolver, now = Date.now()): Promise<DidRotation> {
  const { kid, alg, claims, signingInput, signature } = parse(jwt)
  if (claims.sub !== from) throw new FromPriorError('sub is not the message\'s from')
  if (claims.sub === claims.iss) throw new FromPriorError('iss and sub must differ')
  const seconds = now / 1000
  if (claims.exp !== undefined && seconds >= claims.exp) throw new FromPriorError('expired')
  if (claims.nbf !== undefined && seconds < claims.nbf) throw new FromPriorError('not yet valid')
  const key = await resolveKey(claims.iss, kid)
  if (!verifyJwsSignature(alg, key, signingInput, signature)) throw new FromPriorError('signature does not verify')
  return { prior: claims.iss, current: claims.sub, kid, iat: claims.iat }
}

// ---- What a DID document authorizes ----

interface DocumentMethods {
  id: string
  verificationMethod?: ReadonlyArray<{ id: string; publicKeyMultibase?: string; publicKeyJwk?: { kty?: string; crv?: string; x?: string } }>
  authentication?: readonly unknown[]
}

/** `#fragment` of a DID URL (or the id itself when it has none). */
export function fragmentOf(id: string): string {
  const hash = id.indexOf('#')
  return hash < 0 ? id : id.slice(hash)
}

/** The public key (multibase) of the method `fragment` names, when
 * `authentication` references it. References are compared by fragment: a
 * domain move rewrites a did:webvh's DID part, never a key's fragment. */
export function authenticationKeyOf(document: DocumentMethods, fragment: string): string | undefined {
  const method = authenticationMethodOf(document, fragment)
  return typeof method?.publicKeyMultibase === 'string' ? method.publicKeyMultibase : undefined
}

/** `authenticationSigningKey`, its refusal a FromPriorError. */
function signingKeyOf(document: DocumentMethods, kid: string): SigningKey {
  try { return authenticationSigningKey(document, kid) } catch (error) {
    if (error instanceof SignatureError) throw new FromPriorError(error.message)
    throw error
  }
}

// ---- did:webvh: keys published before a device was removed (§7-2) ----

/** The device keys (keyAgreement fragments) a log entry lists. */
export function keyAgreementOf(entry: LogEntry): string[] {
  const state = entry.state as { keyAgreement?: unknown }
  if (!Array.isArray(state.keyAgreement)) return []
  return state.keyAgreement.filter((id): id is string => typeof id === 'string').map(fragmentOf)
}

/** Since which entry (index) the latest entry's authentication key
 * `fragment` has been published unchanged, and its key; undefined when the
 * latest entry does not publish it. */
export function authenticationKeySince(entries: readonly LogEntry[], fragment: string): { key: string; since: number } | undefined {
  const keyAt = (index: number) => authenticationKeyOf(entries[index]!.state as DocumentMethods, fragment)
  const last = entries.length - 1
  const key = last < 0 ? undefined : keyAt(last)
  if (key === undefined) return undefined
  let since = last
  while (since > 0 && keyAt(since - 1) === key) since--
  return { key, since }
}

/** True when an entry AFTER `since` removed a `keyAgreement` key (a device):
 * a key published at `since` is then one a removed device may hold. A device
 * removed in the entry at `since` itself was removed with the key's renewal. */
export function deviceRemovedSince(entries: readonly LogEntry[], since: number): boolean {
  for (let index = since + 1; index < entries.length; index++) {
    const after = keyAgreementOf(entries[index]!)
    if (keyAgreementOf(entries[index - 1]!).some(fragment => !after.includes(fragment))) return true
  }
  return false
}

/** The §7-2 check on a did:webvh `iss`'s verified log: `kid` must still be
 * published, and no device removed since it was. */
export function assertKeyNotStale(entries: readonly LogEntry[], kid: string): void {
  const published = authenticationKeySince(entries, kid)
  if (!published) throw new FromPriorError(`${kid} is not an authentication key of the latest log entry`)
  if (deviceRemovedSince(entries, published.since)) throw new FromPriorError(`${kid} was published before a device was removed`)
}

/** The key resolver for every DID method biset reads as a prior DID:
 * did:webvh from its whole verified log (with the §7-2 check), did:web from
 * its document, did:peer:2 from the DID itself. `fetchImpl` should bypass a
 * host's CDN: a stale document would accept a key already replaced. */
export function fromPriorKeyResolver(fetchImpl: typeof fetch = fetch): FromPriorKeyResolver {
  return async (iss, kid) => {
    if (iss.startsWith('did:peer:2.')) return signingKeyOf(decodePeerDid2(iss) as unknown as DocumentMethods, kid)
    if (iss.startsWith('did:web:')) {
      const document = await resolveDidWeb(iss, fetchImpl)
      if (!document) throw new Error(`from_prior: ${iss} does not resolve`)
      return signingKeyOf(document as DocumentMethods, kid)
    }
    if (!iss.startsWith('did:webvh:')) throw new FromPriorError(`unsupported DID method for iss ${iss}`)
    const response = await fetchImpl(didToHttpsUrl(iss))
    if (response.status === 404) throw new FromPriorError(`${iss} has no log`)
    if (!response.ok) throw new Error(`from_prior: HTTP ${response.status} fetching ${iss}'s log`)
    const entries = parseLog(await response.text())
    const document = resolveEntries(iss, entries)
    if (!document) throw new FromPriorError(`${iss} is deactivated`)
    const key = signingKeyOf(document as unknown as DocumentMethods, kid)
    assertKeyNotStale(entries, kid)
    return key
  }
}
