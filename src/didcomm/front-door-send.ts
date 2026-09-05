// The Vault-independent half of send-message.ts's outbound DIDComm send:
// resolve routing.json, authcrypt (Forward-wrapped through a registered
// mediator when the recipient has one), POST. Split out (2026-08-31) so
// DOM-less deploy units (mls-ds/, whose own tsconfig has no `lib: ["DOM"]`)
// that need only this generic primitive don't pull in send-message.ts's
// relationship functions -- those depend on vault/contact-key.ts, which
// transitively reaches vault/objects.ts's Web Crypto `KeyUsage` type,
// unavailable without the DOM lib these deploy units deliberately exclude
// (tsconfig.mediator.json's own header explains why: proving a deploy unit
// stays free of Vault/UI coupling is the whole point of the DOM-less check).
// send-message.ts re-exports this unchanged for its own existing callers.
import { resolveWithRouting } from './webvh-resolve.ts'
import { decodeX25519Multikey, decodeMlkem768Multikey } from './multikey.ts'
import { packAuthcrypt, packAuthcryptHybrid, type DidCommJWE } from './crypto.ts'
import { mlkemKidFor } from './devicekid.ts'
import { buildPlaintext } from './message.ts'
import { wrapForwardChain } from './forward-wrap.ts'
import { decodePeerDid2, publicKeyOf } from './peer.ts'
import type { DidCommServiceEndpoint } from './webvh-routing.ts'
import { defaultFetch } from '../net-fetch.ts'

export type DidCommSendResult = { ok: true } | { ok: false; error: string }

export interface SendDidCommMessageOptions {
  /** This device's own DIDComm kid (identity/bootstrap.ts's `enableDidComm`
   * -- didcomm/devicekid.ts's deviceKidFragment, distinct from the MLS
   * leaf's own deviceKid). */
  fromKid: string
  x25519PrivateKey: Uint8Array
  subject?: string
  fetch?: typeof fetch
}

/** Wallet enrollment appends a new public front-door device rather than
 * rewriting older (possibly offline) device entries. Prefer that newest
 * endpoint. Generic DIDComm documents still fall back to their newest
 * keyAgreement entry when no Biset device suffix links service and key. */
function newestDidCommRoute(doc: NonNullable<Awaited<ReturnType<typeof resolveWithRouting>>>) {
  const service = [...doc.service].reverse().find(value => value.type === 'DIDCommMessaging')
  const endpoint = service?.serviceEndpoint
  const value = endpoint && typeof endpoint === 'object' && !Array.isArray(endpoint)
    ? endpoint as Partial<DidCommServiceEndpoint>
    : undefined
  const keyAgreementIds = new Set(doc.keyAgreement ?? [])
  const suffix = /#didcomm-biset-([A-Za-z0-9_-]+)$/.exec(service?.id ?? '')?.[1]
  const keyAgreement = suffix
    ? doc.verificationMethod.find(candidate => candidate.id.endsWith(`#k_${suffix}`) && keyAgreementIds.has(candidate.id))
    : undefined
  return { endpoint: value, keyAgreement: keyAgreement ?? [...doc.verificationMethod].reverse().find(candidate => keyAgreementIds.has(candidate.id)) }
}

/** The generic "resolve routing.json, authcrypt (Forward-wrapped if the
 * recipient registered a mediator), POST" primitive `sendDidCommMessage`/
 * `initiateRelationship` (send-message.ts) are thin wrappers around --
 * exported so a caller needing an arbitrary `type`/`body`
 * (mls-ds/fanout.ts's `message-notify` delivery, mls-ds-1.0.md §5.2)
 * doesn't have to reimplement routing.json resolution and Forward-wrapping
 * to get one. */
export async function sendFrontDoorMessage(toDid: string, type: string, body: unknown, opts: SendDidCommMessageOptions): Promise<DidCommSendResult> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  let doc: Awaited<ReturnType<typeof resolveWithRouting>>
  try {
    doc = await resolveWithRouting(toDid, fetchImpl)
  } catch (error) {
    return { ok: false, error: `could not resolve ${toDid}: ${error instanceof Error ? error.message : String(error)}` }
  }
  if (!doc) return { ok: false, error: `${toDid} does not resolve to a published identity` }

  const { endpoint, keyAgreement: kaVm } = newestDidCommRoute(doc)
  if (!endpoint || typeof endpoint.uri !== 'string' || !endpoint.uri) return { ok: false, error: `${toDid} has no DIDComm service endpoint published` }
  // A non-empty routingKeys (webvh-routing.ts's own header) means the
  // recipient has registered with an independent, blind mediator: deliver
  // Forward-wrapped through it rather than authcrypt'ing straight to
  // `endpoint.uri` (the legacy first-party-infra model, still supported for
  // an identity that hasn't migrated yet). The full array is a hop chain
  // (forward-wrap.ts's `wrapForwardChain`, outermost/closest-to-sender
  // first) -- not just its first entry.
  const routingKeys = endpoint.routingKeys ?? []

  if (!kaVm) return { ok: false, error: `${toDid} has no keyAgreement key published -- they need to enable DIDComm first` }
  let recipientPublicKey: Uint8Array
  try {
    recipientPublicKey = decodeX25519Multikey(kaVm.publicKeyMultibase)
  } catch {
    return { ok: false, error: `${toDid}'s published keyAgreement key is not a valid X25519 key` }
  }

  const plaintext = buildPlaintext(type, body, opts.fromKid.split('#', 1)[0], toDid)
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(plaintext))
  const sender = { kid: opts.fromKid, privateKey: opts.x25519PrivateKey }

  // Upgrade to the hybrid X25519+ML-KEM-768 authcrypt whenever the recipient
  // published an ML-KEM entry alongside their X25519 one (mlkemKidFor's
  // naming convention -- devicekid.ts) -- this is the only production path
  // that ever reaches packAuthcryptHybrid; without it the fully-implemented,
  // tested PQ-hybrid mode was unreachable and every message stayed exposed
  // to harvest-now-decrypt-later even between two devices that both
  // supported it (found live, 2026-08-26). Falls back to classical authcrypt
  // on any malformed mlkem entry rather than failing the send outright.
  let mlkemVm: (typeof doc.verificationMethod)[number] | undefined
  try {
    const mlkemId = mlkemKidFor(kaVm.id)
    mlkemVm = doc.verificationMethod.find(v => v.id === mlkemId)
  } catch {
    mlkemVm = undefined
  }
  let jwe: DidCommJWE
  if (mlkemVm) {
    try {
      const mlkemPublicKey = decodeMlkem768Multikey(mlkemVm.publicKeyMultibase)
      jwe = packAuthcryptHybrid(plaintextBytes, sender, { kid: kaVm.id, x25519PublicKey: recipientPublicKey, mlkemPublicKey })
    } catch {
      jwe = packAuthcrypt(plaintextBytes, sender, { kid: kaVm.id, publicKey: recipientPublicKey })
    }
  } else {
    jwe = packAuthcrypt(plaintextBytes, sender, { kid: kaVm.id, publicKey: recipientPublicKey })
  }
  let outbound: DidCommJWE = jwe
  if (routingKeys.length > 0) {
    try {
      outbound = wrapForwardChain(jwe, kaVm.id, routingKeys)
    } catch {
      return { ok: false, error: `${toDid}'s registered mediator routing keys (${routingKeys.join(', ')}) are not valid did:peer kids` }
    }
  }
  const response = await fetchImpl(endpoint.uri, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(outbound) })
  if (response.status !== 202) {
    return { ok: false, error: `send failed: HTTP ${response.status} ${(await response.text().catch(() => '')).slice(0, 256)}` }
  }
  return { ok: true }
}

/** Resolves a recipient's registered independent mediator route (url +
 * routing kid) -- send-message.ts's `initiateRelationship` uses this to
 * enroll a fresh private did:peer with the SAME mediator the recipient's
 * front door already advertises. */
export async function frontDoorMediatorRoute(toDid: string, fetchImpl: typeof fetch): Promise<{ url: string; routingKid: string }> {
  const doc = await resolveWithRouting(toDid, fetchImpl)
  if (!doc) throw new Error(`${toDid} does not resolve to a published identity`)
  const { endpoint: value } = newestDidCommRoute(doc)
  if (!value) throw new Error(`${toDid} has no DIDComm mediator service published`)
  if (!value.uri || !value.routingKeys?.[0]) throw new Error(`${toDid} has no independent DIDComm mediator published`)
  // Decode before registration so a hostile routing document cannot make us
  // enroll a private key against a malformed/non-self-certifying route.
  publicKeyOf(decodePeerDid2(value.routingKeys[0].split('#', 1)[0]!), value.routingKeys[0])
  return { url: value.uri, routingKid: value.routingKeys[0] }
}
