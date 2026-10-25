// The DIDComm side of DID resolution: one sender-key resolver.
//
// did.md publishes `keyAgreement` and the `#didcomm` service INTO the signed
// log, so `resolveDidDocument()` alone returns everything a DIDComm sender
// needs. A caller that wants a route calls doc-route.ts's
// `didCommRouteFromDocument` on that document.
import { resolveDidDocument } from '../did-resolve.ts'
import { defaultFetch } from '../net-fetch.ts'
import { keyAgreementRecipients } from './doc-route.ts'
import { didOfKid } from '../ids.ts'

/** Resolves a DIDComm sender's kid (a full DID URL, `did:vh:...#k_<hash>`)
 * to its published X25519 keyAgreement public key -- crypto.ts's
 * `ResolveSenderKey`, backed by a live resolve. Throws if the identity
 * doesn't resolve, or hasn't published a keyAgreement entry for this exact
 * kid (a JWE claiming a sender that never registered this key cannot be
 * authenticated, so there is nothing safe to decrypt with).
 *
 * Matches by `#fragment` against the resolved document's OWN current id,
 * not `senderKid` verbatim: a kid is matched by its `#fragment`, which is
 * what names a device key, whichever absolute form a sender wrote. */
/** The sender's DID resolved, and does not list this kid as a
 * keyAgreement key: a device removed from it, or a kid that never was one.
 * Not a network failure -- retrying cannot change the answer. */
export class SenderKeyNotPublishedError extends Error {
  constructor(kid: string) {
    super(`resolveDidCommSenderKey: ${kid} is not a published keyAgreement entry`)
    this.name = 'SenderKeyNotPublishedError'
  }
}

export async function resolveDidCommSenderKey(senderKid: string, fetchImpl: typeof fetch = defaultFetch()): Promise<Uint8Array> {
  const hash = senderKid.indexOf('#')
  if (hash < 0) throw new Error(`resolveDidCommSenderKey: not a DID URL: ${senderKid}`)
  const did = didOfKid(senderKid)
  const fragment = senderKid.slice(hash)
  const doc = await resolveDidDocument(did, { fetch: fetchImpl })
  if (!doc) throw new Error(`resolveDidCommSenderKey: sender identity ${did} does not resolve`)
  // The device list is `keyAgreement`; a verification method it does not
  // reference (a removed device's, left behind) authenticates nothing.
  const recipient = keyAgreementRecipients(doc as Parameters<typeof keyAgreementRecipients>[0]).find(value => value.kid.slice(value.kid.indexOf('#')) === fragment)
  if (!recipient) throw new SenderKeyNotPublishedError(senderKid)
  return recipient.publicKey
}
