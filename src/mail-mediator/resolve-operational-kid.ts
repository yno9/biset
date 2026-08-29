// Resolves a route-bind sender's kid to the mail address it is published
// for, plus its X25519 key -- the `resolveMailOperationalKid` this
// mediator's server.ts requires (PLAN_biset-mail-mediator.md section 4).
//
// Reuses the exact same did:webvh + routing.json resolve as DIDComm's own
// resolveDidCommSenderKey (didcomm/webvh-resolve.ts) -- a mail operational
// kid is published the same way (a keyAgreement verificationMethod entry
// in the identity's routing document), so there is no separate wire
// format to invent for it. What's new here is reading the address back
// out: identity/bootstrap.ts's `mailFromForIdentity` already publishes the
// identity's derived mail address as a bare string (no `mailto:` scheme)
// into routing.json's `alsoKnownAs` -- this picks that same entry back up
// rather than inventing a second convention for the same fact.
import { didOfKid } from '../protocol/ids.ts'
import { decodeX25519Multikey } from '../didcomm/multikey.ts'
import { resolveWithRouting } from '../didcomm/webvh-resolve.ts'
import { defaultFetch } from '../net-fetch.ts'

const MAIL_ADDRESS = /^[^\s@:]+@[^\s@:]+$/

/** True for a bare `user@domain` alsoKnownAs entry (bootstrap.ts's own
 * mailFromForIdentity shape) -- excludes anything carrying a URI scheme
 * (`:`), since alsoKnownAs can hold other identifiers too. */
function isMailAddress(value: string): boolean {
  return MAIL_ADDRESS.test(value)
}

/** Null means "does not resolve as a mail operational kid at all" -- the
 * identity doesn't resolve, this exact kid isn't a published
 * verificationMethod, or the document has no mail address in
 * alsoKnownAs yet (enableDidComm's own alsoKnownAs backfill hasn't run,
 * or this identity has no mail apex configured). */
export async function resolveMailOperationalKid(
  kid: string, fetchImpl: typeof fetch = defaultFetch(),
): Promise<{ address: string; publicKey: Uint8Array } | null> {
  const hash = kid.indexOf('#')
  if (hash < 0) return null
  const did = didOfKid(kid)
  const fragment = kid.slice(hash)
  const doc = await resolveWithRouting(did, fetchImpl)
  if (!doc) return null
  const vm = doc.verificationMethod.find(v => v.id === `${doc.id}${fragment}`)
  if (!vm) return null
  const address = doc.alsoKnownAs.find(isMailAddress)
  if (!address) return null
  return { address, publicKey: decodeX25519Multikey(vm.publicKeyMultibase) }
}
