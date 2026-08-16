// The display name published in a DID document.
//
// Method-agnostic and deliberately so: it reuses the same JMAP `Identity.name`
// the "Change display name" modal already sets (`ui/left-pane.ts`) rather than
// inventing a separate DID-specific name to manage. It lived in the did:dht
// publisher only because that was the first thing to publish one.
//
// An identity can span several relays/addresses; take the first one that has a
// name set at all.
import * as identityStore from '../store/identities.ts'

export function displayNameFor(relaySessions: Array<{ account: { email: string } }>): string | undefined {
  for (const s of relaySessions) {
    const name = identityStore.all().find(i => i.email === s.account.email)?.name
    if (name) return name
  }
  return undefined
}
