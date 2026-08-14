// The Authentication Service (PLANMLS.md §2's AS role, Phase 2): deciding
// whether an MLS leaf's claim to be `did#kN` is currently true.
//
// ## What this checks, and what actually authenticates a device
//
// A leaf's credential is a DIDComm device key id (mls/identity.ts). This
// resolves that DID and checks the fragment is still one of its listed
// keyAgreement keys — so a device removed from the identity's document stops
// validating, and a credential naming a DID that never had that device never
// validates at all.
//
// It is important to be exact about what this does NOT prove. MLS leaf
// signature keys are minted per key package and are not in the DID document,
// so "this signature key belongs to that device" is not verifiable here. The
// binding that actually holds is one layer down and is stronger than a
// document lookup:
//
//   - Every message that introduces a leaf — a commit adding someone, an
//     external commit adding oneself — reaches the Delivery Service inside an
//     **authcrypt'd DIDComm envelope**, which proves the sender holds the
//     private key of a device listed in that DID's document. That is the
//     authentication.
//   - The DS admits an external commit only when the joiner's DID is already
//     in the group's roster (anchor/mediator/mls-ds.ts), so the ability to
//     add a device is exactly the ability to authenticate AS that identity.
//
// This check is therefore defence in depth over that, plus the piece the DS
// cannot do: the DS never parses MLS and cannot see what a leaf claims, while
// every member can.
//
// ## Why it is cached, and why failure is not silent
//
// Validation runs while processing a commit, on a path with no UI waiting on
// it, but a resolve per leaf per commit would be a network round trip inside
// every group operation. Resolved device lists are cached briefly. A resolve
// that FAILS is not treated as invalid — a DHT hiccup must not eject a real
// member from a group — but it is logged, because silently accepting on
// failure is how a validator turns into an accept-all one without anyone
// noticing.
import type { AuthenticationService, Credential } from './vendor/index.ts'
import { resolveDidCommDoc } from '../did/didcomm/resolve.ts'
import { memberIdOf, didOfKid } from './identity.ts'

/** How long a resolved device list is reused. Short: a device removal should
 * take effect in minutes, and the mediator's own key cache (10 min) already
 * sets the scale of "recently published" everywhere else in this codebase. */
const TTL_MS = 5 * 60 * 1000

interface CachedDevices { kids: Set<string>; at: number }

const cache = new Map<string, CachedDevices>()

async function deviceKidsOf(did: string): Promise<Set<string> | null> {
  const hit = cache.get(did)
  if (hit && Date.now() - hit.at < TTL_MS) return hit.kids
  const doc = await resolveDidCommDoc(did)
  if (!doc) return null
  const kids = new Set(doc.keyAgreement)
  cache.set(did, { kids, at: Date.now() })
  return kids
}

/** Drop the cached device list for a DID — call after this identity's own
 * document changes (a device added or removed), so the next validation sees
 * it without waiting out the TTL. */
export function forgetDevices(did: string): void {
  cache.delete(did)
}

/** True when `kid` is currently a listed device of its own DID. Exported for
 * the self-group's own membership reconciliation, which asks the same
 * question about its own devices. */
export async function isLiveDeviceKid(kid: string): Promise<boolean> {
  const kids = await deviceKidsOf(didOfKid(kid))
  return kids === null ? false : kids.has(kid)
}

/** The DID-backed credential validator to install with `setMlsAuthService`. */
export const didAuthenticationService: AuthenticationService = {
  async validateCredential(credential: Credential, _signaturePublicKey: Uint8Array): Promise<boolean> {
    let kid: string
    try {
      ;({ kid } = memberIdOf(credential))
    } catch {
      // Not a biset credential at all (an X.509 leaf, or a basic credential
      // that isn't a DID URL). Nothing here can vouch for it.
      return false
    }
    const kids = await deviceKidsOf(didOfKid(kid))
    if (kids === null) {
      // Unresolvable right now. Fail OPEN, loudly — see the header.
      console.warn(`[mls] could not resolve ${didOfKid(kid)} to validate a leaf credential; accepting unverified`)
      return true
    }
    return kids.has(kid)
  },
}
