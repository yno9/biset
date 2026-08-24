// resolveRecipient (protocol/transport.ts's TransportAdapterHost) for mail:
// turns an RCPT TO address into a local identity. Identities in this rewrite
// use a subdomain-per-identity did:webvh convention (an identity's DID
// domain IS its own subdomain, e.g. alice.biset.md) -- so "does this relay
// host alice@mail.biset.md" reduces to "does alice.biset.md resolve to a
// did:webvh with a trusted-device roster", no separate address registry
// needed. The webvh log itself is already the public, signed source of
// truth (identity/webvh/resolver.ts's resolveByDomain).
import { resolveByDomain } from '../../identity/webvh/resolver.ts'
import type { RecipientReference, RecipientResolution } from '../../protocol/transport.ts'
import type { TrustedDeviceRoster } from '../identity/device-roster.ts'

/** Thrown when resolution itself failed (network/DNS/log-verification error
 * reaching the recipient's own identity subdomain) -- distinct from a plain
 * "no such recipient" (which resolves to `undefined`, not a throw), so a
 * caller (the SMTP listener) can reply with a temporary 4xx instead of a
 * permanent 5xx for what may just be a transient outage on the recipient's
 * side. */
export class MailRecipientResolutionError extends Error {}

export interface MailRecipientResolverOptions {
  /** This deployment's apex domain, e.g. "biset.md" -- identity subdomains
   * are `${localpart}.${apexDomain}`, matching the same convention already
   * used by src/ui/account-create.ts's __BISET_CONFIG__.apexDomain. */
  apexDomain: string
  /** The SMTP domain this listener accepts mail for. Defaults to
   * `mail.${apexDomain}`; only pass this to override an unusual deployment
   * where the MX name isn't simply "mail." + apex. */
  mailDomain?: string
  roster: TrustedDeviceRoster
  /** Injectable for tests; defaults to the real live DID resolution. */
  resolveByDomain?: typeof resolveByDomain
}

const LOCAL_PART_RE = /^[!#$%&'*+/0-9=?A-Z^_`a-z{|}~.-]+$/

export function createMailRecipientResolver(
  options: MailRecipientResolverOptions,
): (reference: RecipientReference) => Promise<RecipientResolution | undefined> {
  if (!options.apexDomain) throw new TypeError('mail recipient resolver requires an apexDomain')
  const apexDomain = options.apexDomain
  const mailDomain = (options.mailDomain ?? `mail.${apexDomain}`).toLowerCase()
  const roster = options.roster
  const resolve = options.resolveByDomain ?? resolveByDomain

  return async (reference: RecipientReference): Promise<RecipientResolution | undefined> => {
    if (!reference.address) return undefined
    const at = reference.address.lastIndexOf('@')
    if (at <= 0 || at === reference.address.length - 1) return undefined
    const localPart = reference.address.slice(0, at)
    const domain = reference.address.slice(at + 1).toLowerCase()
    if (domain !== mailDomain) return undefined
    if (!LOCAL_PART_RE.test(localPart)) return undefined

    const candidateSubdomain = `${localPart.toLowerCase()}.${apexDomain}`
    let document
    try {
      document = await resolve(candidateSubdomain)
    } catch (error) {
      // Wraps any failure -- WebvhResolutionError (bad HTTP status, log
      // verification failure) or a raw fetch() failure (network/DNS) both
      // mean "couldn't tell", not "no such recipient".
      const message = error instanceof Error ? error.message : String(error)
      throw new MailRecipientResolutionError(message)
    }
    if (!document) return undefined

    const devices = await roster.trustedDevices(document.id)
    if (devices.length === 0) return undefined
    return { identityId: document.id, deviceIds: devices.map(device => device.deviceId) }
  }
}
