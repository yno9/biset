// Autocrypt Level 1 on the DIDComm side: what this device tells a mail bridge about its own key (didmail
// PROTOCOL.md §7.4). The bridge turns it into an `Autocrypt:` header; a peer that reads it can encrypt to us.
import { autocryptKeydata } from './keyring.ts'

export interface OwnAutocrypt {
  keydata: string
  preferEncrypt: 'mutual'
}

/** A mail bridge's DID for an external address: `did:web:{bridge-host}:{domain}:{local}` (didmail PROTOCOL.md §3.1),
 * the domain being the one with a dot. Any other DID is a DIDComm peer, which has no use for an Autocrypt key. */
export function isMailBridgeDid(did: string): boolean {
  return /^did:web:[^:]+:[^:%]+\.[^:%]+:[^:]+$/.test(did)
}

/** The key to send along to `toDid`, or `undefined` when it is not a mail address or this identity has no key. */
export async function ownAutocryptFor(toDid: string, own: { address: string; privateKey: Uint8Array } | undefined): Promise<OwnAutocrypt | undefined> {
  if (!own || !isMailBridgeDid(toDid)) return undefined
  return { keydata: await autocryptKeydata(own.privateKey, own.address), preferEncrypt: 'mutual' }
}

/** The mail address a bridge DID stands for (`did:web:did.md:4r.ma:n` -> `n@4r.ma`; the local part is percent-encoded), or undefined. */
export function mailAddressOfBridgeDid(did: string): string | undefined {
  if (!isMailBridgeDid(did)) return undefined
  const [, , , domain, local] = did.split(':')
  try { return `${decodeURIComponent(local!)}@${domain!.toLowerCase()}` } catch { return undefined }
}

/** The host of a mail bridge DID (`did:web:did.md:4r.ma:n` -> `did.md`), or undefined. */
export function bridgeHostOf(did: string): string | undefined {
  return isMailBridgeDid(did) ? decodeURIComponent(did.split(':')[2]!) : undefined
}

/** Whether to write to a mail address encrypted: a key is held for it and it asked for encryption when both sides want it
 * (Autocrypt Level 1, 2.2; this identity always does). */
export function shouldEncrypt(held: { preferEncrypt?: 'mutual' } | undefined): boolean { return held?.preferEncrypt === 'mutual' }
