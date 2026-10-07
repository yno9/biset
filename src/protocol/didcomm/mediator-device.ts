// The `device` label naming one device's inbox at a mediator
// (mediator/server.ts). Every DID a device registers -- its did:webvh
// front door and each relationship did:peer -- needs one, and they must not
// match across DIDs: the same label under two DIDs would tell the mediator
// that a relationship did:peer belongs to the same device (and so the same
// person) as a public did:webvh, which is exactly what a pairwise did:peer
// exists to hide. So the label is a keyed hash of the DID under a secret
// only this device holds: stable for this device, unlinkable across DIDs.
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { b64url } from './crypto.ts'
import type { DidCommSender, MediatorInboxClient } from './mediator-transport.ts'

const LABEL_CONTEXT = 'biset/mediator-device/v1\n'

function mediatorDeviceLabel(deviceSecret: Uint8Array, did: string): string {
  if (deviceSecret.length !== 32) throw new TypeError('mediator device secret must be 32 bytes')
  return b64url(hmac(sha256, deviceSecret, new TextEncoder().encode(LABEL_CONTEXT + did))).slice(0, 22)
}

/** The inbox a request that names no `device` belongs to: one per sending
 * key. Coordinate Mediation 3.0 and Pickup 3.0 have no `device` field -- a
 * standard client holds one inbox per key it authenticates with -- so the
 * mediator derives the label from the key's own kid. `device` is a biset
 * extension for the case where several devices share ONE key (a
 * relationship did:peer), which a kid cannot tell apart. */
export function defaultDeviceLabel(senderKid: string): string {
  return 'k' + b64url(sha256(new TextEncoder().encode('biset/mediator-default-device/v1\n' + senderKid))).slice(0, 21)
}

/** `identity` (a DID and one of its own keyAgreement keys) as this device's
 * inbox at a mediator. */
export function mediatorInbox(identity: DidCommSender, deviceSecret: Uint8Array): MediatorInboxClient {
  return { ...identity, device: mediatorDeviceLabel(deviceSecret, identity.did) }
}
