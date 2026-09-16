import { describe, expect, test } from 'bun:test'
import { deriveRelationshipPeerIdentity } from '../../src/protocol/didcomm/peer.ts'

const counterpartyDid = 'did:webvh:QmCounterparty:bob.example'
const secretA = new Uint8Array(32).fill(1)
const secretB = new Uint8Array(32).fill(2)

describe('deriveRelationshipPeerIdentity', () => {
  test('is deterministic: the same secret and counterparty always derive the same peer', () => {
    const first = deriveRelationshipPeerIdentity(secretA, counterpartyDid)
    const second = deriveRelationshipPeerIdentity(secretA, counterpartyDid)
    expect(second.did).toBe(first.did)
    expect(second.xPriv).toEqual(first.xPriv)
  })

  test('two different secrets for the same counterparty derive two different peers -- the pre-fix multi-device failure mode', () => {
    // Before 2026-09-15 this function was keyed on each DEVICE's own
    // front-door key, so two different devices of the same Wallet identity
    // (each with its own front-door key, modeled here as secretA/secretB)
    // independently contacting the same external counterparty derived two
    // different, non-superseding relationship peers -- eventually surfacing
    // as "current contact key is ambiguous; explicit rotation is required"
    // once Vault Sync merged both. This case documents that failure mode so
    // a future change can't silently reintroduce it.
    const fromDeviceOne = deriveRelationshipPeerIdentity(secretA, counterpartyDid)
    const fromDeviceTwo = deriveRelationshipPeerIdentity(secretB, counterpartyDid)
    expect(fromDeviceTwo.did).not.toBe(fromDeviceOne.did)
  })

  test('the SAME shared secret from two independent call sites converges on one peer -- the actual fix', () => {
    // did-md-oauth.ts's RELATIONSHIP_SECRET_PURPOSE derives to the identical
    // value on every device of the same Wallet identity. Two devices
    // independently contacting the same counterparty for the first time
    // therefore derive the SAME peer identity, so Vault Sync merging both
    // devices' independently-created ContactKeyV1 records finds them
    // identical (same ownRelationshipKid) instead of ambiguous.
    const sharedSecret = new Uint8Array(32).fill(3)
    const fromDeviceOne = deriveRelationshipPeerIdentity(sharedSecret, counterpartyDid)
    const fromDeviceTwo = deriveRelationshipPeerIdentity(sharedSecret, counterpartyDid)
    expect(fromDeviceTwo.did).toBe(fromDeviceOne.did)
    expect(fromDeviceTwo.xPriv).toEqual(fromDeviceOne.xPriv)
  })

  test('different counterparties derive independent peers from the same secret', () => {
    const toBob = deriveRelationshipPeerIdentity(secretA, counterpartyDid)
    const toCarol = deriveRelationshipPeerIdentity(secretA, 'did:webvh:QmCarol:carol.example')
    expect(toCarol.did).not.toBe(toBob.did)
  })

  test('rejects a secret that is not exactly 32 bytes', () => {
    expect(() => deriveRelationshipPeerIdentity(new Uint8Array(16), counterpartyDid)).toThrow('relationship secret must be 32 bytes')
  })
})
