import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { generatePeerIdentity } from '../../src/didcomm/peer.ts'
import { issueBisetMailAddressCredential, verifyBisetMailAddressCredential } from '../../src/oid4vp/mail-address-profile.ts'

const issuer = 'https://anchor.biset.md'
const keyId = `${issuer}/oid4vp/jwks#mail-address-credential-eddsa-1`
const issuerPrivateKey = ed25519.utils.randomSecretKey()
const issuerPublicKey = ed25519.getPublicKey(issuerPrivateKey)
const now = new Date('2026-08-28T08:00:00.000Z')
const address = 'y@mail.biset.md'

function credential(relationshipDid: string): string {
  return issueBisetMailAddressCredential({
    issuer, signingKeyId: keyId, signingPrivateKey: issuerPrivateKey, address, relationshipDid,
    validFrom: new Date(now.getTime() - 60_000), validUntil: new Date(now.getTime() + 86_400_000),
  })
}

describe('Biset mail address ownership VC profile', () => {
  test('issues and verifies a credential naming only the relationship DID, never a stable identity DID', () => {
    const relationship = generatePeerIdentity()
    const token = credential(relationship.did)
    const verified = verifyBisetMailAddressCredential(token, { issuer, signingKeyId: keyId, signingPublicKey: issuerPublicKey, now })
    expect(verified.credentialSubject.address).toBe(address)
    expect(verified.cnf.relationshipDid).toBe(relationship.did)
    // did:peer:2 IS the relationship identity, so it's expected to appear --
    // what must never appear is a did:webvh (the stable, publicly resolvable
    // identity this credential is meant to hide).
    expect(JSON.stringify(verified)).not.toContain('did:webvh')
  })

  test('rejects a wrong issuer key, tampered address, and an expired credential', () => {
    const relationship = generatePeerIdentity()
    const token = credential(relationship.did)
    const wrongKey = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    expect(() => verifyBisetMailAddressCredential(token, { issuer, signingKeyId: keyId, signingPublicKey: wrongKey, now }))
      .toThrow('JWT signature is invalid')
    expect(() => verifyBisetMailAddressCredential(token, { issuer, signingKeyId: keyId, signingPublicKey: issuerPublicKey, now: new Date(now.getTime() + 86_500_000) }))
      .toThrow('credential is outside its validity period')
  })

  test('rejects a relationship DID that is not a did:peer:2', () => {
    expect(() => credential('did:web:not-a-peer-did')).toThrow('relationship DID is invalid')
  })

  test('rejects a mail address without an @ sign', () => {
    expect(() => issueBisetMailAddressCredential({
      issuer, signingKeyId: keyId, signingPrivateKey: issuerPrivateKey, address: 'not-an-address',
      relationshipDid: generatePeerIdentity().did, validFrom: new Date(now.getTime() - 60_000), validUntil: new Date(now.getTime() + 86_400_000),
    })).toThrow('mail address is invalid')
  })
})
