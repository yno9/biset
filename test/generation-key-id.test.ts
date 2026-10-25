// The id of the key that marks the generation of the generation seed in the DID document: `#biset-generation`.
import { describe, expect, test } from 'vitest'
import { publishedRotationKey, ROTATION_KEY_FRAGMENT, rotationSigningKey } from '../src/client/didcomm/rotation-key.ts'
import { chooseRoute, ownRotationIdentity } from '../src/client/didcomm/did-rotation.ts'
import { applyContactSet, didContactPatch, ownRotationPatch, type LocalJmapContactCard } from '../src/client/store/projection/contacts.ts'
import { fromPriorClaims } from '../src/protocol/didcomm/from-prior.ts'

const DID = 'did:vh:scid'
const seed = crypto.getRandomValues(new Uint8Array(32))

describe('the key\'s id', () => {
  test('it is #biset-generation, apart from the service #didcomm (a document\'s ids are one namespace)', () => {
    expect(ROTATION_KEY_FRAGMENT).toBe('#biset-generation')
    expect(ROTATION_KEY_FRAGMENT).not.toBe('#didcomm')
  })

  test('a document publishes the key under that id only; the old name is not read', () => {
    const key = rotationSigningKey(seed).publicKeyMultibase
    const document = (fragment: string) => ({ id: DID, authentication: [fragment], verificationMethod: [{ id: fragment, type: 'Multikey', publicKeyMultibase: key }] })
    expect(publishedRotationKey(document('#biset-generation'))).toBe(key)
    expect(publishedRotationKey(document('#didcomm-rotation'))).toBeUndefined()
  })

  test('from_prior is signed under it', () => {
    const mediatorDid = 'did:web:mediator.example', peerDid = 'did:vh:scid2'
    let card = applyContactSet(undefined, didContactPatch(peerDid))! as LocalJmapContactCard
    card = applyContactSet(card, ownRotationPatch(card.id, ownRotationIdentity(seed, peerDid, mediatorDid).did, 'startedAt', '2026-10-08T00:00:00Z'))!
    const route = chooseRoute(peerDid, { identityDid: DID, frontDoor: { fromKid: `${DID}#a`, x25519PrivateKey: new Uint8Array(32) }, cards: [card], rotation: { seed, mediatorDid }, now: () => 1_800_000_000_000 })
    expect(fromPriorClaims(route.fromPrior!).kid).toBe(`${DID}#biset-generation`)
  })
})
