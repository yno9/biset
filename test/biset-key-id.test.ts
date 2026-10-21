// The id of biset's own key in the DID document: `#biset-generation` now, `#didcomm-rotation` before. A document that still has
// the old name keeps it as the authority until the key is renewed; a new device's `ifAbsent` for the new id must not
// take over from it.
import { describe, expect, test } from 'vitest'
import type { LogEntry } from '../src/protocol/webvh/log.ts'
import { seedStatus } from '../src/client/didcomm/relationship-seed-bootstrap.ts'
import { relationshipSeedRecord } from '../src/client/store/vault/relationship-seed.ts'
import { LEGACY_ROTATION_KEY_FRAGMENT, publishedRotation, ROTATION_KEY_FRAGMENT, rotationSigningKey } from '../src/client/didcomm/rotation-key.ts'
import { chooseRoute } from '../src/client/didcomm/did-rotation.ts'
import { buildDocumentEdit, walletConfiguration } from '../src/client/identity/wallet/did-md-oauth.ts'
import { didContactPatch, ownRotationPatch, applyContactSet, type LocalJmapContactCard } from '../src/client/store/projection/contacts.ts'
import { ownRotationIdentity } from '../src/client/didcomm/did-rotation.ts'
import { fromPriorClaims } from '../src/protocol/didcomm/from-prior.ts'

const DID = 'did:webvh:scid:alice.example'
const seedA = crypto.getRandomValues(new Uint8Array(32)), seedB = crypto.getRandomValues(new Uint8Array(32))
const key = (seed: Uint8Array) => rotationSigningKey(seed).publicKeyMultibase
const method = (fragment: string, seed: Uint8Array) => ({ id: fragment, type: 'Multikey', publicKeyMultibase: key(seed) })
const doc = (published: Array<[string, Uint8Array]>) => ({
  id: DID, authentication: ['#pass-1', ...published.map(([fragment]) => fragment)], verificationMethod: published.map(([fragment, seed]) => method(fragment, seed)),
})
const entry = (published: Array<[string, Uint8Array]>): LogEntry => ({ versionId: '1-x', versionTime: '2026-10-08T00:00:00Z', parameters: {}, state: { ...doc(published), keyAgreement: ['#a'] } } as unknown as LogEntry)
const stored = (seed: Uint8Array) => ({ seed, seedId: relationshipSeedRecord(DID, seed, 1).seedId })

describe('the key\'s id', () => {
  test('it is #biset-generation, apart from the service #didcomm', () => {
    expect(ROTATION_KEY_FRAGMENT).toBe('#biset-generation')
    expect(ROTATION_KEY_FRAGMENT).not.toBe('#didcomm')
  })

  test('a document publishes it under the new id, or still under the old; with both, the old one is the authority', () => {
    expect(publishedRotation(doc([['#biset-generation', seedA]]))).toEqual({ fragment: '#biset-generation', key: key(seedA) })
    expect(publishedRotation(doc([[LEGACY_ROTATION_KEY_FRAGMENT, seedA]]))).toEqual({ fragment: LEGACY_ROTATION_KEY_FRAGMENT, key: key(seedA) })
    expect(publishedRotation(doc([['#biset-generation', seedB], [LEGACY_ROTATION_KEY_FRAGMENT, seedA]]))).toEqual({ fragment: LEGACY_ROTATION_KEY_FRAGMENT, key: key(seedA) })
    expect(publishedRotation(doc([]))).toBeUndefined()
  })

  test('the seed in use is found under either id, and says which; a stray new id does not displace the old authority', () => {
    const own = '#a'.replace('#', 'did:webvh:scid:alice.example#')
    const fresh = seedStatus([entry([['#biset-generation', seedA]])], own, [stored(seedA)], Date.now())
    const old = seedStatus([entry([[LEGACY_ROTATION_KEY_FRAGMENT, seedA]])], own, [stored(seedA)], Date.now())
    const both = seedStatus([entry([[LEGACY_ROTATION_KEY_FRAGMENT, seedA], ['#biset-generation', seedB]])], own, [stored(seedA), stored(seedB)], Date.now())
    expect(fresh).toMatchObject({ state: 'usable', fragment: '#biset-generation' })
    expect(old).toMatchObject({ state: 'usable', fragment: LEGACY_ROTATION_KEY_FRAGMENT })
    expect(both).toMatchObject({ state: 'usable', fragment: LEGACY_ROTATION_KEY_FRAGMENT })
    expect(both.state === 'usable' && [...both.seed]).toEqual([...seedA])
  })
})

describe('signing a DID Rotation', () => {
  const mediatorDid = 'did:web:mediator.example'
  const peerDid = 'did:webvh:scid2:bob.example'
  const route = (fragment?: string) => {
    const own = ownRotationIdentity(seedA, peerDid, mediatorDid)
    let card = applyContactSet(undefined, didContactPatch(peerDid))! as LocalJmapContactCard
    card = applyContactSet(card, ownRotationPatch(card.id, own.did, 'startedAt', '2026-10-08T00:00:00Z'))!
    return chooseRoute(peerDid, {
      identityDid: DID, frontDoor: { fromKid: `${DID}#a`, x25519PrivateKey: new Uint8Array(32) }, cards: [card],
      rotation: { seed: seedA, mediatorDid, ...(fragment ? { fragment } : {}) }, now: () => 1_800_000_000_000,
    })
  }

  test('from_prior names the key by the id the document publishes it under', () => {
    expect(fromPriorClaims(route(LEGACY_ROTATION_KEY_FRAGMENT).fromPrior!).kid).toBe(`${DID}#didcomm-rotation`)
    expect(fromPriorClaims(route('#biset-generation').fromPrior!).kid).toBe(`${DID}#biset-generation`)
    expect(fromPriorClaims(route().fromPrior!).kid).toBe(`${DID}#biset-generation`)
  })
})

describe('publishing it', () => {
  const config = walletConfiguration()

  test('replacing the seed also removes the old id; asking ifAbsent leaves a document\'s ids alone', () => {
    const replace = buildDocumentEdit(DID, config, undefined, ['#k_old'], [], { id: '#biset-generation', type: 'Multikey', controller: '', publicKeyMultibase: key(seedA), relationships: ['authentication'], mode: 'replace' })
    expect(replace.remove).toEqual(['#k_old', LEGACY_ROTATION_KEY_FRAGMENT])
    expect(replace.verificationMethods.map(value => value.id)).toEqual(['#biset-generation'])
    const ifAbsent = buildDocumentEdit(DID, config, undefined, ['#k_old'], [], { id: '#biset-generation', type: 'Multikey', controller: '', publicKeyMultibase: key(seedA), relationships: ['authentication'], mode: 'ifAbsent' })
    expect(ifAbsent.remove).toEqual(['#k_old'])
    expect(buildDocumentEdit(DID, config).remove).toEqual([])
  })
})
