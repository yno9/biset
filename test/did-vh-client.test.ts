// The client side of did:vh: how a did:vh is shown, what its contact card keeps, and the memory that refuses an old log.
import { afterEach, expect, test } from 'vitest'
import { displayName, labelForDid, setContactDids, setContactNames, setVerifiedAddresses } from '../src/client/app/ui/did-display.ts'
import { aliasPatch, didContactPatch, didContactUid } from '../src/client/store/projection/contacts.ts'
import { StoredVersionMemory } from '../src/client/identity/version-memory.ts'
import { verifiedVhAddress, configureDidResolution } from '../src/protocol/did-resolve.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import { serializeLog } from '../src/protocol/webvh/log.ts'
import { buildVhDidCommLog } from './protocol/support/vh-log-fixture.ts'

const priv = new Uint8Array(32).fill(7)
const { did, log } = buildVhDidCommLog({ rootPrivateKey: priv, rootPublicKey: ed25519.getPublicKey(priv), alsoKnownAs: ['did:web:alice.did.md'] })
const shadow = { ...JSON.parse(JSON.stringify(log[0]!.state).split(did).join('did:web:alice.did.md')), alsoKnownAs: [did] }

afterEach(() => { setVerifiedAddresses(new Map()); setContactNames(new Map()); setContactDids(new Map()); configureDidResolution({}) })

test('a did:vh is shown as the DID until an address was verified for it, then as that address', () => {
  expect(labelForDid(did)).toBe(did)
  setVerifiedAddresses(new Map([[did, 'alice@did.md']]))
  expect(labelForDid(did)).toBe('alice@did.md')
  expect(displayName(did)).toBe('alice@did.md')
  setContactNames(new Map([[did, 'Alice']]))
  expect(displayName(did)).toBe('Alice')
})

test('the contact card of a did:vh is the same under any fragment, and keeps the verified address as an alias', () => {
  expect(didContactUid(`${did}#key-1`)).toBe(didContactUid(did))
  const created = didContactPatch(did, 'alice@did.md')
  const emails = Object.values(created.patch).filter(value => typeof value === 'object' && value !== null && 'address' in value)
  expect(emails).toEqual([{ address: 'alice@did.md' }])
  expect(created.patch['biset.md:scid']).toBeUndefined()
  // without a verified address nothing is invented
  expect(Object.keys(didContactPatch(did).patch).some(key => key.startsWith('emails/'))).toBe(false)
  const card = { id: created.cardId, emails: {} } as Parameters<typeof aliasPatch>[0]
  expect(aliasPatch(card, did)).toBeUndefined()
  expect(aliasPatch(card, did, 'alice@did.md')).toBeDefined()
})

test('verifiedVhAddress: only when the did:web shadow is what the log derives', async () => {
  const world = (webDocument: unknown): typeof fetch => (async (input: string | URL | Request) => {
    const url = String(input)
    if (url === 'https://alice.did.md/.well-known/did.jsonl') return new Response(serializeLog(log))
    if (url === 'https://alice.did.md/.well-known/did.json') return Response.json(webDocument)
    return new Response('', { status: 404 })
  }) as typeof fetch
  const vh = { locations: ['alice.did.md'] }
  expect(await verifiedVhAddress(did, { fetch: world(shadow), vh })).toBe('alice@did.md')
  expect(await verifiedVhAddress(did, { fetch: world({ ...shadow, service: [{ id: '#x', type: 'X', serviceEndpoint: 'https://evil.example' }] }), vh })).toBeUndefined()
  expect(await verifiedVhAddress(did, { fetch: world(shadow) })).toBeUndefined() // nowhere to look
})

test('StoredVersionMemory survives a reload, forgets on request, and starts empty from damaged storage', () => {
  const data = new Map<string, string>()
  const storage = { getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => { data.set(key, value) } }
  const first = new StoredVersionMemory(storage)
  first.set(did, { versionNumber: 3, versionId: '3-Qm' })
  expect(new StoredVersionMemory(storage).get(did)).toEqual({ versionNumber: 3, versionId: '3-Qm' })
  first.forget(did)
  expect(new StoredVersionMemory(storage).get(did)).toBeUndefined()
  data.set('biset.log-versions', '{not json')
  expect(new StoredVersionMemory(storage).get(did)).toBeUndefined()
  expect(new StoredVersionMemory(undefined).get(did)).toBeUndefined()
})
