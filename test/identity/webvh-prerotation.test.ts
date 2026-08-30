import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createGenesis } from '../../src/identity/webvh/create-genesis.ts'
import { rotateToPreRotatedKey } from '../../src/identity/webvh/prerotation.ts'
import { encodeMultikey } from '../../src/identity/webvh/multikey.ts'
import { multikeyHashBase58 } from '../../src/identity/webvh/hash.ts'
import { parseLog, resolveParameters, type LogParameters } from '../../src/identity/webvh/log.ts'
import { resolveEntries } from '../../src/identity/webvh/resolver.ts'

const hashOf = (publicKey: Uint8Array) => multikeyHashBase58(encodeMultikey(publicKey))

describe('permanent did:webvh pre-rotation', () => {
  test('starts Root as Sign with one Spare commitment and preserves it across rotation', async () => {
    const rootPrivateKey = new Uint8Array(32).fill(1)
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const firstSparePrivateKey = new Uint8Array(32).fill(2)
    const firstSparePublicKey = ed25519.getPublicKey(firstSparePrivateKey)
    const secondSparePublicKey = ed25519.getPublicKey(new Uint8Array(32).fill(3))
    let log = ''
    const fetchImpl: typeof fetch = async (_input, init) => {
      if (init?.method === 'PUT') { log = String(init.body); return new Response(null, { status: 201 }) }
      if (init?.method === 'POST') { log += String(init.body); return new Response(null, { status: 201 }) }
      return new Response(log, { status: 200 })
    }

    const { did } = await createGenesis({ domain: 'rotation.example', rootPrivateKey, rootPublicKey, nextKeyHash: hashOf(firstSparePublicKey), fetch: fetchImpl })
    let entries = parseLog(log)
    expect(entries[0]!.parameters.updateKeys).toEqual([encodeMultikey(rootPublicKey)])
    expect(entries[0]!.parameters.nextKeyHashes).toEqual([hashOf(firstSparePublicKey)])
    expect(entries[0]!.state.service).toEqual([{ id: `${did}#routing`, type: 'BisetRoutingDocument', serviceEndpoint: 'https://rotation.example/.well-known/routing.json' }])
    expect(resolveEntries(did, entries)?.id).toBe(did)

    await rotateToPreRotatedKey({ did, revealedPrivateKey: firstSparePrivateKey, revealedPublicKey: firstSparePublicKey, nextKeyHash: hashOf(secondSparePublicKey), fetch: fetchImpl })
    entries = parseLog(log)
    let parameters: LogParameters = {}
    for (const entry of entries) parameters = resolveParameters(parameters, entry.parameters)
    expect(entries).toHaveLength(2)
    expect(parameters.updateKeys).toEqual([encodeMultikey(firstSparePublicKey)])
    expect(parameters.nextKeyHashes).toEqual([hashOf(secondSparePublicKey)])
    expect(resolveEntries(did, entries)?.id).toBe(did)
  })
})
