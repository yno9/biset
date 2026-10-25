// Root-cause regression guard for the DIDComm-side counterpart of the same bug fixed in mls/did-authentication-service.ts: a
// device that never itself changed anything must keep resolving under its OWN senderKid after the identity's log moved on
// (a sibling's update, or the log moving to another host).
//
// The device's X25519 key is published IN the signed log, so a later version carries it automatically, and what the resolver
// matches on is the `#fragment` of the DID, which nothing in a later version changes: a did:vh never changes.
import { describe, expect, test } from 'vitest'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { serializeLog } from '../../src/protocol/vh/log.ts'
import { resolveDidCommSenderKey } from '../../src/protocol/didcomm/sender-key.ts'
import { buildDidCommLog } from './support/did-log-fixture.ts'
import { extendVhLog } from './support/vh-log-fixture.ts'

describe('resolveDidCommSenderKey', () => {
  test('a never-moved device\'s senderKid still resolves after the log moves to another host', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const senderPublicKey = x25519.getPublicKey(x25519.utils.randomSecretKey())
    const { did, log } = buildDidCommLog({
      rootPrivateKey, rootPublicKey,
      keyAgreementKeys: [{ fragment: 'k1', x25519PublicKey: senderPublicKey }],
      endpointUri: 'https://mediator.test.example',
      domain: 'move-src.example',
    })
    // Someone else's update: the log now lives at another host; this sender device never re-publishes anything.
    const moved = extendVhLog(log, rootPrivateKey, rootPublicKey, state => { state.alsoKnownAs = ['did:web:move-dst.example', `${did}?src=https://move-dst.example`] }, '2026-08-24T00:00:00Z')
    const served = (async () => new Response(serializeLog(moved))) as unknown as typeof fetch
    expect(await resolveDidCommSenderKey(`${did}#k1`, served)).toEqual(senderPublicKey)
  })
})
