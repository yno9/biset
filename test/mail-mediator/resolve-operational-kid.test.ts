// resolveMailOperationalKid reuses resolveDidCommSenderKey's own
// did:webvh + routing.json resolve (see test/protocol/
// webvh-resolve-sender-key.test.ts for the underlying resolve mechanics)
// and adds one thing: reading identity/bootstrap.ts's own mailFromForIdentity
// convention (a bare address in alsoKnownAs) back out.
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { createGenesis } from '../../src/identity/webvh/create-genesis.ts'
import { encodeMultikey } from '../../src/identity/webvh/multikey.ts'
import { buildRoutingDoc, putRouting } from '../../src/didcomm/webvh-routing.ts'
import { resolveMailOperationalKid } from '../../src/mail-mediator/resolve-operational-kid.ts'
import { fakeAnchor } from '../protocol/support/webvh-log-fixture.ts'

async function withGlobalFetch<T>(fetchImpl: typeof fetch, run: () => Promise<T>): Promise<T> {
  const realFetch = globalThis.fetch
  globalThis.fetch = fetchImpl
  try {
    return await run()
  } finally {
    globalThis.fetch = realFetch
  }
}

describe('resolveMailOperationalKid', () => {
  test('resolves the address and key for a published mail operational kid', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const mailPrivateKey = x25519.utils.randomSecretKey()
    const mailPublicKey = x25519.getPublicKey(mailPrivateKey)
    const anchor = fakeAnchor()
    const signing = { updateKey: encodeMultikey(rootPublicKey), privateKey: rootPrivateKey }

    const { did } = await createGenesis({ domain: 'y.biset.md', rootPrivateKey, rootPublicKey, fetch: anchor.fetch })
    const kid = `${did}#mail-k1`
    await putRouting(did, buildRoutingDoc(did, {
      keyAgreementKeys: [{ kid: '#mail-k1', publicKey: mailPublicKey }],
      alsoKnownAs: ['y@mail.biset.md'],
    }), signing, anchor.fetch)

    await withGlobalFetch(anchor.fetch, async () => {
      const result = await resolveMailOperationalKid(kid, anchor.fetch)
      expect(result).toEqual({ address: 'y@mail.biset.md', publicKey: mailPublicKey })
    })
  })

  test('returns null when the identity has no mail address in alsoKnownAs yet', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const mailPrivateKey = x25519.utils.randomSecretKey()
    const mailPublicKey = x25519.getPublicKey(mailPrivateKey)
    const anchor = fakeAnchor()
    const signing = { updateKey: encodeMultikey(rootPublicKey), privateKey: rootPrivateKey }

    const { did } = await createGenesis({ domain: 'y.biset.md', rootPrivateKey, rootPublicKey, fetch: anchor.fetch })
    const kid = `${did}#mail-k1`
    await putRouting(did, buildRoutingDoc(did, { keyAgreementKeys: [{ kid: '#mail-k1', publicKey: mailPublicKey }] }), signing, anchor.fetch)

    await withGlobalFetch(anchor.fetch, async () => {
      expect(await resolveMailOperationalKid(kid, anchor.fetch)).toBeNull()
    })
  })

  test('returns null for a kid the document never published', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const anchor = fakeAnchor()

    const { did } = await createGenesis({ domain: 'y.biset.md', rootPrivateKey, rootPublicKey, fetch: anchor.fetch })
    await withGlobalFetch(anchor.fetch, async () => {
      expect(await resolveMailOperationalKid(`${did}#never-published`, anchor.fetch)).toBeNull()
    })
  })

  test('returns null for a kid with no fragment', async () => {
    expect(await resolveMailOperationalKid('did:webvh:no-fragment')).toBeNull()
  })
})
