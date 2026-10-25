// A mediator that serves did:vh recipients: the DID names no place, so their logs come from the operator's watchers
// (GET /log?scid=), and everything else — registration, a key the DID lists, a key it no longer lists, a pushed log —
// works as for a did:webvh. Logs are hand-built (support/vh-log-fixture.ts), not the resolver under test.
import { describe, expect, test } from 'vitest'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { serializeLog } from '../src/protocol/vh/log.ts'
import { T, deviceLabel, freshMediator, utf8 } from './support/mediator.ts'
import { packAuthcrypt } from '../src/protocol/didcomm/crypto.ts'
import { buildPlaintext } from '../src/protocol/didcomm/message.ts'
import { SqliteMediatorStore } from '../src/server/mediator/sqlite-store.ts'
import { createDidStateResolver, createNetworkWebvhResolver, createVhWatcherResolver } from '../src/server/mediator/log-state.ts'
import { addKeyAgreement, buildVhDidCommLog, extendVhLog } from './protocol/support/vh-log-fixture.ts'

const root = ed25519.utils.randomSecretKey()
const rootPublic = ed25519.getPublicKey(root)
const phone = x25519.utils.randomSecretKey()
const laptop = x25519.utils.randomSecretKey()
const base = buildVhDidCommLog({ rootPrivateKey: root, rootPublicKey: rootPublic, keyAgreementKeys: [{ fragment: 'k_phone', x25519PublicKey: x25519.getPublicKey(phone) }], endpointUri: 'https://mediator.example', alsoKnownAs: ['did:web:alice.did.md'] })
const did = base.did
const publicLookup = async () => ['93.184.216.34']
const phoneHolder = { did, xKid: `${did}#k_phone`, xPriv: phone }
const laptopHolder = { did, xKid: `${did}#k_laptop`, xPriv: laptop }
const add = { updates: [{ recipient_did: did, action: 'add' }] }

/** A mediator whose only watcher is `https://did.md`, which serves whatever log `world.log` holds (or 404, or is down). */
function withWatcher(world: { log: typeof base.log | null; down?: boolean }, options: { watchers?: string[] } = {}) {
  const calls = { n: 0 }
  const clock = { now: Date.now() }
  const fetchImpl = (async (input: RequestInfo | URL) => {
    calls.n += 1
    if (world.down) return new Response('', { status: 503 })
    if (!new URL(String(input)).pathname.startsWith('/log') || world.log === null) return new Response('', { status: 404 })
    return new Response(serializeLog(world.log))
  }) as typeof fetch
  const resolveLog = createDidStateResolver({
    webvh: createNetworkWebvhResolver({ lookup: publicLookup, fetch: fetchImpl }),
    ...((options.watchers ?? ['https://did.md']).length ? { vh: createVhWatcherResolver({ watchers: options.watchers ?? ['https://did.md'], lookup: publicLookup, fetch: fetchImpl }) } : {}),
  })
  const m = freshMediator({}, SqliteMediatorStore.memory(), { now: () => clock.now, logFreshMs: 300_000, logRetryMs: 10_000, logStaleMs: 3_600_000, resolveLog })
  return { ...m, calls, clock }
}

/** One raw authcrypt request from `holder`, for the answers that are not a DIDComm reply (HTTP errors). */
async function raw(m: ReturnType<typeof withWatcher>, holder: { did: string; xKid: string; xPriv: Uint8Array }) {
  const plaintext = buildPlaintext(T.RECIPIENT_UPDATE, add, holder.did, m.mediator.did, { returnRoute: 'all' })
  return m.post(packAuthcrypt(utf8(JSON.stringify(plaintext)), { kid: holder.xKid, privateKey: holder.xPriv }, [{ kid: m.mediator.xKid, publicKey: m.mediator.xPub }]))
}

describe('a mediator with a watcher for did:vh', () => {
  test('registers a device whose key the did:vh lists, learned from the watcher by SCID', async () => {
    const m = withWatcher({ log: base.log })
    const reply = await m.request(phoneHolder, T.RECIPIENT_UPDATE, add)
    expect((reply.body as any).updated[0].result).toBe('success')
    expect(m.store.listInboxes(did)).toHaveLength(1)
    expect(m.calls.n).toBe(1)
  })

  test('a key the DID does not list is refused (401): the watcher does not decide who the DID is', async () => {
    const m = withWatcher({ log: base.log })
    const response = await raw(m, { did, xKid: `${did}#k_stranger`, xPriv: x25519.utils.randomSecretKey() })
    expect(response.status).toBe(401)
    expect(m.store.listInboxes(did)).toHaveLength(0)
  })

  test('a key added to the DID later is found: an unlisted key triggers a fresh resolve of the new version', async () => {
    const world = { log: base.log as typeof base.log | null }
    const m = withWatcher(world)
    await m.request(phoneHolder, T.RECIPIENT_UPDATE, add)
    world.log = extendVhLog(base.log, root, rootPublic, state => addKeyAgreement(state, 'k_laptop', x25519.getPublicKey(laptop)), '2026-08-24T00:00:00Z')
    m.clock.now += 11_000 // past the retry window
    const reply = await m.request(laptopHolder, T.RECIPIENT_UPDATE, { updates: [{ recipient_did: did, action: 'add' }], device: deviceLabel(2) })
    expect((reply.body as any).updated[0].result).toBe('success')
  })

  test('a device the DID no longer lists loses its inbox when the DID is resolved again (refreshLogs)', async () => {
    const world = { log: base.log as typeof base.log | null }
    const m = withWatcher(world)
    await m.request(phoneHolder, T.RECIPIENT_UPDATE, add)
    expect(m.store.listInboxes(did)).toHaveLength(1)
    expect(m.store.logRecipientDids()).toEqual([did])
    world.log = extendVhLog(base.log, root, rootPublic, state => {
      state.keyAgreement = []
      state.verificationMethod = state.verificationMethod.filter((vm: { id: string }) => vm.id !== `${did}#k_phone`)
    }, '2026-08-24T00:00:00Z')
    expect(await m.refreshLogs()).toMatchObject({ checked: 1, revoked: 1 })
    expect(m.store.listInboxes(did)).toHaveLength(0)
  })

  test('a log that is another DID\'s, or forged, teaches the mediator nothing (401)', async () => {
    const otherRoot = new Uint8Array(32).fill(9)
    const other = buildVhDidCommLog({ rootPrivateKey: otherRoot, rootPublicKey: ed25519.getPublicKey(otherRoot), keyAgreementKeys: [{ fragment: 'k_phone', x25519PublicKey: x25519.getPublicKey(phone) }] })
    const swapped = withWatcher({ log: other.log })
    expect((await raw(swapped, phoneHolder)).status).toBe(401)
    expect(swapped.store.listInboxes(did)).toHaveLength(0)
    const forged = structuredClone(base.log)
    forged[0]!.state.service = [{ id: `${did}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: 'https://mallory.example' }]
    const tampered = withWatcher({ log: forged })
    expect((await raw(tampered, phoneHolder)).status).toBe(401)
    expect(tampered.store.listInboxes(did)).toHaveLength(0)
  })

  test('the watcher being down is "retry later" (503) for a DID never seen', async () => {
    const m = withWatcher({ log: base.log, down: true })
    expect((await raw(m, phoneHolder)).status).toBe(503)
  })

  test('a log pushed to POST /did-log works for a did:vh too, and a stale one is ignored', async () => {
    const m = withWatcher({ log: null })
    expect(await (await m.pushLog(serializeLog(base.log))).json()).toMatchObject({ did, version: 1, outcome: 'stored' })
    expect(await (await m.pushLog(serializeLog(base.log))).json()).toMatchObject({ outcome: 'stale' })
    expect((await m.pushLog('not a log')).status).toBe(400)
    const reply = await m.request(phoneHolder, T.RECIPIENT_UPDATE, add)
    expect((reply.body as any).updated[0].result).toBe('success')
  })
})

describe('a mediator without a watcher', () => {
  test('knows a did:vh only from a pushed log: it never goes looking for one', async () => {
    const m = withWatcher({ log: base.log }, { watchers: [] })
    expect((await raw(m, phoneHolder)).status).toBe(401)
    expect(m.calls.n).toBe(0)
    await m.pushLog(serializeLog(base.log))
    expect((await raw(m, phoneHolder)).status).toBe(200)
  })
})
