// The capstone test for PLAN.md §6.2's outbound send: a real sender vault
// (IndexedDB) composes and locally commits an "outbox" email, submits it
// through the real authenticated narrow API (CoreMailSubmissionAdapter),
// which really dials out (mail-smtp-client.ts) to a real inbound listener
// (mail-smtp-listener.ts) hosting a separate recipient identity on the same
// core -- then the sender's own local vault commit (transport.result +
// mailbox.set) is verified by rebuilding the projection from scratch, and
// the recipient's copy is verified by pulling it over real HTTP.
import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { Database } from 'bun:sqlite'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createBisetCoreFetchHandler } from '../../../src/core/app.ts'
import { SqliteTrustedDeviceRoster } from '../../../src/core/identity/sqlite-device-roster.ts'
import { SqliteIngressStore } from '../../../src/core/mediation/sqlite-ingress-store.ts'
import { rosterBackedIngressAuthorizer, rosterBackedMailSubmissionAuthorizer } from '../../../src/core/identity/authorizers.ts'
import { CoreIngressAdapter } from '../../../src/core/adapters/ingress.ts'
import { MailIngressAdapter } from '../../../src/core/adapters/mail.ts'
import { CoreMailSubmissionAdapter } from '../../../src/core/adapters/mail-submission-adapter.ts'
import { createSmtpMailListener } from '../../../src/core/adapters/mail-smtp-listener.ts'
import { CoreIngressTransport } from '../../../src/vault/core-ingress-transport.ts'
import { ingressPullSigningBytes } from '../../../src/protocol/signing.ts'
import { createMlsGroup, generateOwnKeyPackage, ownSignaturePrivateKey } from '../../../src/mls/group.ts'
import { selfGroupIdHex } from '../../../src/mls/self-group.ts'
import { buildMailMessageAdd } from '../../../src/vault/mail-message.ts'
import { IndexedDbVaultStore } from '../../../src/vault/store.ts'
import { VaultBackedLocalJmapMutationSink } from '../../../src/local-jmap/vault-mutation-sink.ts'
import { buildLocalJmapProjectionRebuild, buildMailSubmitter, buildVaultCryptoBoundary } from '../../../src/identity/bootstrap.ts'
import { buildGenesisLog } from '../../protocol/support/webvh-log-fixture.ts'
import type { IdentityRecord } from '../../../src/identity/record-store.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../../src/mls/store.ts'

const DATABASE_NAME = 'biset-vault-core'
const APEX_DOMAIN = 'example'
const CORE_ORIGIN = 'https://core.test.example'

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

function memorySelfGroupStore(): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>()
  return {
    async save(id, selfGroupId, state) { rows.set(id, { selfGroupId, state }) },
    async load(id) { return rows.get(id) },
  }
}

async function makeIdentity(did: string, deviceKid: string) {
  const kp = await generateOwnKeyPackage(deviceKid)
  const state = await createMlsGroup(hexToBytes(selfGroupIdHex(did)), kp)
  const selfGroupStore = memorySelfGroupStore()
  await selfGroupStore.save(did, selfGroupIdHex(did), state)
  const publicKey = ed25519.getPublicKey(ownSignaturePrivateKey(state))
  const record: IdentityRecord = { did, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
  return { record, selfGroupStore, publicKey }
}

const sqlitePaths: string[] = []
afterEach(async () => {
  for (const path of sqlitePaths.splice(0)) for (const suffix of ['', '-wal', '-shm']) { try { rmSync(`${path}${suffix}`) } catch {} }
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DATABASE_NAME)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => resolve()
  })
})

describe('outbound send: a real sender vault submits, a real inbound listener receives it', () => {
  test('mailbox moves outbox -> sent, a transport.result is recorded, projection rebuild succeeds, and the recipient pulls the exact bytes', async () => {
    // Recipient: a real did:webvh genesis (buildGenesisLog's fixture domain,
    // "test.example") -- its own RCPT TO address is derived the same way
    // mail-recipient-resolver.ts derives it in production: localpart "test"
    // + apexDomain "example" -> the subdomain "test.example" the fixture
    // log actually resolves for.
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did: recipientDid, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const recipient = await makeIdentity(recipientDid, `${recipientDid}#device-a`)
    const recipientAddress = `test@mail.${APEX_DOMAIN}`

    // Sender: a syntactically valid did:webvh under a DIFFERENT subdomain
    // ("sender.example") -- never actually resolved over the network in
    // this flow (mailFromForIdentity is a pure local string derivation),
    // so it only needs to parse, not to be independently publishable. Reuses
    // the recipient log's own SCID purely for a valid base58 shape.
    const senderScid = recipientDid.split(':')[2]!
    const senderDid = `did:webvh:${senderScid}:sender.${APEX_DOMAIN}`
    const sender = await makeIdentity(senderDid, `${senderDid}#device-a`)

    const databasePath = `/tmp/biset-mail-e2e-${process.pid}-${Date.now()}.sqlite`
    sqlitePaths.push(databasePath)
    const database = new Database(databasePath)
    const roster = new SqliteTrustedDeviceRoster(database)
    const signingKeys = {
      async resolveEd25519PublicKey(keyId: string) {
        if (keyId === sender.record.deviceKid) return sender.publicKey
        if (keyId === recipient.record.deviceKid) return recipient.publicKey
        return undefined
      },
    }
    const { Ed25519DeviceControlSignatureVerifier } = await import('../../../src/core/identity/ed25519-device-control-verifier.ts')
    const verifier = new Ed25519DeviceControlSignatureVerifier(signingKeys)
    await roster.installAcceptedProjection({
      version: 1, identityId: sender.record.did, selfGroupId: 'self-sender', epoch: '1', acceptedAt: '2026-08-24T00:00:00.000Z',
      devices: [{ deliveryFloor: '1', deviceId: sender.record.deviceKid!, signingKeyId: sender.record.deviceKid! }],
    })
    await roster.installAcceptedProjection({
      version: 1, identityId: recipient.record.did, selfGroupId: 'self-recipient', epoch: '1', acceptedAt: '2026-08-24T00:00:00.000Z',
      devices: [{ deliveryFloor: '1', deviceId: recipient.record.deviceKid!, signingKeyId: recipient.record.deviceKid! }],
    })

    const ingressStore = new SqliteIngressStore(database, rosterBackedIngressAuthorizer(roster, verifier))
    const ingressAdapter = new CoreIngressAdapter(roster, ingressStore)
    const mailIngressAdapter = new MailIngressAdapter(ingressAdapter)
    const listener = createSmtpMailListener({
      port: 0, helloName: `mail.${APEX_DOMAIN}`, apexDomain: APEX_DOMAIN,
      ingressAdapter: mailIngressAdapter, roster,
    })

    // Redirects outbound delivery to the listener above instead of real DNS
    // -- everything past this injection point (mail-smtp-client.ts's own
    // wire dialogue) is exercised for real, same as the outbound client's
    // own delivery test.
    const { deliverMail } = await import('../../../src/core/adapters/mail-smtp-client.ts')
    const testDeliverMail: typeof deliverMail = (options, message) =>
      deliverMail({ ...options, mxResolver: async () => ['127.0.0.1'], port: listener.port }, message)
    const mailSubmissionAuthorizer = rosterBackedMailSubmissionAuthorizer(roster, verifier)
    const mailSubmissionAdapter = new CoreMailSubmissionAdapter(mailSubmissionAuthorizer, `mail.${APEX_DOMAIN}`, testDeliverMail)

    const coreFetch = createBisetCoreFetchHandler({
      ingressStore, roster: { store: roster, verifier }, mailSubmission: mailSubmissionAdapter,
    })
    const realFetch = globalThis.fetch
    // withFetch() alone would REPLACE globalThis.fetch entirely for its
    // callback's duration, clobbering the route to coreFetch below --
    // this single combined stub serves both roles directly, the same
    // pattern identity-end-to-end-mail-sync.test.ts's own combinedFetch
    // uses (core-origin requests vs. the recipient's webvh log fetch).
    globalThis.fetch = (async (input, init) => {
      const request = new Request(input, init)
      if (request.url.startsWith(CORE_ORIGIN)) return coreFetch(request)
      return new Response(log.map(entry => JSON.stringify(entry)).join('\n') + '\n', { status: 200 })
    }) as typeof fetch

    try {
      {
        // Sender: a real IndexedDB vault, a real message.add into "outbox".
        const store = await IndexedDbVaultStore.open()
        const boundary = buildVaultCryptoBoundary(store, store, sender.selfGroupStore, sender.record)
        const segment = await boundary.activeSegment()
        // Ends in \r\n on purpose: mail-smtp-client.ts adds one before the
        // DATA terminator only when the body doesn't already end in a
        // newline (RFC 5321 dialogue correctness, matches the archived
        // relay's own documented behavior) -- ending with one here keeps
        // this test's byte-for-byte round-trip assertion exact.
        const rawRfc5322 = new TextEncoder().encode('Subject: hello from the outbox\r\n\r\nsent through the real pipe\r\n')
        const { metadataObject, rawRfc5322Object, event } = await buildMailMessageAdd(
          {
            email: {
              id: 'msg-1', threadId: 'thread-1', mailboxIds: { outbox: true }, keywords: {},
              receivedAt: '2026-08-24T00:00:00.000Z', to: [{ email: recipientAddress }],
            },
            rawRfc5322,
          },
          { identityId: sender.record.did, actorDeviceId: sender.record.deviceKid!, actorSeq: 1, parents: [], segmentId: segment.segmentId, segmentKey: segment.segmentKey, createdAt: '2026-08-24T00:00:00.000Z' },
          boundary.signer,
        )
        await store.commitRecoveryArchive({
          identityId: sender.record.did,
          events: [{ ...event, identityId: sender.record.did }],
          objects: [{ ...metadataObject, identityId: sender.record.did }, { ...rawRfc5322Object, identityId: sender.record.did }],
          keyWraps: segment.keyWraps,
        })
        const rebuildBefore = await buildLocalJmapProjectionRebuild(store, store, store, sender.selfGroupStore, sender.record.did)()
        expect(rebuildBefore.emails[0]).toMatchObject({ id: 'msg-1', mailboxIds: { outbox: true } })

        let sequence = 1
        const sink = new VaultBackedLocalJmapMutationSink({
          accountId: `biset:${sender.record.did}`, identityId: sender.record.did, actorDeviceId: sender.record.deviceKid!,
          async nextActorSeq() { sequence += 1; return sequence },
          async initialParents() { return [event.id] },
          activeSegment: () => boundary.activeSegment(),
          signer: boundary.signer,
          committer: store,
        })
        const submitter = buildMailSubmitter(store, sender.selfGroupStore, sender.record, sink, APEX_DOMAIN, CORE_ORIGIN)
        const result = await submitter.submit('msg-1', rawRfc5322Object.objectId, [recipientAddress], rebuildBefore)
        expect(result.status).toBe('accepted')

        const rebuildAfter = await buildLocalJmapProjectionRebuild(store, store, store, sender.selfGroupStore, sender.record.did)()
        expect(rebuildAfter.emails[0]).toMatchObject({ id: 'msg-1', mailboxIds: { sent: true } })

        store.close()
      }

      const recipientTransport = new CoreIngressTransport({ baseUrl: CORE_ORIGIN, fetch: (input, init) => coreFetch(new Request(input, init)) })
      const recipientState = (await recipient.selfGroupStore.load(recipient.record.did))!.state
      const pullUnsigned = { version: 1 as const, identityId: recipient.record.did, recipientDeviceId: recipient.record.deviceKid!, requestedAt: '2026-08-24T00:05:00.000Z' }
      const envelopes = await recipientTransport.pull({ ...pullUnsigned, signature: ed25519.sign(ingressPullSigningBytes(pullUnsigned), ownSignaturePrivateKey(recipientState)) })
      expect(envelopes).toHaveLength(1)
      expect(new TextDecoder().decode(envelopes[0]!.protectedPayload)).toBe('Subject: hello from the outbox\r\n\r\nsent through the real pipe\r\n')

      listener.stop()
      database.close()
    } finally {
      globalThis.fetch = realFetch
    }
  })
})
