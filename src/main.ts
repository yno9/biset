import type { AccountSession } from './local-jmap/transport.ts'
import { defaultFetch } from './net-fetch.ts'
import { IndexedDbIdentityRecordStore } from './identity/record-store.ts'
import {
  buildActorSequencer,
  buildLocalJmapProjectionRebuild,
  buildLocalJmapReadModel,
  buildMailSubmitter,
  buildRestoreTransferVerifier,
  buildVaultCryptoBoundary,
  buildVaultDeliveryProjector,
  buildWalletVaultCryptoBoundary,
  enableDidComm,
  ensureMimiVaultRoom,
  ensureWalletMimiVaultRoom,
  fromHex,
  mailFromForIdentity,
  migrateLocalSegmentKeysToStorageRoot,
  repairCurrentLocalSegmentKeyWraps,
} from './identity/bootstrap.ts'
import { IndexedDbMlsSelfGroupStore } from './mls/store.ts'
import { IndexedDbVaultStore } from './vault/store.ts'
import { setOnIdentityCreated, setOnWalletConnected } from './ui/account-create.ts'
import { beginDidMdWalletMessagingEnrollment, disconnectDidMdWallet, openDidMdWalletBisetDidCommDevice, openDidMdWalletBisetDevice, restoreDidMdWalletSession } from './wallet/did-md-oauth.ts'
import { refreshInbox, showApp, showSysMsg } from './ui/shell.ts'
import { configureCompose } from './ui/thread.ts'
import type { ReplySendInput } from './ui/thread.ts'
import { configureAccountPage, showAccountPage, updateVaultCardStatus, type VaultCardStatus } from './ui/account-page.ts'
import { configureComposePage } from './ui/compose-page.ts'
import { readBisetConfig } from './ui/config.ts'
import { VaultBackedLocalJmapMutationSink } from './local-jmap/vault-mutation-sink.ts'
import type { LocalJmapMutationSink } from './local-jmap/gateway.ts'
import { LocalJmapGateway, LocalJmapTransport } from './local-jmap/gateway.ts'
import { MailIngressProjector } from './mail/ingress-projector.ts'
import { DidCommIngressProjector } from './didcomm/ingress-projector.ts'
import { resolveDidCommSenderKey } from './didcomm/webvh-resolve.ts'
import { sendDidCommMessage, sendRelationshipAccept, sendRelationshipMessage, sendGroupChatMessage } from './didcomm/send-message.ts'
import { MAIL_BRIDGE_INBOUND, mailBridgeInboundBodyOf } from './didcomm/mail-bridge.ts'
import { didCommThreadId } from './didcomm/basicmessage.ts'
import {
  GROUP_INVITE, GROUP_MESSAGE, parseDidCommGroupAddress,
  groupInviteBodyOf, groupMessageBodyOf, buildDidCommGroupMessageVaultRecord,
  type GroupInviteBody, type GroupMessageBody,
} from './didcomm/group-chat.ts'
import { IndexedDbDidCommGroupChatStore } from './didcomm/group-chat-store.ts'
import { ensureDidCommContact as ensureDidCommContactWith, sendReply as sendReplyWith, type PendingHandshake, type SendContext } from './app/send.ts'
import { didCommMessageDedupeId, resolveDidCommSenderDid } from './didcomm/ingress-projector.ts'
import { registerWithMediator, type MediatorPollHandle } from './didcomm/mediator-sync.ts'
import { watchMediator } from './didcomm/mediator-watch.ts'
import type { DidCommSender } from './didcomm/mediator-transport.ts'
import type { DeliveredMessage } from './didcomm/mediator-pickup.ts'
import { ingestTransportIngress } from './vault/ingress-ingest.ts'
import type { IngressEnvelopeV1 } from './protocol/ingress.ts'
import { canonicalHash, equalBytes, sha256Bytes } from './protocol/canonical.ts'
import { fetchRouting, mimiVaultRoomFromRouting, putRouting, setRoutingMimiVaultRoom, setRoutingName } from './didcomm/webvh-routing.ts'
import { moveWebvhIdentity } from './identity/webvh/move.ts'
import { adoptPendingMove } from './identity/webvh/adopt-move.ts'
import { encodeMultikey } from './identity/webvh/multikey.ts'
import { memberDeviceCredentialBytes, memberKids, ownMlsDeviceCredential, ownSignaturePrivateKey } from './mls/group.ts'
import { createMlsDeviceCredential, encodeMlsDeviceCredential } from './mls/device-credential.ts'
import { DidCommDeviceKeyReader } from './vault/didcomm-device-key-reader.ts'
import { DidCommDeviceKeyVaultSink } from './vault/didcomm-device-key-sink.ts'
import { OpenPgpCredentialReader } from './vault/openpgp-credential-reader.ts'
import { OpenPgpCredentialVaultSink } from './vault/openpgp-credential-sink.ts'
import { enableOpenPgpMail } from './mail/enable-openpgp.ts'
import { DidCommCredentialReader } from './vault/didcomm-credential-reader.ts'
import { DidCommCredentialVaultSink } from './vault/didcomm-credential-sink.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import { ContactKeyReader } from './vault/contact-key-reader.ts'
import { ContactKeyVaultSink } from './vault/contact-key-sink.ts'
import type { ContactKeyV1 } from './vault/contact-key.ts'
import { decodePeerDid2, generatePeerIdentity, publicKeyOf } from './didcomm/peer.ts'
import { RELATIONSHIP_ACCEPT, RELATIONSHIP_INIT, relationshipBodyOf, relationshipMediatorService } from './didcomm/relationship.ts'
import type { DidCommPlaintext } from './didcomm/message.ts'
import { deliverySeq, didOfKid } from './protocol/ids.ts'
import { IndexedDbBisetLoginWalletCredentialStore } from './oid4vp/wallet-store.ts'
import { ingestVaultDelivery } from './vault/delivery-ingest.ts'
import { createRecoveryArchiveSnapshot } from './vault/recovery-archive-export.ts'
import { createPortableCoordinatorCheckpoint, openPortableCoordinatorCheckpoint } from './vault/vault-checkpoint.ts'
import { rewrapRecoveryArchiveForCurrentEpoch } from './vault/recovery-archive-rewrap.ts'
import { VAULT_STORAGE_EPOCH, VAULT_STORAGE_GROUP_ID } from './vault/storage-root.ts'
import { MimiClientTransport } from './mls/mimi-client-transport.ts'
import { PersistedMimiVaultSession } from './mls/mimi-vault-session.ts'
import { watchMimiVaultDeliveries } from './mls/mimi-vault-watch.ts'
import { createMimiVaultRoom, joinMimiVaultRoom, removeMimiVaultDevice } from './mls/mimi-vault-room.ts'
import { pullMimiVaultPages, sendMimiVaultCheckpoint, synchronizeMimiVault } from './vault/mimi-vault-sync.ts'
import type { DeliveriesPullRequest } from './mimi/protocol-types.ts'
import { deliveriesPullSigningBytes } from './mimi/authorizer.ts'

let pollTimer: ReturnType<typeof setInterval> | undefined
let mimiVaultWatchHandle: { close(): void } | undefined
let mediatorPollHandles: MediatorPollHandle[] = []

/**
 * New-client bootstrap. The only branch this makes is "does this device
 * already have an identity locally": with none, this lands on the account
 * page in its zero-identity state (the signup form mounted inline --
 * account-page.ts's own showAccountPage) -- src.bak's ACTUAL default page
 * whenever there's no session (`if (!sessions.length) showMenuPage('/account')`),
 * not a separate full-page overlay (corrected 2026-08-25 after drifting into
 * inventing that instead). With one, it opens the vault UI (read model +
 * reply-send, PLAN.md §7) against the first local identity's vault, and
 * still runs `maintainSelfGroup` for every local identity (self-group
 * catch-up + roster reflection + KeyPackage pool top-up) so a second
 * identity on this device doesn't silently drift out of sync just because
 * there's no account switcher yet.
 */
// Registered once, at module load -- a plain function reference, not an
// import back into this module (see account-create.ts's own note on why:
// this file is the bundle's entry point, and a dynamic `import('../main.ts')`
// there used to make it also reachable via another module's import edge,
// which silently broke bundling -- bootClient was defined but never invoked).
//
// Lands back on the account page after bootClient's normal has-identity
// flow finishes -- src.bak's own signup handler ends the same way
// (`showMenuPage('/account')`), showing the just-created identity's card,
// not the (empty, since nothing's arrived yet) inbox bootClient's own
// showApp() renders by default. showAccountPage lives here, not in
// account-create.ts, for the identical reason bootClient does: importing it
// from account-create.ts would close the same kind of cycle (account-page.ts
// already imports FROM account-create.ts for the inline-mount helpers).
setOnIdentityCreated(async () => {
  await bootClient()
  showAccountPage()
})
setOnWalletConnected(async () => {
  await bootClient()
  showAccountPage()
})

// Every IndexedDB database this app opens, device-local and meaningless
// without an owning identity record in biset-identity -- shared by logout()
// (explicit, this device is deliberately dropping the identity) and
// bootClient()'s own zero-identity branch below (silent, defensive: a
// crash mid-signup, a corrupted store, or any other path that reaches "no
// identity" without ever going through logout() would otherwise leave
// this device's SECONDARY stores stale/orphaned indefinitely, with no way
// for an end user to notice or clear them -- found live, 2026-09-04, on a
// device stuck rendering the zero-identity page with unrelated console
// silence). Deleting a database with zero rows is a fast no-op, so running
// this on every ordinary fresh-install boot costs nothing.
const ALL_LOCAL_DATABASE_NAMES = [
  'biset-identity', 'biset-mls-keypackages', 'biset-mls-self-group',
  'biset-vault-core', 'biset-wallet', 'biset-didcomm-group-chat',
]

async function deleteLocalDatabases(names: readonly string[]): Promise<void> {
  await Promise.all(names.map(name => new Promise<void>(resolve => {
    const request = indexedDB.deleteDatabase(name)
    request.onsuccess = () => resolve()
    request.onerror = () => resolve()
    request.onblocked = () => resolve()
    setTimeout(resolve, 3000) // a step that never settles must not outlive its budget
  })))
}

async function configureWalletAccountIfPresent(): Promise<boolean> {
  let session
  try {
    session = await restoreDidMdWalletSession()
  } catch (error) {
    console.warn('[did.md Wallet restore]', error instanceof Error ? error.message : error)
    return false
  }
  if (!session) return false
  let vault: VaultCardStatus | undefined
  let onRemoveVaultDevice: ((targetDeviceId: string) => Promise<void>) | undefined
  let didComm: { xKid: string; mediatorUrl: string; error?: string } | undefined
  let activeDidCommDevice: { did: string; xKid: string; x25519PrivateKey: Uint8Array } | undefined
  try {
    const device = await openDidMdWalletBisetDevice()
    const { mimiSelfBaseUrl, mediatorUrls } = readBisetConfig()
    const selfGroupStore = new IndexedDbMlsSelfGroupStore()
    const vaultStore = await IndexedDbVaultStore.open()
    const ensured = await ensureWalletMimiVaultRoom({
      did: device.did, credential: device.credential, signaturePrivateKey: device.signaturePrivateKey,
      roomId: device.mimiVaultRoom.roomId, providerUrl: device.mimiVaultRoom.providerUrl,
      createRoom: device.mimiVaultRoomCreated,
    }, selfGroupStore, mimiSelfBaseUrl)
    // A Wallet device has no Master-derived storage KEK. Its local Vault
    // segments are instead wrapped for the current MLS epoch.  If the room
    // advanced while this tab was away, the raw local SegmentKey is still
    // present but its current-epoch wrap must be reissued before inbox or
    // relationship records can be read. The ordinary Biset boot path has
    // always done this repair; the Wallet branch had accidentally omitted
    // it, which made a perfectly intact local inbox look empty on reload.
    await repairCurrentLocalSegmentKeyWraps(selfGroupStore, vaultStore, vaultStore, {
      did: device.did,
      deviceKid: device.credential.deviceKid,
    })
    const members = memberKids(ensured.room.state, device.did).map(deviceId => ({ deviceId, current: deviceId === device.credential.deviceKid }))
    // A Wallet account has no Master seed, but it does have a real, typed
    // MLS leaf. That leaf is sufficient for ordinary post-join MIMI Vault
    // delivery: the self-group exporter opens current-epoch SegmentKey
    // wraps, and the leaf signs the provider pull plus local delivery ACK.
    // Checkpoint recovery deliberately remains unavailable here because its
    // archive key is Master-derived; pretending a Wallet leaf could recover
    // pre-join history would defeat MLS forward secrecy.
    const readModel = buildLocalJmapReadModel(vaultStore, selfGroupStore, device.did)
    const boundary = buildWalletVaultCryptoBoundary(vaultStore, vaultStore, selfGroupStore, {
      did: device.did,
      deviceKid: device.credential.deviceKid,
    })
    const projector = buildVaultDeliveryProjector(selfGroupStore, device.did, () => readModel.snapshot())
    const mlsCredential = ensured.credential
    const visibleCredential = () => ({
      kind: 'visible' as const,
      user: device.did,
      client: mlsCredential.deviceKid,
      credential: encodeMlsDeviceCredential(mlsCredential),
      signaturePublicKey: mlsCredential.signaturePublicKey,
    })
    const mimiSession = new PersistedMimiVaultSession({
      identityId: device.did,
      mode: 'self',
      transport: ensured.transport,
      stateStore: selfGroupStore,
      credential: visibleCredential(),
      sign: bytes => ed25519.sign(bytes, ensured.signaturePrivateKey),
    })
    const sequencer = await buildActorSequencer(vaultStore, device.did, device.credential.deviceKid)
    const mutationSink = new VaultBackedLocalJmapMutationSink({
      accountId: `biset:${device.did}`,
      identityId: device.did,
      actorDeviceId: device.credential.deviceKid,
      nextActorSeq: () => sequencer.nextActorSeq(),
      initialParents: () => sequencer.initialParents(),
      activeSegment: () => boundary.activeSegment(),
      signer: boundary.signer,
      committer: vaultStore,
    })
    // Relationship keys are Biset-local, encrypted Vault records.  The
    // Wallet contributes only its public Root key so this browser can verify
    // those records after a reload; no Wallet controller private key enters
    // Biset at any point.
    const walletEventVerifier = buildRestoreTransferVerifier(selfGroupStore, device.did, device.rootPublicKey).eventVerifier
    const walletContactKeyReader = new ContactKeyReader({
      identityId: device.did,
      objects: vaultStore,
      events: vaultStore,
      segmentKeys: boundary.resolver,
      verifier: walletEventVerifier,
    })
    const walletContactKeySink = new ContactKeyVaultSink({
      identityId: device.did,
      actorDeviceId: device.credential.deviceKid,
      nextActorSeq: () => sequencer.nextActorSeq(),
      initialParents: () => sequencer.initialParents(),
      activeSegment: () => boundary.activeSegment(),
      currentSnapshot: () => readModel.snapshot(),
      signer: boundary.signer,
      committer: vaultStore,
    })
    // The Wallet branch returns before the ordinary local-identity boot
    // path, which normally loads this projection.  Restore the existing
    // local inbox before rendering so a page reload never looks like it
    // discarded a Wallet account's encrypted history.
    await refreshInbox(readModel).catch(error => console.warn('[did.md Wallet inbox restore]', error))

    const setWalletVaultStatus = (next: VaultCardStatus): void => {
      // The first sync begins before configureAccountPage() below.  Retain
      // its result locally as well as repainting an already-mounted card,
      // otherwise a fast successful sync is overwritten by the initial
      // "Checking" state when the Account page is configured afterwards.
      vault = next
      updateVaultCardStatus(next)
    }
    let syncBusy = false
    const synchronizeWalletVault = async (): Promise<void> => {
      if (syncBusy) return
      syncBusy = true
      try {
        // This is the ordinary background pull for new encrypted MIMI
        // deliveries, not an interactive operation. Keep a healthy Vault
        // card at "Connected" while it runs; flashing "Syncing" every ten
        // seconds conveys no useful state and makes the account page noisy.
        const before = await selfGroupStore.loadMimiVault(device.did)
        const providerCursor = before?.deliveryCursor ?? 0
        const pullRequest = (): Omit<DeliveriesPullRequest, 'afterSeq' | 'signature'> => ({
          version: 1,
          roomId: ensured.room.roomId,
          requester: visibleCredential(),
          requestedAt: new Date().toISOString(),
        })
        const result = await synchronizeMimiVault({
          pull: value => ensured.transport.pullDeliveries('self', value),
          signPull: unsigned => ed25519.sign(deliveriesPullSigningBytes(unsigned), ensured.signaturePrivateKey),
          pullRequest: pullRequest(),
          receiver: mimiSession,
          sender: mimiSession,
          outbox: vaultStore,
          identityId: device.did,
          afterSeq: providerCursor,
          ingest: async (payload, seq) => {
            await ingestVaultDelivery({
              version: 1,
              identityId: device.did,
              seq,
              payload,
              payloadHash: sha256Bytes(payload),
              createdAt: new Date().toISOString(),
              expiresAt: '9999-12-31T23:59:59.999Z',
          }, boundary.signer, projector, vaultStore)
          },
        })
        // Receiving an MLS commit can move this device to a new epoch during
        // the pull above. Reissue its local wraps immediately, while this
        // browser still has the same encrypted segment records, so the next
        // reload never needs an external restore grant merely to read its
        // own current Vault.
        await repairCurrentLocalSegmentKeyWraps(selfGroupStore, vaultStore, vaultStore, {
          did: device.did,
          deviceKid: device.credential.deviceKid,
        })
        const outboxFailure = result.gaps.find(gap => gap.kind === 'outbox-flush-failed')
        if (outboxFailure) throw new Error(`MIMI Vault outbox append failed: ${outboxFailure.detail}`)
        if (result.latestSequence > providerCursor) {
          const current = await selfGroupStore.loadMimiVault(device.did)
          if (!current) throw new Error('MIMI Vault state disappeared while synchronizing')
          await selfGroupStore.saveMimiVault(device.did, { ...current, deliveryCursor: result.latestSequence })
        }
        if (result.ingestedSequences.length) await refreshInbox(readModel)
        const gap = result.gaps[0]
        setWalletVaultStatus({
          state: 'connected', coordinatorUrl: mimiSelfBaseUrl, vaultId: ensured.room.roomId as never,
          localSeq: String(await vaultStore.readDeliveryCursor(device.did, device.credential.deviceKid)),
          latestSeq: String(result.latestSequence), devices: members,
          detail: gap ? `MIMI Vault synced with a skipped item: ${gap.detail}` : 'Encrypted MIMI Vault is current',
        })
      } catch (error) {
        setWalletVaultStatus({
          state: 'error', coordinatorUrl: mimiSelfBaseUrl, vaultId: ensured.room.roomId as never, devices: members,
          detail: error instanceof Error ? error.message : String(error),
        })
        console.warn('[did.md Wallet MIMI Vault sync]', error)
      } finally {
        syncBusy = false
      }
    }

    vault = { state: 'checking', coordinatorUrl: mimiSelfBaseUrl, vaultId: ensured.room.roomId as never, detail: 'Checking encrypted MIMI Vault', devices: members }
    onRemoveVaultDevice = async (targetDeviceId: string) => {
      const membersAfter = await removeMimiVaultDevice({
        identityId: device.did, deviceId: ensured.credential.deviceKid, targetDeviceId,
        signaturePrivateKey: ensured.signaturePrivateKey, transport: ensured.transport, stateStore: selfGroupStore,
      })
      setWalletVaultStatus({ state: 'connected', coordinatorUrl: mimiSelfBaseUrl, vaultId: ensured.room.roomId as never, detail: 'MIMI Self Vault connected', devices: membersAfter.map(member => ({ deviceId: member.client, current: member.client === ensured.credential.deviceKid })) })
    }
    // Synchronize once on opening, then use the provider's SSE delivery
    // stream as a wake-up signal. `watchMimiVaultDeliveries` reconnects with
    // a freshly signed, short-lived watch token itself, so there is no
    // periodic 10-second pull in the steady state.
    void synchronizeWalletVault()
    let watchDebounceTimer: ReturnType<typeof setTimeout> | undefined
    const watchCursor = await selfGroupStore.loadMimiVault(device.did).then(stored => stored?.deliveryCursor ?? 0)
    const walletWatch = watchMimiVaultDeliveries({
      transport: ensured.transport,
      roomId: ensured.room.roomId,
      requester: visibleCredential(),
      sign: bytes => ed25519.sign(bytes, ensured.signaturePrivateKey),
      afterSeq: watchCursor,
      // A room update can produce several sequential entries (notably an
      // MLS commit plus its application deliveries). Let that burst settle,
      // then run the established pull/verify/project pipeline once.
      onEntry: () => {
        if (watchDebounceTimer !== undefined) clearTimeout(watchDebounceTimer)
        watchDebounceTimer = setTimeout(() => {
          watchDebounceTimer = undefined
          void synchronizeWalletVault()
        }, 1_500)
      },
      onError: error => console.warn('[did.md Wallet MIMI Vault watch]', error instanceof Error ? error.message : error),
    })
    mimiVaultWatchHandle = {
      close: () => {
        walletWatch.close()
        if (watchDebounceTimer !== undefined) clearTimeout(watchDebounceTimer)
      },
    }

    // DIDComm has its own X25519 leaf, never the MLS signing leaf and never
    // a did.md controller key. Wallet published the public leaf and mediator
    // route during the explicit consent that enrolled it; this registration
    // only proves possession of the local X25519 private key to the mediator.
    // A corrupt or independently revoked DIDComm envelope must not make the
    // otherwise healthy MIMI Vault look unavailable.  It has its own sealed
    // device material and its registration is deliberately best-effort.
    try {
      const didCommDevice = await openDidMdWalletBisetDidCommDevice()
      if (didCommDevice) {
        try {
        // URL serialization is canonical at the Wallet boundary (an origin
        // gains its trailing slash), whereas deployment configuration may
        // omit it.  Compare canonical URLs, not their source spellings.
        const authorizedMediator = new URL(didCommDevice.mediatorUrl).toString()
        const configuredMediator = mediatorUrls.some(url => {
          try { return new URL(url).toString() === authorizedMediator } catch { return false }
        })
        if (!configuredMediator) throw new Error('Wallet-authorized mediator is not configured by this Biset deployment')
        const mediator = await registerWithMediator(didCommDevice.mediatorUrl, {
          did: didCommDevice.did,
          xKid: didCommDevice.xKid,
          xPriv: didCommDevice.x25519PrivateKey,
        })
        if (mediator.xKid !== didCommDevice.routingKid) throw new Error('Mediator routing key changed since Wallet authorization; enable messaging again')
        didComm = { xKid: didCommDevice.xKid, mediatorUrl: didCommDevice.mediatorUrl }
        activeDidCommDevice = didCommDevice
        // Enrollment alone only lets the mediator queue messages.  Open the
        // device-bound live Pickup watch as well, then project every durable
        // DIDComm delivery into this browser's encrypted MIMI Vault.
        // Public first-contact messages resolve from did:webvh.  Once a
        // relationship is established, continuing DIDComm traffic is signed
        // by a did:peer key embedded in its own identifier instead.
        const resolveWalletSenderKey = async (kid: string): Promise<Uint8Array> => {
          if (kid.startsWith('did:peer:2.')) {
            const peerDid = kid.split('#', 1)[0]!
            return publicKeyOf(decodePeerDid2(peerDid), kid)
          }
          return resolveDidCommSenderKey(kid)
        }
        const walletDidCommProjector = new DidCommIngressProjector({
          identityId: device.did,
          actorDeviceId: device.credential.deviceKid,
          resolveOwnKey: async kid => {
            if (kid === didCommDevice.xKid) return { kid, x25519PrivateKey: didCommDevice.x25519PrivateKey }
            const contact = await walletContactKeyReader.forOwnKid(kid)
            return contact ? { kid, x25519PrivateKey: contact.ownX25519PrivateKey } : null
          },
          resolveSenderKey: resolveWalletSenderKey,
          resolveCounterpartyDid: async kid => (await walletContactKeyReader.forCounterpartyKid(kid))?.counterpartyDid ?? null,
          async alreadyProcessed() { return false },
          nextActorSeq: () => sequencer.nextActorSeq(),
          initialParents: () => sequencer.initialParents(),
          activeSegment: () => boundary.activeSegment(),
          currentSnapshot: () => readModel.snapshot(),
          signer: boundary.signer,
        })
        const relationshipWatchKids = new Set<string>()
        let handleWalletDidCommMessage: (message: DeliveredMessage, recipientKid: string, mediatorUrl: string) => Promise<void>
        const startWalletRelationshipWatch = (xKid: string, xPriv: Uint8Array, did: string, mediatorUrl: string): void => {
          if (relationshipWatchKids.has(xKid)) return
          relationshipWatchKids.add(xKid)
          const watch = watchMediator({
            mediatorUrl,
            own: { did, xKid, xPriv },
            resolveSenderKey: resolveWalletSenderKey,
            onMessage: message => handleWalletDidCommMessage(message, xKid, mediatorUrl),
            onError: error => console.warn('[did.md Wallet relationship watch]', error),
          })
          mediatorPollHandles.push({ stop: () => watch.close() })
        }
        const handleWalletRelationshipMessage = async (message: DeliveredMessage, mediatorUrl: string): Promise<void> => {
          const plaintext = message.plaintext as DidCommPlaintext
          if (plaintext.type !== RELATIONSHIP_INIT) return
          const body = relationshipBodyOf(plaintext)
          if (!body) throw new TypeError('relationship message body is invalid')
          const route = relationshipMediatorService(body.relationshipKid)
          if (new URL(route.url).toString() !== new URL(mediatorUrl).toString()) {
            throw new TypeError('relationship mediator does not match the delivery route')
          }
          if (message.senderKid.startsWith('did:peer:2.')) {
            throw new TypeError('relationship init must be authenticated by a public front-door kid')
          }
          const counterpartyDid = didOfKid(message.senderKid)
          let contact = await walletContactKeyReader.currentFor(counterpartyDid)
          if (!contact || contact.counterpartyRelationshipKid !== body.relationshipKid) {
            const peer = generatePeerIdentity({ uri: route.url, routingKeys: [route.routingKid] })
            await registerWithMediator(route.url, { did: peer.did, xKid: peer.xKid, xPriv: peer.xPriv })
            const next: ContactKeyV1 = {
              version: 1,
              kind: 'contact-key',
              identityId: device.did,
              counterpartyDid,
              ownRelationshipKid: peer.xKid,
              ownX25519PrivateKey: peer.xPriv,
              ownEd25519PrivateKey: peer.edPriv,
              counterpartyRelationshipKid: body.relationshipKid,
              counterpartyPublicKey: body.publicKey,
              createdAt: new Date().toISOString(),
              ...(contact ? { supersedesKid: contact.ownRelationshipKid } : {}),
            }
            await walletContactKeySink.store(next)
            contact = next
            startWalletRelationshipWatch(peer.xKid, peer.xPriv, peer.did, route.url)
          }
          const accepted = await sendRelationshipAccept(contact)
          if (!accepted.ok) throw new Error(accepted.error)
        }
        handleWalletDidCommMessage = async (message, recipientKid, mediatorUrl) => {
            const payload = new TextEncoder().encode(JSON.stringify(message.rawJwe))
            const envelope: IngressEnvelopeV1 = {
              version: 1,
              ingressId: canonicalHash('biset/didcomm-wallet-mediator-ingress/v1', {
                mediatorUrl, recipientKid, queueId: message.ackId,
              }),
              protocol: 'didcomm',
              recipientIdentityId: device.did,
              recipientDeviceSnapshot: [device.credential.deviceKid],
              createdAt: new Date().toISOString(),
              expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
              transportMetadata: {},
              sourceEvidence: new Uint8Array(0),
              protectedPayload: payload,
              protectedPayloadHash: sha256Bytes(payload),
            }
            await ingestTransportIngress(envelope, walletDidCommProjector, vaultStore)
            // Projecting INIT records the audit event.  Accepting it here is
            // the missing second half: register the private receiver, store
            // its encrypted contact key, then send the DIDComm ACCEPT.  The
            // Pickup ACK is intentionally delayed until all three succeed.
            await handleWalletRelationshipMessage(message, mediatorUrl)
            await refreshInbox(readModel)
            void synchronizeWalletVault()
        }
        const watch = watchMediator({
          mediatorUrl: didCommDevice.mediatorUrl,
          own: { did: didCommDevice.did, xKid: didCommDevice.xKid, xPriv: didCommDevice.x25519PrivateKey },
          resolveSenderKey: resolveWalletSenderKey,
          onMessage: message => handleWalletDidCommMessage(message, didCommDevice.xKid, didCommDevice.mediatorUrl),
          onError: error => console.warn('[did.md Wallet DIDComm watch]', error),
        })
        mediatorPollHandles.push({ stop: () => watch.close() })
        // Relationship keys survive reloads as encrypted Vault records.
        // Re-open their Pickup watches before accepting new messages so an
        // existing Biset conversation cannot disappear after refresh.
        const knownContacts = await walletContactKeyReader.readAll()
        const counterparties = new Set(knownContacts.map(contact => contact.counterpartyDid))
        for (const counterpartyDid of counterparties) {
          const contact = await walletContactKeyReader.currentFor(counterpartyDid)
          if (!contact) continue
          const route = relationshipMediatorService(contact.ownRelationshipKid)
          startWalletRelationshipWatch(
            contact.ownRelationshipKid,
            contact.ownX25519PrivateKey,
            contact.ownRelationshipKid.split('#', 1)[0]!,
            route.url,
          )
        }
      } catch (error) {
        didComm = { xKid: didCommDevice.xKid, mediatorUrl: didCommDevice.mediatorUrl, error: error instanceof Error ? error.message : String(error) }
        console.warn('[did.md Wallet DIDComm]', error)
      }
      }
    } catch (error) {
      console.warn('[did.md Wallet DIDComm]', error)
    }
    const sendWalletMessage = async (input: ReplySendInput): Promise<void> => {
      if (!activeDidCommDevice) throw new Error('DIDComm is still connecting for this Wallet session')
      if (input.toAddrs.length !== 1 || !input.toAddrs[0]?.startsWith('did:')) {
        throw new Error('A did.md Wallet session can currently compose to one DID recipient')
      }
      const toDid = input.toAddrs[0]
      const contact = await walletContactKeyReader.currentFor(toDid)
      const sent = contact
        ? await sendRelationshipMessage(contact, input.body, input.subject)
        : await sendDidCommMessage(toDid, input.body, {
          fromKid: activeDidCommDevice.xKid,
          x25519PrivateKey: activeDidCommDevice.x25519PrivateKey,
          ...(input.subject ? { subject: input.subject } : {}),
        })
      if (!sent.ok) throw new Error(sent.error)
      const now = new Date().toISOString()
      const snapshot = await readModel.snapshot()
      await mutationSink.commitMailMessage({
        email: {
          id: crypto.randomUUID(),
          threadId: didCommThreadId(device.did, toDid),
          mailboxIds: { sent: true },
          keywords: { '$seen': true },
          receivedAt: now,
          sentAt: now,
          from: [{ email: device.did }],
          to: [{ email: toDid }],
          ...(input.subject ? { subject: input.subject } : {}),
        },
        rawRfc5322: new TextEncoder().encode(input.body),
      }, snapshot)
      await refreshInbox(readModel)
      void synchronizeWalletVault()
    }
    configureCompose({
      selfAddress: device.did,
      selfDid: activeDidCommDevice ? device.did : undefined,
      sendReply: sendWalletMessage,
      onError: message => { showSysMsg(message); console.warn('[did.md Wallet send]', message) },
    })
    configureComposePage({
      selfAddress: device.did,
      selfDid: activeDidCommDevice ? device.did : undefined,
      sendMessage: sendWalletMessage,
      onError: message => { showSysMsg(message); console.warn('[did.md Wallet compose]', message) },
    })
  } catch (error) {
    vault = { state: 'error', coordinatorUrl: readBisetConfig().mimiSelfBaseUrl, detail: error instanceof Error ? error.message : String(error) }
    console.warn('[did.md Wallet MIMI Vault]', error)
  }
  configureAccountPage({
    did: session.did,
    wallet: {
      handle: session.handle,
      deviceJkt: session.deviceJkt,
      capabilityExpiresAt: session.capabilityExpiresAt,
      deviceKid: session.deviceKid,
      ...(didComm ? { didComm } : {}),
      onEnableMessaging: async () => beginDidMdWalletMessagingEnrollment(readBisetConfig().mediatorUrls),
      onDisconnect: async () => {
        await disconnectDidMdWallet()
        await bootClient()
      },
    },
    vault,
    onRemoveVaultDevice,
    showMessage: showSysMsg,
  })
  return true
}

export async function bootClient(): Promise<void> {
  // Cleared unconditionally, before any branch -- logout's own re-entry into
  // bootClient() lands on the zero-identity branch below, which returns
  // before the has-identity branch's own clearInterval would ever run,
  // leaving the OLD interval alive and polling a vault store logout just
  // closed. A re-registration below (has-identity branch) replaces this.
  if (pollTimer !== undefined) { clearInterval(pollTimer); pollTimer = undefined }
  if (mimiVaultWatchHandle !== undefined) { mimiVaultWatchHandle.close(); mimiVaultWatchHandle = undefined }
  // Same reasoning as pollTimer just above: a re-entry into bootClient()
  // (logout, most notably) must not leave a PRIOR identity's mediator polls
  // running against the new session's own vault/readModel.
  for (const handle of mediatorPollHandles) handle.stop()
  mediatorPollHandles = []

  const recordStore = new IndexedDbIdentityRecordStore()
  const loadedRecords = await recordStore.list().catch(() => [])
  // Credential v2 intentionally has no compatibility path: an old
  // Root-authorized record would defeat Sign-generation revocation. Remove
  // only its identity index so the UI returns to explicit restore instead
  // of crashing on missing Sign material.
  const storedRecords = loadedRecords.filter(record => record.signPrivateKey && record.signPublicKey && record.generation)
  for (const record of loadedRecords) if (!storedRecords.includes(record)) await recordStore.delete(record.did).catch(() => {})
  if (storedRecords.length === 0) {
    // A did.md Wallet account intentionally has no IdentityRecord: its
    // controller keys remain in Wallet.  It nevertheless owns real local
    // MLS/Vault state.  Restore it BEFORE the ordinary zero-identity cleanup
    // below, or every reload would delete that state and force an unsafe
    // re-create/external-join attempt for the same Wallet device.
    if (await configureWalletAccountIfPresent()) {
      showApp()
      showAccountPage()
      return
    }
    // No local identity owns them -- see ALL_LOCAL_DATABASE_NAMES's comment.
    // Neither a local IdentityRecord nor a valid Wallet session owns them.
    // `biset-identity` itself is excluded: already reconciled just above,
    // and this recordStore connection stays open past this branch's `return`
    // (unrelated to this cleanup), which would otherwise block its delete.
    await deleteLocalDatabases(ALL_LOCAL_DATABASE_NAMES.filter(name => name !== 'biset-identity'))
    configureAccountPage({ did: null })
    showApp()
    showAccountPage()
    return
  }

  const selfGroupStore = new IndexedDbMlsSelfGroupStore()
  const vaultStore = await IndexedDbVaultStore.open()
  const loginWalletStore = new IndexedDbBisetLoginWalletCredentialStore()
  // did:webvh domain move (identity/webvh/adopt-move.ts) -- catches this
  // device up on ANY identity that moved to a new domain while a SIBLING
  // device performed the move and this one wasn't looking, before anything
  // below reads a record's `.did`/`.deviceKid`/`.didCommKid`. A no-op
  // (returns the record unchanged) for an identity that hasn't moved, or
  // when resolution fails right now (offline, host unreachable) -- routine
  // upkeep, not something to block boot on.
  const records = await Promise.all(storedRecords.map(record =>
    adoptPendingMove({ recordStore, record, vaultStore, selfGroupStore }).catch(e => {
      console.warn(`[adoptPendingMove] ${record.did}:`, e instanceof Error ? e.message : e)
      return record
    }),
  ))
  for (let index = 0; index < storedRecords.length; index += 1) {
    const before = storedRecords[index]!
    const after = records[index]!
    if (before.did !== after.did) await loginWalletStore.rekeyIdentity(before.did, after.did).catch(error => console.warn('[OID4VP wallet rekey]', error))
  }
  // Single-account slice: the vault UI reads/writes the first local
  // identity's vault. maintainSelfGroup below still runs for every identity
  // on this device, so a second one doesn't silently drift out of sync just
  // because there's no account switcher yet (PLAN.md §7 plan, out of scope).
  // `let`, not `const`: enableDidComm (below) updates the record in place
  // automatically at boot, and every closure that reads it (sendReply, the
  // mediator-poll handlers) has to see the new didCommKid/
  // didCommX25519PrivateKey without needing a page reload.
  let identity = records[0]!
  const readModel = buildLocalJmapReadModel(vaultStore, selfGroupStore, identity.did, identity.masterSeed)
  const { apexDomain, mediatorUrls, mimiSelfBaseUrl } = readBisetConfig()
  const mimiVaultConfigured = !!(mimiSelfBaseUrl && identity.deviceKid)
  // Ensured here, before EVERY self-group reader below -- not just
  // vaultDevices/buildVaultCryptoBoundary/enableDidComm further down, but
  // also the repairCurrentLocalSegmentKeyWraps/migrateLocalSegmentKeysToStorageRoot
  // loops right below this. A MIMI-driven identity's self-group state IS
  // this room's own ClientState (store.ts's `saveMimiVault` writes the same
  // row `load` reads), so on this device's very first boot ever, before this
  // room exists, every one of those readers would otherwise fail once each
  // (found live, 2026-09-02: this used to only be ensured much later, past
  // all of them -- and even after moving it before vaultDevices, still
  // after these two loops specifically, which is why
  // migrateLocalSegmentKeysToStorageRoot kept logging "Vault storage
  // migration requires Self Group state" on a fresh account's very first
  // boot even once the room itself was working). ensureMimiVaultRoom's own
  // doc comment covers why this same call is repeated again, cheaply,
  // further down.
  const mimiVaultRoom = mimiVaultConfigured ? await ensureMimiVaultRoom(identity, selfGroupStore, mimiSelfBaseUrl) : undefined
  // Catch up MLS and repair every local SegmentKey wrap before any inbox,
  // credential, or relationship reader attempts decryption. Running this
  // near the end of boot used to render an empty inbox first; if a segment
  // had skipped more than one epoch, the transition-only self-grant could
  // not repair it at all on later reloads.
  for (const record of records) {
    await repairCurrentLocalSegmentKeyWraps(selfGroupStore, vaultStore, vaultStore, record).catch(e => {
      console.warn(`[repairCurrentLocalSegmentKeyWraps] ${record.did}:`, e instanceof Error ? e.message : e)
    })
  }
  for (const record of records) {
    await migrateLocalSegmentKeysToStorageRoot(vaultStore, vaultStore, record, selfGroupStore).catch(e => {
      console.warn(`[vault-storage/migrate] ${record.did}:`, e instanceof Error ? e.message : e)
    })
  }
  let vaultDevices = await selfGroupStore.load(identity.did).then(stored => stored
    ? memberKids(stored.state, identity.did).map(deviceId => ({ deviceId, current: deviceId === identity.deviceKid }))
    : []).catch(() => [])
  let vaultCardStatus: VaultCardStatus | undefined = mimiVaultConfigured ? {
    state: 'checking', coordinatorUrl: mimiSelfBaseUrl, detail: 'Opening MIMI Self Vault', devices: vaultDevices,
  } : undefined
  const setVaultCard = (next: VaultCardStatus): void => {
    next = { ...next, devices: vaultDevices }
    if (vaultCardStatus && JSON.stringify(vaultCardStatus) === JSON.stringify(next)) return
    vaultCardStatus = next
    updateVaultCardStatus(next)
  }
  // Signs with the current Sign key (the key routing.json authorization
  // keyAgreement/alsoKnownAs entries are already signed with, webvh-routing.ts's
  // DataIntegrityProof) -- account-page.ts never sees key material itself,
  // only calls this callback.
  const editName = async (name: string): Promise<void> => {
    const signPrivateKey = fromHex(identity.signPrivateKey)
    const signPublicKey = fromHex(identity.signPublicKey)
    await setRoutingName(identity.did, name, { updateKey: encodeMultikey(signPublicKey), privateKey: signPrivateKey }, defaultFetch())
  }
  // MIMI-native individual device removal ("zombie device" cleanup) — the
  // Coordinator subsystem this app used to run (self-group.ts's
  // removeDeviceFromSelfGroup/rotateSelfGroupGeneration, both hard-wired to
  // CoordinatorMlsDeliveryTransport.submitCommit) has since been deleted
  // outright, not merely dead code in this branch -- there is no non-MIMI
  // identity shape left to worry about. mimiVaultRoom's own state IS this
  // identity's self-group state (ensureMimiVaultRoom's doc comment;
  // store.ts's saveMimiVault writes the same row selfGroupStore.load
  // reads), so vaultDevices only needs updating here, not re-derived from a
  // second source.
  const removeVaultDevice = async (targetDeviceId: string): Promise<void> => {
    if (!mimiVaultRoom) throw new Error('MIMI Vault is not configured for this identity')
    const members = await removeMimiVaultDevice({
      identityId: identity.did, deviceId: mimiVaultRoom.credential.deviceKid, targetDeviceId,
      signaturePrivateKey: mimiVaultRoom.signaturePrivateKey, transport: mimiVaultRoom.transport, stateStore: selfGroupStore,
    })
    vaultDevices = members.map(member => ({ deviceId: member.client, current: member.client === mimiVaultRoom!.credential.deviceKid }))
    if (vaultCardStatus) setVaultCard(vaultCardStatus)
  }
  // did:webvh domain move (identity/webvh/move.ts) — same server-side
  // independence as editName/pre-rotation above for the
  // did.jsonl move plus local DID-keyed store migration. MLS credentials are
  // stable Root-signed objects and require no move-time commit.
  const moveIdentity = async (newDomain: string, revealedPrivateKey: Uint8Array, revealedPublicKey: Uint8Array, nextKeyHash: string): Promise<string> => {
    const previousDid = identity.did
    const moved = await moveWebvhIdentity({
      recordStore, record: identity, vaultStore, selfGroupStore,
      newDomain, signingPrivateKey: revealedPrivateKey, signingPublicKey: revealedPublicKey, nextKeyHash,
    })
    await loginWalletStore.rekeyIdentity(previousDid, moved.did)
    identity = moved
    // A full re-render, same as logout()'s own re-entry into bootClient()
    // just above -- account-page.ts's own config (did/deviceKid/masterSeed)
    // was captured at configure time below, not read live, so there is no
    // lighter way to get the identity card, devices list, and every other
    // did-scoped closure in this file (editName and the
    // pre-rotation trio) onto the new did without going through this same
    // boot path again.
    await bootClient()
    return moved.did
  }
  configureAccountPage({
    did: identity.did, masterSeed: identity.masterSeed,
    onLogout: logout, onEditName: editName,
    onMoveIdentity: moveIdentity,
    onRemoveVaultDevice: mimiVaultRoom ? removeVaultDevice : undefined,
    vault: vaultCardStatus,
    showMessage: showSysMsg,
  })

  // Identity menu's "Log out" (account-page.ts's own confirm() already ran
  // before this is called -- src.bak's confirmAndLogout/logout split, the
  // same layering here). **No page navigation**, matching src.bak's own
  // logout() exactly and for the identical reason (that function's own
  // header): logging out doesn't need a fresh document, it needs the app to
  // land on the right empty-identity UI, which is a RE-RENDER. This
  // rewrite's own equivalent of "the account page in its zero-account
  // state" is bootClient()'s own `records.length === 0` branch (the
  // new-user page) -- re-invoking it in place is exactly that render,
  // reusing the same logic a real first boot uses rather than inventing a
  // second "empty" path.
  async function logout(): Promise<void> {
    // Every one of this session's own IndexedDB connections, not just
    // vaultStore -- selfGroupStore/recordStore never closed
    // anywhere before this (each store class's own close() note explains
    // why). Left open, a deleteDatabase() call below blocks on it
    // (IndexedDB won't actually delete a database a live connection still
    // holds); this function's own onblocked handler just resolves anyway
    // (a 3s-budget best-effort step), so the delete silently no-opped and
    // the OLD database survived logout entirely. Across enough logout/
    // signup-retry cycles in one tab, the accumulated open connections left
    // this browser's IndexedDB implementation unable to complete even a
    // brand-new open() at all -- no onsuccess, no onblocked, no onerror,
    // ever (found live, 2026-08-26; a fresh Incognito window, with no
    // accumulated connections, worked every time).
    try { vaultStore.close() } catch { /* best-effort */ }
    try { selfGroupStore.close() } catch { /* best-effort */ }
    try { recordStore.close() } catch { /* best-effort */ }
    try { loginWalletStore.close() } catch { /* best-effort */ }
    // biset-didcomm-group-chat used to be missing from this list entirely
    // (found 2026-09-04 while adding bootClient()'s own zero-identity-branch
    // cleanup, ALL_LOCAL_DATABASE_NAMES's comment) -- every logout left that
    // store's rows behind indefinitely, orphaned the moment this device's
    // identity record was gone.
    await deleteLocalDatabases(ALL_LOCAL_DATABASE_NAMES)
    await bootClient()
  }

  let flushDidCommTransportOutbox: (() => Promise<void>) | undefined
  /** Best-effort nudge: ask the MIMI Vault sync loop to run right now
   * instead of waiting out whatever's left of its 10s tick. Set once,
   * inside the mimiVaultConfigured branch further down -- undefined for
   * any other deployment shape, so every call site below treats a missing
   * trigger as "nothing to nudge" rather than throwing. */
  let triggerMimiVaultSync: (() => Promise<void>) | undefined
  // Reply-send needs the signing/MLS boundary maintainSelfGroup already
  // requires a deviceKid for -- without a device identity to sign with, the
  // UI stays read-only. `coreBaseUrl` was dropped from this gate 2026-09-04:
  // it used to be required here, silently disabling this ENTIRE block
  // (enableDidComm, mediator polling/registration, mail submit/ingress,
  // group chat, contact-key relationships, outbox flush -- essentially
  // everything below) in every production deployment since core was
  // removed, with no error, because it was simply always falsy (found
  // live: a queued mediator message for a real identity was never once
  // polled for, with zero console output of any kind, because
  // startMediatorPolling/mediatorPollHandles are set up inside this same
  // block, further down).
  if (apexDomain && identity.deviceKid) {
    // Captured once, before enableDidComm's own `identity = ...` reassignment
    // below widens `identity.deviceKid` back to `string | undefined` for
    // TypeScript's control-flow narrowing -- enableDidComm never actually
    // touches deviceKid (only didCommKid/didCommX25519PrivateKey), but its
    // return type is the general IdentityRecord, so the narrowing doesn't
    // survive the reassignment even though the value can't actually change.
    const deviceKid = identity.deviceKid
    const boundary = buildVaultCryptoBoundary(vaultStore, vaultStore, selfGroupStore, identity)
    /**
     * Sibling-device replication after a local vault commit. A no-op since
     * core was retired (2026-09-04): core's `/v1/deliveries` was the only
     * transport this ever had, and `coreBaseUrl` was always '' in
     * production, so every non-MIMI call threw here instead of replicating.
     * A MIMI-driven identity never wanted this path in the first place --
     * its delivery outbox is exclusively flushMimiVaultOutbox's job
     * (synchronizeMimi's own 10s poll), and routing it through core's
     * endpoint too was actively harmful: both flushes share the SAME outbox
     * row, and core's removed it the moment its endpoint returned success,
     * deleting a just-received DIDComm message's relay-onward entry before
     * the next MIMI poll could send it (found live, 2026-09-02).
     * Kept as an explicit no-op rather than deleted at every call site: this
     * is where a non-MIMI replication transport would plug back in.
     */
    const flushReplicationOutbox = async () => ({ appendedEntryIds: [] as string[] })
    const sequencer = await buildActorSequencer(vaultStore, identity.did, deviceKid)
    const mutationSink = new VaultBackedLocalJmapMutationSink({
      accountId: `biset:${identity.did}`,
      identityId: identity.did,
      actorDeviceId: deviceKid,
      nextActorSeq: () => sequencer.nextActorSeq(),
      initialParents: () => sequencer.initialParents(),
      activeSegment: () => boundary.activeSegment(),
      signer: boundary.signer,
      committer: vaultStore,
    })
    const eventVerifier = buildRestoreTransferVerifier(selfGroupStore, identity.did, fromHex(identity.rootPublicKey)).eventVerifier
    const contactKeyReader = new ContactKeyReader({
      identityId: identity.did,
      objects: vaultStore,
      events: vaultStore,
      segmentKeys: boundary.resolver,
      verifier: eventVerifier,
    })
    const contactKeySink = new ContactKeyVaultSink({
      identityId: identity.did,
      actorDeviceId: deviceKid,
      nextActorSeq: () => sequencer.nextActorSeq(),
      initialParents: () => sequencer.initialParents(),
      activeSegment: () => boundary.activeSegment(),
      currentSnapshot: () => readModel.snapshot(),
      signer: boundary.signer,
      committer: vaultStore,
    })

    // DIDComm-native group chat (group-chat.ts) -- full-mesh pairwise
    // fan-out over the SAME ContactKeyV1 relationships 1:1 chat already
    // uses, no MLS. Device-local roster cache only (not vault-synced across
    // this identity's own devices in v1), accepted limitation for v1.
    const groupChatStore = new IndexedDbDidCommGroupChatStore()

    const pendingByOwnKid = new Map<string, PendingHandshake>()
    const pendingByCounterparty = new Map<string, PendingHandshake>()
    const relationshipPollKids = new Set<string>()
    let startRelationshipPoll: (xKid: string, xPriv: Uint8Array, did: string, mediatorUrl: string) => void = () => {
      throw new Error('DIDComm relationship polling is not initialized')
    }

    // Automatic, not opt-in (reversed 2026-08-25 after user feedback -- no
    // "Enable DIDComm" UI, same as every other identity capability this
    // rewrite just provisions on its own once a core is configured).
    // Idempotent (no-ops once didCommKid is already set) and best-effort: a
    // failure here must not block mail, which the user actually depends on
    // already working. Needs the vault-crypto boundary/sequencer above (the
    // DIDComm keyAgreement key is identity-shared, read/written through the
    // vault like the OpenPGP credential below) -- moved here, from an
    // earlier, lighter-weight call site, when that stopped being optional.
    {
      const didCommReader = new DidCommCredentialReader({
        identityId: identity.did,
        objects: vaultStore,
        events: vaultStore,
        segmentKeys: boundary.resolver,
        verifier: buildRestoreTransferVerifier(selfGroupStore, identity.did, fromHex(identity.rootPublicKey)).eventVerifier,
      })
      const didCommSink = new DidCommCredentialVaultSink({
        identityId: identity.did,
        actorDeviceId: deviceKid,
        nextActorSeq: () => sequencer.nextActorSeq(),
        initialParents: () => sequencer.initialParents(),
        activeSegment: () => boundary.activeSegment(),
        currentSnapshot: () => readModel.snapshot(),
        signer: boundary.signer,
        committer: vaultStore,
      })
      identity = await enableDidComm(recordStore, identity, didCommReader, didCommSink, { apexDomain, mediatorUrls }).catch(e => {
        console.warn('[enableDidComm]', e instanceof Error ? e.message : e)
        return identity
      })
    }

    const mailFrom = mailFromForIdentity(identity.did, apexDomain)
    // Records this device's own (deviceKid, didCommKid) pairing into the
    // vault -- private, synced only to this identity's own trusted devices
    // -- so revokeDevice above can later find and remove the matching
    // routing.json entry for a device being cut off. Write-once (skipped
    // once this device's pairing is already there) and best-effort: a
    // failure here must not block mail, same treatment as enableDidComm
    // itself above.
    const didCommKid = identity.didCommKid
    if (didCommKid) {
      const deviceKeyReader = new DidCommDeviceKeyReader({
        identityId: identity.did,
        objects: vaultStore,
        events: vaultStore,
        segmentKeys: boundary.resolver,
        verifier: buildRestoreTransferVerifier(selfGroupStore, identity.did, fromHex(identity.rootPublicKey)).eventVerifier,
      })
      const existingPairing = await deviceKeyReader.forDeviceKid(deviceKid).catch(() => undefined)
      if (!existingPairing) {
        const deviceKeySink = new DidCommDeviceKeyVaultSink({
          identityId: identity.did,
          actorDeviceId: deviceKid,
          nextActorSeq: () => sequencer.nextActorSeq(),
          initialParents: () => sequencer.initialParents(),
          activeSegment: () => boundary.activeSegment(),
          currentSnapshot: () => readModel.snapshot(),
          signer: boundary.signer,
          committer: vaultStore,
        })
        await deviceKeySink.store({
          version: 1, kind: 'didcomm.device-key', identityId: identity.did,
          deviceKid, didCommKid, createdAt: new Date().toISOString(),
        }).catch(e => console.warn('[didcomm-device-key]', e instanceof Error ? e.message : e))
      }
    }

    // Mints this identity's OpenPGP credential the first time any device
    // reaches this point (private key into the vault, synced identity-wide
    // -- unlike DIDComm's per-device keys, see enable-openpgp.ts's own
    // header), publishes the public half into routing.json. Automatic and
    // best-effort, same treatment as enableDidComm above -- PGP support is
    // required for mail, but a failure here must still not block sending
    // or receiving unencrypted mail.
    {
      const pgpReader = new OpenPgpCredentialReader({
        identityId: identity.did,
        objects: vaultStore,
        events: vaultStore,
        segmentKeys: boundary.resolver,
        verifier: buildRestoreTransferVerifier(selfGroupStore, identity.did, fromHex(identity.rootPublicKey)).eventVerifier,
      })
      const pgpSink = new OpenPgpCredentialVaultSink({
        identityId: identity.did,
        actorDeviceId: deviceKid,
        nextActorSeq: () => sequencer.nextActorSeq(),
        initialParents: () => sequencer.initialParents(),
        activeSegment: () => boundary.activeSegment(),
        currentSnapshot: () => readModel.snapshot(),
        signer: boundary.signer,
        committer: vaultStore,
      })
      const signPrivateKey = fromHex(identity.signPrivateKey)
      const signPublicKey = fromHex(identity.signPublicKey)
      await enableOpenPgpMail(pgpReader, pgpSink, { updateKey: encodeMultikey(signPublicKey), privateKey: signPrivateKey }, { identityId: identity.did, mailAddress: mailFrom })
        .catch(e => console.warn('[enableOpenPgpMail]', e instanceof Error ? e.message : e))
    }

    // Outbound submission goes to the mediator+mail-plugin deploy's own
    // /v1/mail/submit (mediator/mail-plugin/mail-submission-http.ts),
    // POSTing through the SAME public URL this device already talks to for
    // DIDComm -- no separate mail-specific endpoint configuration. Signed
    // with the identity's current did:webvh update key, not a device
    // credential, so there is nothing to register ahead of time (see that
    // handler's own header for why -- biset-core's roster-backed design
    // this TODO used to point at was retired 2026-09-04 along with core
    // itself).
    const submitter = buildMailSubmitter(vaultStore, selfGroupStore, identity, mutationSink, apexDomain, mediatorUrls[0] ?? '')
    const localMutationSink: LocalJmapMutationSink = {
      emailSet: (arguments_, snapshot) => mutationSink.emailSet(arguments_, snapshot),
      submitMail: (arguments_, snapshot) => submitter.submitMail(arguments_, snapshot),
    }
    const transport = new LocalJmapTransport(new LocalJmapGateway({
      accountId: `biset:${identity.did}`,
      identityId: identity.did,
      readModel,
      mutationSink: localMutationSink,
    }))

    // Send-side handlers: app/send.ts. Lifted out of this scope
    // (PLAN-simplify.md §2 S4 stage 1) with no behaviour change --
    // SendContext's own doc comment covers why `identity` and the
    // forward-declared `let`s below are handed over as callbacks rather
    // than as captured values.
    const sendContext: SendContext = {
      identity: () => identity,
      readModel,
      mutationSink,
      contactKeyReader,
      groupChatStore,
      transport,
      mailFrom,
      pendingByOwnKid,
      pendingByCounterparty,
      startRelationshipPoll: (xKid, xPriv, did, mediatorUrl) => startRelationshipPoll(xKid, xPriv, did, mediatorUrl),
      // The `?.` stays on this side of the wiring, where it has always
      // been: both of these are undefined for deployment shapes that never
      // assign them, and "nothing to nudge" means a silent no-op.
      flushDidCommTransportOutbox: async () => { await flushDidCommTransportOutbox?.() },
      triggerMimiVaultSync: () => { void triggerMimiVaultSync?.() },
    }
    // Only these two are still called from this file: ensureDidCommContact
    // by the outbox flush and the group-mesh catch-up below,
    // sendReply by configureCompose/configureComposePage. The other three
    // (sendDidCommChat / sendDidCommGroupMessage / createAndSendDidCommGroup)
    // are reached only through sendReply's own dispatch, inside send.ts.
    const ensureDidCommContact = (toDid: string): Promise<ContactKeyV1> => ensureDidCommContactWith(sendContext, toDid)
    const sendReply = (input: ReplySendInput): Promise<void> => sendReplyWith(sendContext, input)

    let flushingDidComm = false
    flushDidCommTransportOutbox = async (): Promise<void> => {
      if (flushingDidComm) return
      flushingDidComm = true
      try {
        const queued = await vaultStore.readDidCommOutbox(identity.did)
        for (const item of queued) {
          const snapshot = await readModel.snapshot()
          const email = snapshot.emails.find(candidate => candidate.id === item.emailId)
          if (!email) {
            console.warn(`[didcomm/outbox] ${item.emailId}: local message is missing`)
            continue
          }
          if (!email.blobId) {
            console.warn(`[didcomm/outbox] ${item.emailId}: local message has no body object`)
            continue
          }
          // No "already sent, crashed before cleanup" fast path here on
          // purpose -- there used to be one, gated on the SHARED email's
          // mailboxIds.sent/outbox flags, but mailbox.set (local-jmap/
          // reducer.ts) REPLACES mailboxIds wholesale rather than merging.
          // For a group message, N outbox rows (one per recipient) share
          // ONE emailId: the first recipient's successful send legitimately
          // clears `outbox` off that shared email as part of its own
          // mailbox.set{sent:true}, which made every OTHER recipient's row
          // in the SAME flush pass look like a stale post-crash leftover
          // and get silently deleted here without ever actually sending
          // (found live, 2026-09-03: a 2-recipient group founding message
          // only ever reached whichever recipient's outbox row happened to
          // be processed first, with zero console output for the other --
          // both `sent`/`outbox` are per-EMAIL, but "was this delivered to
          // THIS toDid" is inherently per-ROW, and nothing tracked that).
          // A genuine crash-before-cleanup instead just means one retried
          // send with the SAME item.messageId below -- the receiving side's
          // own dedupe (didCommMessageDedupeId, keyed by senderKid+message
          // id) already makes that a harmless no-op, so there is nothing to
          // guard against here.
          await vaultStore.noteDidCommOutboxAttempt(identity.did, item.outboundEventId, item.toDid, new Date().toISOString())
          try {
            const contactKey = await ensureDidCommContact(item.toDid)
            const content = new TextDecoder().decode(await readModel.download(email.blobId))
            const result = email.threadId.startsWith('didcomm-group:')
              ? await sendGroupChatMessage(contactKey, { groupId: parseDidCommGroupAddress(email.threadId), content, ...(email.subject ? { subject: email.subject } : {}) }, undefined, {
                  id: item.messageId,
                  sentAt: email.sentAt ?? item.createdAt,
                })
              : await sendRelationshipMessage(contactKey, content, email.subject, undefined, {
                  id: item.messageId,
                  sentAt: email.sentAt ?? item.createdAt,
                })
            if (!result.ok) throw new Error(result.error)
            // N recipient rows for one group message share the SAME
            // emailId -- guard the mailbox.set so the second, third, ...
            // recipient's own delivery doesn't redundantly re-commit
            // {sent:true} on an email that already has it (harmless either
            // way, this just avoids the wasted round trip).
            const latest = await readModel.snapshot()
            const alreadySent = latest.emails.find(candidate => candidate.id === item.emailId)?.mailboxIds.sent === true
            await mutationSink.commitIntents([{
              kind: 'transport.result',
              targetIds: [item.emailId],
              payload: { emailId: item.emailId, status: 'accepted', occurredAt: new Date().toISOString(), transport: 'didcomm' },
            }, ...(alreadySent ? [] : [{
              kind: 'mailbox.set' as const,
              targetIds: [item.emailId],
              payload: { emailId: item.emailId, mailboxIds: { sent: true } },
            }])], latest)
            await vaultStore.removeDidCommOutbox(identity.did, item.outboundEventId, item.toDid)
            await flushReplicationOutbox()
          } catch (error) {
            console.warn(`[didcomm/outbox] ${item.emailId} -> ${item.toDid}:`, error instanceof Error ? error.message : error)
            // Per-recipient, not per-batch: one unreachable fan-out target
            // (a group member whose mesh connection isn't up yet) must not
            // stall delivery to every OTHER recipient queued behind it in
            // this same flush pass (found live, 2026-09-03 -- this used to
            // `break`, which was harmless for 1:1's single-item queues but
            // wrong the moment a group message shares a flush pass with
            // multiple recipients).
            continue
          }
        }
      } finally {
        flushingDidComm = false
      }
    }

    configureCompose({
      selfAddress: mailFrom,
      // Same guard as configureComposePage's own selfDid: only claim a DID
      // identity once DIDComm is actually enabled.
      selfDid: identity.didCommKid && identity.didCommX25519PrivateKey ? identity.did : undefined,
      sendReply,
      onError: message => {
        showSysMsg(message)
        console.warn('[sendReply]', message)
      },
      // DIDComm group chat's own read-only counterpart -- membersOf/
      // groupName read straight from groupChatStore's device-local roster
      // cache (no server round trip, no invite operation: see
      // ComposeConfig.didcommGroup's own doc comment for why).
      didcommGroup: {
        membersOf: async groupId => (await groupChatStore.load(groupId))?.members ?? [],
        groupName: async groupId => (await groupChatStore.load(groupId))?.name,
      },
    })
    // Same commit-then-submit function as reply -- buildOutboundRfc5322
    // treats a missing inReplyTo/references as a fresh thread, so nothing
    // new-message-specific is needed here.
    configureComposePage({
      selfAddress: mailFrom,
      // Only offered as a From option once DIDComm is actually usable --
      // matches sendDidCommChat's own guard, so "From" never claims a DID
      // send is possible when it would immediately throw.
      selfDid: identity.didCommKid && identity.didCommX25519PrivateKey ? identity.did : undefined,
      sendMessage: sendReply,
      onError: message => {
        showSysMsg(message)
        console.warn('[sendMessage]', message)
      },
    })

    // Pulls any mail the core is holding for this device (SMTP listener ->
    // ingress store -> here), verifies+commits it into the vault as
    // message.add, ACKs it, then flushes the resulting vault-delivery pack
    // for sibling devices. Nothing called this before (2026-08-25, found
    // live: mail arrived at the core and sat in its ingress queue forever,
    // never once pulled by any client) -- reply/compose's send path and
    // maintainSelfGroup's catch-up never touched inbound mail at all.
    //
    // A single pulled batch can hold both protocols at once (the shared
    // IngressStore doesn't separate them) -- dispatched here by
    // envelope.protocol to whichever projector actually understands it,
    // same ingestIngress orchestration either way (that "Mail" in the name
    // predates DIDComm and is otherwise protocol-agnostic already, see
    // ingress-ingest.ts's own header).
    // Built here for the mediator-poll path (further down), which needs
    // "this identity's DIDComm ingress projector, if it has one" in more
    // than one branch; building two divergent copies is exactly the kind of
    // thing that quietly drifts apart.
    // Returns undefined once as freely as identity.didCommKid/
    // didCommX25519PrivateKey do -- an identity that hasn't enabled DIDComm
    // yet, or (not currently possible, but not asserted against either) had
    // it revoked mid-session.
    const resolveAnyDidCommSenderKey = (kid: string): Promise<Uint8Array> => {
      if (kid.startsWith('did:peer:2.')) {
        const did = kid.split('#', 1)[0]!
        return Promise.resolve(publicKeyOf(decodePeerDid2(did), kid))
      }
      return resolveDidCommSenderKey(kid)
    }

    const buildDidCommProjector = (): DidCommIngressProjector | undefined =>
      identity.didCommKid && identity.didCommX25519PrivateKey
        ? new DidCommIngressProjector({
            identityId: identity.did,
            actorDeviceId: identity.deviceKid!,
            resolveOwnKey: async kid => {
              if (kid === identity.didCommKid) return { kid, x25519PrivateKey: fromHex(identity.didCommX25519PrivateKey!) }
              const pending = pendingByOwnKid.get(kid)?.pending.peer
              if (pending) return { kid, x25519PrivateKey: pending.xPriv }
              const contact = await contactKeyReader.forOwnKid(kid)
              return contact ? { kid, x25519PrivateKey: contact.ownX25519PrivateKey } : null
            },
            resolveSenderKey: resolveAnyDidCommSenderKey,
            resolveCounterpartyDid: async kid => (await contactKeyReader.forCounterpartyKid(kid))?.counterpartyDid ?? null,
            // TODO(PLAN.md §6.1): always "not yet seen" -- there is no
            // committed-dedupe-id lookup wired to this projector yet. Not a
            // safety gap: message.add's own duplicate-emailId conflict
            // check (local-jmap/reducer.ts) still rejects a resent
            // basicmessage using the identical (senderKid, message id)
            // pair, just louder (a thrown/logged error here rather than a
            // quiet skip) than a real alreadyProcessed would be.
            async alreadyProcessed() { return false },
            nextActorSeq: () => sequencer.nextActorSeq(),
            initialParents: () => sequencer.initialParents(),
            activeSegment: () => boundary.activeSegment(),
            currentSnapshot: () => readModel.snapshot(),
            signer: boundary.signer,
          })
        : undefined

    // Used by the mediator-poll path's mail-bridge branch (onMessage,
    // further down): a mediator+mail-plugin instance's inbound-mail Forward
    // needs this projector. Kept as a builder (rather than one shared
    // instance) because it closes over `identity`, which enableDidComm
    // above can reassign.
    const buildMailProjector = (): MailIngressProjector => new MailIngressProjector({
      identityId: identity.did,
      actorDeviceId: identity.deviceKid!,
      nextActorSeq: () => sequencer.nextActorSeq(),
      initialParents: () => sequencer.initialParents(),
      activeSegment: () => boundary.activeSegment(),
      currentSnapshot: () => readModel.snapshot(),
      signer: boundary.signer,
    })


    // Independent, blind mediators (ARC.md's 2026-08-27 redesign): this
    // device registers directly with each one configured (self-heal on
    // every boot -- registerWithMediator's own note) and polls it on its
    // own cadence. A delivered message is bridged into the SAME
    // DidCommIngressProjector (built fresh per call -- didCommKid/
    // didCommX25519PrivateKey can't change mid-session today, but nothing
    // here assumes that) via the transport-neutral vault commit path, so it
    // lands in the vault without creating any transport-specific ingress
    // ACK; the resulting vault-delivery pack then syncs to sibling devices
    // through this identity's MIMI Vault room (mimi-vault-sync.ts), which
    // is the only multi-device sync transport left now that core is gone.
    if (identity.didCommKid && identity.didCommX25519PrivateKey) {
      const didCommKid = identity.didCommKid
      const own: DidCommSender = { did: identity.did, xKid: didCommKid, xPriv: fromHex(identity.didCommX25519PrivateKey) }

      // Inbound mail arrives as an ordinary DIDComm message -- Forward-
      // delivered by a mediator+mail-plugin instance, authcrypt'd from its
      // own persisted bridge identity to this identity's didCommKid
      // (mediator/mail-plugin/bridge.ts) -- through this SAME mediatorUrls
      // polling loop, not a mail-mediator-specific pickup loop.
      async function onMessage(msg: DeliveredMessage, recipientKid: string, mediatorUrl: string): Promise<void> {
        const plaintext = msg.plaintext as DidCommPlaintext
        if (plaintext.type === MAIL_BRIDGE_INBOUND) {
          const body = mailBridgeInboundBodyOf(plaintext)
          if (!body) throw new TypeError('mail bridge inbound message body is invalid')
          const envelope: IngressEnvelopeV1 = {
            version: 1,
            ingressId: canonicalHash('biset/mail-bridge-mediator-ingress/v1', { mediatorUrl, recipientKid, queueId: msg.ackId }),
            protocol: 'mail',
            recipientIdentityId: identity.did,
            recipientDeviceSnapshot: [identity.deviceKid!],
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
            transportMetadata: { smtpEnvelope: body.smtpEnvelope },
            sourceEvidence: new Uint8Array(0),
            protectedPayload: body.rawRfc5322,
            protectedPayloadHash: sha256Bytes(body.rawRfc5322),
          }
          await ingestTransportIngress(envelope, buildMailProjector(), vaultStore)
          await flushReplicationOutbox()
          await refreshInbox(readModel)
          void triggerMimiVaultSync?.()
          return
        }
        // DIDComm group chat (group-chat.ts) -- neither GROUP_INVITE nor
        // GROUP_MESSAGE carries Basic Message/relationship content, so both
        // must never reach the generic didCommProjector.verifyAndProject
        // below: it throws "unsupported DIDComm message type" for anything
        // outside its own allow-list (ping/basicmessage/relationship).
        if (plaintext.type === GROUP_INVITE || plaintext.type === GROUP_MESSAGE) {
          await handleDidCommGroupMessage(plaintext, msg.senderKid)
          return
        }
        const didCommProjector = buildDidCommProjector()
        if (!didCommProjector) return
        const payload = new TextEncoder().encode(JSON.stringify(msg.rawJwe))
        const envelope: IngressEnvelopeV1 = {
          version: 1,
          ingressId: canonicalHash('biset/didcomm-mediator-ingress/v1', { mediatorUrl, recipientKid, queueId: msg.ackId }),
          protocol: 'didcomm',
          recipientIdentityId: identity.did,
          recipientDeviceSnapshot: [identity.deviceKid!],
          createdAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
          transportMetadata: {},
          sourceEvidence: new Uint8Array(0),
          protectedPayload: payload,
          protectedPayloadHash: sha256Bytes(payload),
        }
        await ingestTransportIngress(envelope, didCommProjector, vaultStore)
        await flushReplicationOutbox()
        await handleRelationshipMessage(msg, recipientKid, mediatorUrl)
        await refreshInbox(readModel)
        void triggerMimiVaultSync?.()
      }

      // DIDComm group chat (group-chat.ts) -- full-mesh pairwise fan-out,
      // no MLS. Both control (GROUP_INVITE) and content (GROUP_MESSAGE)
      // arrive over the SAME established pairwise relationship channel
      // every ordinary 1:1 message does (send-message.ts's own note on
      // why), so this dispatches purely on `plaintext.type`, no separate
      // handshake state machine to track.
      async function handleDidCommGroupMessage(plaintext: DidCommPlaintext, senderKid: string): Promise<void> {
        if (plaintext.type === GROUP_INVITE) {
          const body = groupInviteBodyOf(plaintext)
          if (!body) throw new TypeError('DIDComm group invite body is invalid')
          await handleDidCommGroupInvite(body)
          return
        }
        const body = groupMessageBodyOf(plaintext)
        if (!body) throw new TypeError('DIDComm group message body is invalid')
        await handleDidCommGroupContent(plaintext, body, senderKid)
      }

      // Merges the invited roster locally, then mesh-completes: for every
      // listed member this device doesn't already hold a ContactKeyV1 for,
      // fires (not awaits serially) ensureDidCommContact -- awaiting each
      // one in turn here would stall every OTHER message queued behind
      // this one on the same mediator poll behind a per-member 60s
      // handshake budget. Idempotent on redelivery for free: `merge`
      // unions the same member set into itself (a no-op), and
      // ensureDidCommContact already no-ops for a member it's already
      // contacted or mid-handshake with.
      async function handleDidCommGroupInvite(body: GroupInviteBody): Promise<void> {
        const now = new Date().toISOString()
        await groupChatStore.merge(body.groupId, { members: body.members, ...(body.name ? { name: body.name } : {}), updatedAt: now })
        for (const member of body.members) {
          if (member === identity.did) continue
          ensureDidCommContact(member).catch(e => console.warn(`[didcomm-group/mesh] ${member}:`, e instanceof Error ? e.message : e))
        }
      }

      // Unknown groupId (the invite hasn't arrived yet, e.g. reordered
      // delivery): log and drop, don't buffer. A whole second piece of
      // durable state to replay-on-invite-arrival isn't worth it for a v1
      // feature that already accepts coarser gaps (no cross-device roster
      // sync at all) -- the cost is bounded to the one reordered message;
      // every later message to this group succeeds normally once the
      // invite lands.
      async function handleDidCommGroupContent(plaintext: DidCommPlaintext, body: GroupMessageBody, senderKid: string): Promise<void> {
        const senderDid = await resolveDidCommSenderDid(senderKid, kid => contactKeyReader.forCounterpartyKid(kid).then(c => c?.counterpartyDid ?? null))
        if (!senderDid) throw new TypeError('DIDComm group message sender is not associated with a counterparty')
        const roster = await groupChatStore.load(body.groupId)
        if (!roster) {
          console.warn(`[didcomm-group] message for unknown group ${body.groupId} from ${senderDid} -- dropping (invite has not arrived yet)`)
          return
        }
        const createdAt = new Date().toISOString()
        const sentAt = body.sentAt ?? (plaintext.created_time ? new Date(plaintext.created_time * 1000).toISOString() : createdAt)
        const record = await buildDidCommGroupMessageVaultRecord({
          content: body.content, emailId: didCommMessageDedupeId(senderKid, plaintext.id), groupId: body.groupId, senderDid,
          otherMembers: roster.members.filter(m => m !== senderDid), receivedAt: createdAt, sentAt,
          ...(body.subject ? { subject: body.subject } : {}),
        }, {
          identityId: identity.did, actorDeviceId: deviceKid,
          nextActorSeq: () => sequencer.nextActorSeq(), initialParents: () => sequencer.initialParents(),
          activeSegment: () => boundary.activeSegment(), currentSnapshot: () => readModel.snapshot(), signer: boundary.signer,
        })
        await vaultStore.commitLocalMutation({ identityId: identity.did, ...record })
        await flushReplicationOutbox()
        await refreshInbox(readModel)
      }

      async function handleRelationshipMessage(msg: DeliveredMessage, recipientKid: string, mediatorUrl: string): Promise<void> {
        const plaintext = msg.plaintext as DidCommPlaintext
        if (plaintext.type !== RELATIONSHIP_INIT && plaintext.type !== RELATIONSHIP_ACCEPT) return
        const body = relationshipBodyOf(plaintext)
        if (!body) throw new TypeError('relationship message body is invalid')
        const route = relationshipMediatorService(body.relationshipKid)
        if (route.url !== mediatorUrl) throw new TypeError('relationship mediator does not match the delivery route')

        if (plaintext.type === RELATIONSHIP_INIT) {
          if (msg.senderKid.startsWith('did:peer:2.')) throw new TypeError('relationship init must be authenticated by a public front-door kid')
          const counterpartyDid = didOfKid(msg.senderKid)
          let contact = await contactKeyReader.currentFor(counterpartyDid)
          if (!contact || contact.counterpartyRelationshipKid !== body.relationshipKid) {
            const peer = generatePeerIdentity({ uri: route.url, routingKeys: [route.routingKid] })
            await registerWithMediator(route.url, { did: peer.did, xKid: peer.xKid, xPriv: peer.xPriv })
            const next: ContactKeyV1 = {
              version: 1,
              kind: 'contact-key',
              identityId: identity.did,
              counterpartyDid,
              ownRelationshipKid: peer.xKid,
              ownX25519PrivateKey: peer.xPriv,
              ownEd25519PrivateKey: peer.edPriv,
              counterpartyRelationshipKid: body.relationshipKid,
              counterpartyPublicKey: body.publicKey,
              createdAt: new Date().toISOString(),
              ...(contact ? { supersedesKid: contact.ownRelationshipKid } : {}),
            }
            await contactKeySink.store(next)
            contact = next
            await flushReplicationOutbox()
            startRelationshipPoll(peer.xKid, peer.xPriv, peer.did, route.url)
          }
          const accepted = await sendRelationshipAccept(contact)
          if (!accepted.ok) throw new Error(accepted.error)
          return
        }

        if (body.relationshipKid !== msg.senderKid) throw new TypeError('relationship accept body does not match its authenticated sender')
        const pending = pendingByOwnKid.get(recipientKid)
        if (!pending) {
          const existing = await contactKeyReader.forOwnKid(recipientKid)
          if (existing?.counterpartyRelationshipKid === body.relationshipKid) return
          throw new Error('relationship accept has no pending initiation')
        }
        const contact: ContactKeyV1 = {
          version: 1,
          kind: 'contact-key',
          identityId: identity.did,
          counterpartyDid: pending.pending.counterpartyDid,
          ownRelationshipKid: pending.pending.peer.xKid,
          ownX25519PrivateKey: pending.pending.peer.xPriv,
          ownEd25519PrivateKey: pending.pending.peer.edPriv,
          counterpartyRelationshipKid: body.relationshipKid,
          counterpartyPublicKey: body.publicKey,
          createdAt: new Date().toISOString(),
        }
        await contactKeySink.store(contact)
        await flushReplicationOutbox()
        pendingByOwnKid.delete(recipientKid)
        pendingByCounterparty.delete(pending.pending.counterpartyDid)
        pending.resolve(contact)
      }

      startRelationshipPoll = (xKid: string, xPriv: Uint8Array, did: string, mediatorUrl: string): void => {
        if (relationshipPollKids.has(xKid)) return
        relationshipPollKids.add(xKid)
        const relationshipOwn: DidCommSender = { did, xKid, xPriv }
        const watch = watchMediator({
          mediatorUrl, own: relationshipOwn, resolveSenderKey: resolveAnyDidCommSenderKey,
          onMessage: msg => onMessage(msg, xKid, mediatorUrl),
          onError: e => console.warn(`[didcomm] watch of ${mediatorUrl} lost (reconnecting):`, e instanceof Error ? e.message : e),
        })
        mediatorPollHandles.push({ stop: () => watch.close() })
      }

      // SSE live delivery (mediator-watch.ts), not the old startMediatorPolling
      // loop -- found live, 2026-09-01: Conversation Group's 3-message invite
      // handshake crosses this loop three times, so its 15s poll interval
      // compounded into tens of seconds of pure waiting before a group's
      // founding message could even be sent. This mediator is a biset-run
      // deploy unit (mediator-watch.ts's own header), so a live-push
      // extension on top of its otherwise spec-compliant Pickup 3.0 surface
      // costs nothing a poll-tolerant remote mediator would have needed.
      for (const url of mediatorUrls) {
        const watch = watchMediator({
          mediatorUrl: url, own, resolveSenderKey: resolveAnyDidCommSenderKey,
          onMessage: msg => onMessage(msg, didCommKid, url),
          onError: e => console.warn(`[didcomm] watch of ${url} lost (reconnecting):`, e instanceof Error ? e.message : e),
        })
        mediatorPollHandles.push({ stop: () => watch.close() })
      }

      // TODO(mail-plugin bridge redesign): inbound mail no longer needs its
      // own bind/poll loop here -- it arrives via the SAME mediatorUrls
      // polling loop above (a mediator+mail-plugin instance Forwards it in
      // as an ordinary DIDComm message to this identity's own didCommKid).
      const knownContactKeys = await contactKeyReader.readAll().catch(e => {
        console.warn('[relationship] could not restore contact keys:', e instanceof Error ? e.message : e)
        return []
      })
      const counterparties = new Set(knownContactKeys.map(contact => contact.counterpartyDid))
      for (const counterpartyDid of counterparties) {
        const contact = await contactKeyReader.currentFor(counterpartyDid).catch(e => {
          console.warn(`[relationship] current key for ${counterpartyDid} is ambiguous:`, e instanceof Error ? e.message : e)
          return null
        })
        if (!contact) continue
        const route = relationshipMediatorService(contact.ownRelationshipKid)
        const ownDid = contact.ownRelationshipKid.split('#', 1)[0]!
        startRelationshipPoll(contact.ownRelationshipKid, contact.ownX25519PrivateKey, ownDid, route.url)
      }
      await flushDidCommTransportOutbox().catch(e => {
        console.warn('[didcomm/outbox/boot]', e instanceof Error ? e.message : e)
      })
    }
  }

  showApp()
  await refreshInbox(readModel).catch(e => {
    showSysMsg('Could not load the inbox')
    console.warn('[refreshInbox]', e instanceof Error ? e.message : e)
  })
  // Nothing pulls again after this until the page is reloaded otherwise --
  // there is no push here (PLAN.md §6.1 explicitly leaves DIDComm push out
  // of scope), but a plain periodic pull is a different, much simpler thing
  // that was just never wired as a recurring loop, only this one boot-time
  // call. Found live, 2026-08-25: a message sent between two open sessions
  // only showed up "a long time later" -- actually whenever something else
  // happened to trigger a reboot, not because of any real delay. (Any prior
  // interval was already cleared at the top of this function.)
  if (flushDidCommTransportOutbox) {
    const flushDidComm = flushDidCommTransportOutbox
    pollTimer = setInterval(() => {
      flushDidComm().then(() => refreshInbox(readModel)).catch(e => console.warn('[didcomm/outbox/poll]', e instanceof Error ? e.message : e))
    }, 10_000)
  }

  if (mimiVaultConfigured && identity.deviceKid) {
    // Self/Vault traffic is a normal-mode MIMI room on its isolated provider.
    // There is deliberately no Anchor/OIDC token here: membership plus the
    // MLS leaf signature authenticate every request. Already ensured once,
    // early in this function, before buildVaultCryptoBoundary/enableDidComm
    // needed it to exist -- this second call is then just a fast local read
    // plus a best-effort routing-publish retry (ensureMimiVaultRoom's own
    // doc comment).
    const { credential, signaturePrivateKey, room, transport } = mimiVaultRoom ?? await ensureMimiVaultRoom(identity, selfGroupStore, mimiSelfBaseUrl)
    const mlsCredential = ownMlsDeviceCredential(room.state)
    const session = new PersistedMimiVaultSession({
      identityId: identity.did, mode: 'self', transport, stateStore: selfGroupStore,
      credential: { kind: 'visible', user: identity.did, client: identity.deviceKid, credential: encodeMlsDeviceCredential(mlsCredential), signaturePublicKey: mlsCredential.signaturePublicKey },
      sign: bytes => ed25519.sign(bytes, ownSignaturePrivateKey(room!.state)),
    })
    const boundary = buildVaultCryptoBoundary(vaultStore, vaultStore, selfGroupStore, identity)
    const projector = buildVaultDeliveryProjector(selfGroupStore, identity.did, () => readModel.snapshot(), identity.masterSeed)
    // Debounces checkpoint auto-recreation (below) across THIS device's own
    // back-to-back sync rounds. Live SSE pushes (mimi-vault-watch.ts) mean
    // every sibling device now reacts to a change within milliseconds
    // instead of waiting out a 10s poll -- multiple devices independently
    // noticing "no checkpoint in this batch" and racing to recreate their
    // own, all within the same few seconds, was found live 2026-09-02 to
    // scramble sender-ratchet generation ordering across the resulting
    // burst of near-simultaneous submissions ("Desired gen in the past",
    // permanently losing whichever message a receiver processed out of
    // order). A cooldown does not make the race impossible -- two devices
    // can still both be first through the gate right as it reopens -- but
    // makes the common case (this device's OWN sync loop reacting to a
    // cascade of pushes from ITS OWN prior recreation, plus a sibling doing
    // the same) far less likely to collide.
    let lastCheckpointRecreateAt = 0
    // Surfaces account-page.ts's "Checkpoint" detail row, which the MIMI
    // branch never populated at all (only the legacy coordinator path's own
    // synchronizeStreamOnce ever set VaultCardStatus.checkpointSeq) --
    // showed a permanent "—" regardless of whether checkpoints were
    // actually working (found live, 2026-09-02: they were, this was purely
    // a missing wire, not a functional gap). Not the same as localSeq
    // (vaultStore's own delivery cursor, which keeps advancing past
    // whatever a checkpoint restore set it to as ordinary events get
    // ingested afterward) -- this tracks specifically the most recent
    // checkpoint this device has itself either restored or created, in
    // memory only (there is no persisted "last checkpoint" field to read
    // this back from, so it resets on reload; that matches every other
    // Vault card field, which is also live-session-only).
    let lastKnownCheckpointSeq: string | undefined
    const synchronizeMimi = async (): Promise<void> => {
      setVaultCard({ state: 'syncing', coordinatorUrl: mimiSelfBaseUrl, vaultId: room!.roomId as never, detail: 'Synchronizing encrypted MIMI Vault' })
      // Provider sequence is separate from the Vault event cursor.  Keep it
      // with the encrypted MLS state so historical commits/checkpoints are
      // not replayed on every ten-second poll.
      const beforeSync = await selfGroupStore.loadMimiVault(identity.did)
      const providerCursor = beforeSync?.deliveryCursor ?? 0
      const pull = (value: DeliveriesPullRequest) => transport.pullDeliveries('self', value)
      const signPull = (unsigned: Omit<DeliveriesPullRequest, 'signature'>) => ed25519.sign(deliveriesPullSigningBytes(unsigned), ownSignaturePrivateKey(room!.state))
      const pullRequestBase = (): Omit<DeliveriesPullRequest, 'afterSeq' | 'signature'> => ({ version: 1, roomId: room!.roomId, requester: { kind: 'visible', user: identity.did, client: identity.deviceKid!, credential: encodeMlsDeviceCredential(ownMlsDeviceCredential(room!.state)), signaturePublicKey: ownMlsDeviceCredential(room!.state).signaturePublicKey }, requestedAt: new Date().toISOString() })
      const result = await synchronizeMimiVault({
        pull, signPull, pullRequest: pullRequestBase(),
        receiver: session, outbox: vaultStore, sender: session, identityId: identity.did,
        afterSeq: providerCursor,
        ingest: async (payload, seq) => { await ingestVaultDelivery({ version: 1, identityId: identity.did, seq, payload, payloadHash: sha256Bytes(payload), createdAt: new Date().toISOString(), expiresAt: '9999-12-31T23:59:59.999Z' }, boundary.signer, projector, vaultStore) },
        restoreCheckpoint: async checkpoint => {
          if (!identity.masterSeed) throw new Error('MIMI Vault checkpoint restore requires the identity master seed')
          const localCursor = await vaultStore.readDeliveryCursor(identity.did, identity.deviceKid!)
          // An older manifest is still valid ciphertext, but it cannot add
          // anything after a newer Vault checkpoint is already restored.
          if (BigInt(checkpoint.manifest.coveredSeq) <= BigInt(localCursor)) return
          const snapshot = await openPortableCoordinatorCheckpoint(fromHex(identity.masterSeed), checkpoint.payload, { vaultId: room!.roomId as never, coveredSeq: deliverySeq(BigInt(checkpoint.manifest.coveredSeq)), coordinatorUrl: mimiSelfBaseUrl })
          try {
            if (snapshot.identityId !== identity.did) throw new Error('MIMI Vault checkpoint belongs to another identity')
            const records = await rewrapRecoveryArchiveForCurrentEpoch(snapshot, boundary.epochs, boundary.signer, new Date().toISOString())
            await vaultStore.commitRecoveryArchive({ identityId: identity.did, events: records.events, objects: records.objects.map(object => ({ ...object, identityId: identity.did })), keyWraps: records.keyWraps })
            for (const segment of snapshot.segmentKeys) await vaultStore.sealAndActivateSegment({ identityId: identity.did, segmentId: segment.segmentId, segmentKey: segment.key, selfGroupId: VAULT_STORAGE_GROUP_ID, epoch: VAULT_STORAGE_EPOCH, sealed: false, createdAt: snapshot.createdAt })
            const projection = await buildLocalJmapProjectionRebuild(vaultStore, vaultStore, vaultStore, selfGroupStore, identity.did, identity.masterSeed)()
            await vaultStore.advanceDeliveryCursor(identity.did, identity.deviceKid!, deliverySeq(BigInt(checkpoint.manifest.coveredSeq)), projection.state, new Date().toISOString())
            lastKnownCheckpointSeq = String(checkpoint.manifest.coveredSeq)
          } finally { for (const segment of snapshot.segmentKeys) segment.key.fill(0) }
        },
      })
      // synchronizeMimiVault itself never throws -- an outbox-flush failure
      // comes back as a `gaps` entry like every other kind of loss, so this
      // device's own send retries next poll instead of wedging (mimi-vault-
      // sync.ts's own doc comment). This callsite still surfaces it as an
      // error state the same way an exception used to, matching the
      // previous behavior (deliveryCursor/refreshInbox/checkpoint-recreate
      // below never ran on this path before either).
      const outboxFlushFailure = result.gaps.find(gap => gap.kind === 'outbox-flush-failed')
      if (outboxFlushFailure) throw new Error(`MIMI Vault outbox append failed: ${outboxFlushFailure.detail}`)
      if (result.latestSequence > providerCursor) {
        const current = await selfGroupStore.loadMimiVault(identity.did)
        if (!current) throw new Error('MIMI Vault state disappeared while synchronizing')
        await selfGroupStore.saveMimiVault(identity.did, { ...current, deliveryCursor: result.latestSequence })
      }
      // A successful checkpoint restore (below) populates vault_objects/
      // vault_events directly via commitRecoveryArchive +
      // buildLocalJmapProjectionRebuild -- it never touches
      // ingestedSequences (that only counts the ordinary per-message
      // ingest loop) and never called refreshInbox itself either, so a
      // device recovering its ENTIRE history through a checkpoint restore
      // alone (no ordinary deliveries in the same round) had that history
      // sitting correctly in IndexedDB with nothing on screen to show for
      // it (found live, 2026-09-03: a device recovered via a fresh
      // checkpoint after this session's own chunk/manifest-correlation
      // fix, synced a brand-new message fine, but every message from
      // before stayed invisible until an unrelated reload).
      if (result.ingestedSequences.length || result.checkpoints.length) await refreshInbox(readModel)
      // `result.gaps.length === 0` guards against a device whose OWN local
      // Vault is incomplete this round (an undecryptable entry, a failed
      // ingest, a still-unreconstructed checkpoint...) confidently
      // publishing a checkpoint anyway -- it would be checkpointing content
      // it itself never fully received, and a sibling restoring from that
      // checkpoint loses whatever this device silently skipped, discarding
      // real history nobody actually lost (found live, 2026-09-02: exactly
      // this, root-caused via a side-by-side comparison of two devices'
      // actual message histories after PLAN-SIMPIFY.md's `gaps` reporting
      // made the condition expressible at all -- deferred until then rather
      // than patched in as an ad hoc boolean).
      if (result.latestSequence > 1 && !result.sawCheckpointManifest && result.gaps.length === 0 && identity.masterSeed && Date.now() - lastCheckpointRecreateAt > 5_000) {
        lastCheckpointRecreateAt = Date.now()
        const snapshot = await createRecoveryArchiveSnapshot(vaultStore, boundary.resolver, identity.did, new Date().toISOString())
        try {
          const payload = await createPortableCoordinatorCheckpoint(fromHex(identity.masterSeed), snapshot, { vaultId: room!.roomId as never, coveredSeq: deliverySeq(BigInt(result.latestSequence)) })
          let published = true
          try {
            await sendMimiVaultCheckpoint(payload, result.latestSequence, session)
            lastKnownCheckpointSeq = String(result.latestSequence)
          } catch (error) {
            // A sibling device's own checkpoint can land between this
            // device's pull and its own manifest submission -- the hub
            // deliberately rejects a redundant/stale one with 409 conflict
            // (mimi/store.ts's submitVaultCheckpoint) rather than silently
            // overwriting a fresher checkpoint someone else just published.
            // That is the intended outcome of the race, not a failure: this
            // device's own next ordinary pull already picks up whichever
            // checkpoint the hub kept, same as always -- nothing here needs
            // fixing (found live, 2026-09-02: surfaced as a bare "MIMI
            // request failed (409)" error state on every debounce-quieted
            // sync that happened to lose this race, even though sync
            // itself had already succeeded moments before).
            if (!(error instanceof Error) || !error.message.includes('conflict')) throw error
            console.info('[mimi-vault/checkpoint] a sibling device already published a fresher checkpoint, skipping')
            published = false
          }
          if (published) {
          // The checkpoint's own chunk+manifest just landed at new sequence
          // numbers `synchronizeMimiVault` above never saw (it pulled and
          // computed `result.latestSequence` BEFORE this checkpoint existed),
          // so the delivery cursor saved above does not cover them yet. Left
          // alone, the NEXT sync re-pulls from that stale cursor, and this
          // device recognizes its own just-sent checkpoint chunk as an echo
          // (PersistedMimiVaultSession's ownApplicationHashes) and silently
          // drops it from decode -- while the checkpoint manifest itself is
          // still decoded normally, so `decodeMimiVaultBatch` finds a
          // manifest with no matching chunks and throws "Vault checkpoint
          // chunks are incomplete", forever, on every sync from here on
          // (found live, 2026-09-02). A raw pull (no decode, just sequence
          // numbers -- this device already has this checkpoint's plaintext
          // in `snapshot` above, no need to reconstruct it from chunks) is
          // enough to learn how far to advance past it.
          const afterCheckpoint = await pullMimiVaultPages(pull, signPull, pullRequestBase(), result.latestSequence)
          const newLatest = afterCheckpoint.reduce((max, entry) => Math.max(max, entry.seq), result.latestSequence)
          if (newLatest > result.latestSequence) {
            const current = await selfGroupStore.loadMimiVault(identity.did)
            if (current) await selfGroupStore.saveMimiVault(identity.did, { ...current, deliveryCursor: newLatest })
          }
          }
        } finally { for (const segment of snapshot.segmentKeys) segment.key.fill(0) }
      }
      setVaultCard({ state: 'connected', coordinatorUrl: mimiSelfBaseUrl, vaultId: room!.roomId as never, localSeq: String(await vaultStore.readDeliveryCursor(identity.did, identity.deviceKid!)), latestSeq: String(result.latestSequence), ...(lastKnownCheckpointSeq === undefined ? {} : { checkpointSeq: lastKnownCheckpointSeq }), detail: 'Encrypted MIMI Vault is current' })
    }
    // A hung underlying fetch (no timeout of its own -- MimiClientTransport
    // never had one) would otherwise leave a round of sync stuck forever:
    // the UNGUARDED initial call below would never let bootClient reach the
    // interval registration at all, and a hang inside the interval's own
    // tick would leave `mimiPollBusy` wedged true, so every later tick's
    // `if (mimiPollBusy) return` then silently no-ops, permanently, with no
    // error ever logged -- exactly what "an initial reload-triggered
    // catch-up eventually works, but nothing new arrives after that" looks
    // like from outside (found live, 2026-09-02). Racing against a timeout
    // can't cancel the stuck fetch itself, but it unblocks THIS code so the
    // next attempt (the interval's next tick) gets a fresh try instead of
    // finding everything wedged on.
    const runMimiSync = (): Promise<void> => {
      const timeout = new Promise<never>((_, reject) => setTimeout(() => reject(new Error('MIMI Vault sync timed out')), 25_000))
      return Promise.race([synchronizeMimi(), timeout]).catch(error => {
        const detail = error instanceof Error ? error.message : String(error)
        setVaultCard({ state: 'error', coordinatorUrl: mimiSelfBaseUrl, vaultId: room!.roomId as never, detail })
        console.warn('[mimi-vault/poll]', detail)
      })
    }
    let mimiPollBusy = false
    const runMimiSyncNow = (): Promise<void> => {
      if (mimiPollBusy) return Promise.resolve()
      mimiPollBusy = true
      return runMimiSync().finally(() => { mimiPollBusy = false })
    }
    // Lets a just-committed local send (this device's own reply/DIDComm
    // chat, or a just-relayed inbound message this device is passing on to
    // its siblings) reach the hub immediately, instead of waiting out
    // whatever was left of a polling interval.
    triggerMimiVaultSync = runMimiSyncNow
    await runMimiSyncNow()
    // Polling replaced with a live SSE subscription (mimi-vault-watch.ts,
    // same shape as the now-retired Conversation Group's own `watch`) --
    // this closes the OTHER half of cross-device latency triggerMimiVaultSync
    // above does not (that one only speeds up THIS device's own sends; a
    // sibling device still needed to wait out its own next poll tick to
    // notice anything, up to 10s, found live 2026-09-02 to be the entire
    // remaining gap). `onEntry` never processes the pushed entry itself --
    // it only wakes runMimiSyncNow, which re-runs the existing, already
    // hardened pull-based pipeline (checkpoint collation, epochTooOld
    // retry, the permanently-undecryptable skip, sentAt-agnostic identity
    // merge).
    //
    // Debounced, not immediate: a checkpoint's chunk(s) and its manifest are
    // separate, sequential HTTP submissions (sendMimiVaultCheckpoint), never
    // atomic -- reacting to the FIRST push in that sequence used to pull
    // mid-submission, see an application chunk with no manifest yet in this
    // same batch, and (correctly, per decodeMimiVaultBatch's own claiming
    // logic) treat it as an ordinary delivery, which then failed to parse
    // as one ("vault delivery pack header is invalid", found live,
    // 2026-09-02, even with the earlier checkpoint-recreation cooldown
    // already in place -- that one only reduces how often MULTIPLE devices
    // race each other, not the inherent multi-step-submission window a
    // SINGLE device's own checkpoint always has). Resetting this timer on
    // every push and only syncing once pushes have been quiet for a beat
    // lets one sender's own multi-step submission finish landing before
    // anyone reacts -- still a large win over the 10s polling this
    // replaced, just not literally instant.
    let watchDebounceTimer: ReturnType<typeof setTimeout> | undefined
    const watchCursor = await selfGroupStore.loadMimiVault(identity.did).then(stored => stored?.deliveryCursor ?? 0)
    mimiVaultWatchHandle = watchMimiVaultDeliveries({
      transport, roomId: room.roomId,
      requester: { kind: 'visible', user: identity.did, client: identity.deviceKid, credential: encodeMlsDeviceCredential(mlsCredential), signaturePublicKey: mlsCredential.signaturePublicKey },
      sign: bytes => ed25519.sign(bytes, ownSignaturePrivateKey(room!.state)),
      afterSeq: watchCursor,
      onEntry: () => {
        if (watchDebounceTimer !== undefined) clearTimeout(watchDebounceTimer)
        watchDebounceTimer = setTimeout(() => { watchDebounceTimer = undefined; void runMimiSyncNow() }, 1_500)
      },
      onError: error => console.warn('[mimi-vault/watch]', error instanceof Error ? error.message : error),
    })
  }
}

/** Keeps the initial public API explicit while account routing is implemented. */
export function accountKind(session: AccountSession): AccountSession['kind'] {
  return session.kind
}

bootClient()
