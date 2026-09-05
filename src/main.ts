import type { AccountSession } from './local-jmap/transport.ts'
import {
  buildActorSequencer,
  buildLocalJmapReadModel,
  buildRestoreTransferVerifier,
  buildVaultDeliveryProjector,
  buildWalletVaultCryptoBoundary,
  ensureWalletMimiVaultRoom,
  repairCurrentLocalSegmentKeyWraps,
} from './identity/bootstrap.ts'
import { IndexedDbMlsSelfGroupStore } from './mls/store.ts'
import { IndexedDbVaultStore } from './vault/store.ts'
import { setOnWalletConnected } from './ui/account-create.ts'
import {
  beginDidMdWalletMessagingEnrollment,
  disconnectDidMdWallet,
  openDidMdWalletBisetDidCommDevice,
  openDidMdWalletBisetDevice,
  restoreDidMdWalletSession,
} from './wallet/did-md-oauth.ts'
import { refreshInbox, showApp, showSysMsg } from './ui/shell.ts'
import { configureCompose } from './ui/thread.ts'
import type { ReplySendInput } from './ui/thread.ts'
import { configureAccountPage, showAccountPage, updateVaultCardStatus, type VaultCardStatus } from './ui/account-page.ts'
import { configureComposePage } from './ui/compose-page.ts'
import { readBisetConfig } from './ui/config.ts'
import { VaultBackedLocalJmapMutationSink } from './local-jmap/vault-mutation-sink.ts'
import { DidCommIngressProjector } from './didcomm/ingress-projector.ts'
import { resolveDidCommSenderKey } from './didcomm/webvh-resolve.ts'
import { sendRelationshipMessage } from './didcomm/send-message.ts'
import { didCommThreadId } from './didcomm/basicmessage.ts'
import { isProjectableDidCommIngress } from './didcomm/ingress-projector.ts'
import { registerWithMediator, type MediatorPollHandle } from './didcomm/mediator-sync.ts'
import { watchMediator } from './didcomm/mediator-watch.ts'
import type { DidCommSender } from './didcomm/mediator-transport.ts'
import type { DeliveredMessage } from './didcomm/mediator-pickup.ts'
import { ingestTransportIngress } from './vault/ingress-ingest.ts'
import type { IngressEnvelopeV1 } from './shared/protocol/ingress.ts'
import { canonicalHash, sha256Bytes } from './shared/protocol/canonical.ts'
import { memberKids } from './mls/group.ts'
import { encodeMlsDeviceCredential } from './mls/device-credential.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import { ContactKeyReader } from './vault/contact-key-reader.ts'
import { ContactKeyVaultSink } from './vault/contact-key-sink.ts'
import type { ContactKeyV1 } from './vault/contact-key.ts'
import { decodePeerDid2, publicKeyOf } from './didcomm/peer.ts'
import { relationshipMediatorService } from './didcomm/relationship.ts'
import type { DidCommPlaintext } from './didcomm/message.ts'
import { ingestVaultDelivery } from './vault/delivery-ingest.ts'
import { MimiClientTransport } from './mls/mimi-client-transport.ts'
import { PersistedMimiVaultSession } from './mls/mimi-vault-session.ts'
import { watchMimiVaultDeliveries } from './mls/mimi-vault-watch.ts'
import { removeMimiVaultDevice } from './mls/mimi-vault-room.ts'
import { synchronizeMimiVault } from './vault/mimi-vault-sync.ts'
import type { DeliveriesPullRequest } from './mimi/protocol-types.ts'
import { deliveriesPullSigningBytes } from './mimi/authorizer.ts'
import {
  createWalletRelationshipManager,
  type RelationshipWatchStarter,
  type WalletRelationshipManager,
} from './wallet/relationship.ts'

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
setOnWalletConnected(async () => {
  await bootClient()
  showAccountPage()
})

// Every IndexedDB database this app opens, device-local and meaningless
// without an owning account. Cleared by bootClient()'s own no-account
// branch below (silent, defensive: a Wallet disconnect, a crash mid-login,
// a corrupted store, or any other path that reaches "no account" would
// otherwise leave this device's stores stale/orphaned indefinitely, with no
// way for an end user to notice or clear them -- found live, 2026-09-04, on
// a device stuck rendering the zero-identity page with unrelated console
// silence). Deleting a database with zero rows is a fast no-op, so running
// this on every ordinary fresh-install boot costs nothing.
const ALL_LOCAL_DATABASE_NAMES = [
  'biset-identity', 'biset-mls-keypackages', 'biset-mls-self-group',
  'biset-vault-core', 'biset-didcomm-group-chat',
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

// A Vault sync round that never settles would leave its caller's busy flag
// set for the rest of the page's life, and every later tick returns early on
// that flag -- found live 2026-09-02, when a hung fetch wedged polling until
// reload. Both account paths race their round against this budget so the
// NEXT tick gets a fresh try instead of finding everything stuck.
//
// The timer is cleared once the race settles. Without that, a round that
// finishes in a second still holds a pending 25s timer, one per tick, and
// the poll interval is shorter than the budget -- so they accumulate.
const VAULT_SYNC_TIMEOUT_MS = 25_000

function withVaultSyncTimeout<T>(work: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('MIMI Vault sync timed out')), VAULT_SYNC_TIMEOUT_MS)
  })
  return Promise.race([work, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer)
  })
}

function resolveAnyDidCommSenderKey(kid: string): Promise<Uint8Array> {
  if (kid.startsWith('did:peer:2.')) {
    const did = kid.split('#', 1)[0]!
    return Promise.resolve(publicKeyOf(decodePeerDid2(did), kid))
  }
  return resolveDidCommSenderKey(kid)
}

function updateRememberedVaultCard(
  next: VaultCardStatus,
  options: {
    current: () => VaultCardStatus | undefined
    remember: (status: VaultCardStatus) => void
    normalize?: (status: VaultCardStatus) => VaultCardStatus
    skipEqual?: boolean
  },
): void {
  const status = options.normalize ? options.normalize(next) : next
  if (options.skipEqual && options.current() && JSON.stringify(options.current()) === JSON.stringify(status)) return
  options.remember(status)
  updateVaultCardStatus(status)
}

function startRelationshipWatch(
  watchedKids: Set<string>, mediatorUrl: string, own: DidCommSender,
  resolveSenderKey: (kid: string) => Promise<Uint8Array>,
  onMessage: (message: DeliveredMessage) => Promise<void>,
  onError: (error: unknown) => void,
): void {
  if (watchedKids.has(own.xKid)) return
  watchedKids.add(own.xKid)
  const watch = watchMediator({ mediatorUrl, own, resolveSenderKey, onMessage, onError })
  mediatorPollHandles.push({ stop: () => watch.close() })
}

async function restoreRelationshipWatches(
  reader: { readAll(): Promise<ContactKeyV1[]>; currentFor(counterpartyDid: string): Promise<ContactKeyV1 | null> },
  startWatch: RelationshipWatchStarter,
  onReadAllError?: (error: unknown) => void,
  onCurrentError?: (counterpartyDid: string, error: unknown) => void,
): Promise<void> {
  let knownContacts: ContactKeyV1[]
  try {
    knownContacts = await reader.readAll()
  } catch (error) {
    if (!onReadAllError) throw error
    onReadAllError(error)
    return
  }
  const counterparties = new Set(knownContacts.map(contact => contact.counterpartyDid))
  for (const counterpartyDid of counterparties) {
    let contact: ContactKeyV1 | null
    try {
      contact = await reader.currentFor(counterpartyDid)
    } catch (error) {
      if (!onCurrentError) throw error
      onCurrentError(counterpartyDid, error)
      continue
    }
    if (!contact) continue
    const route = relationshipMediatorService(contact.ownRelationshipKid)
    startWatch(contact.ownRelationshipKid, contact.ownX25519PrivateKey, contact.ownRelationshipKid.split('#', 1)[0]!, route.url)
  }
}

function didCommMediatorIngressEnvelope(
  label: string, mediatorUrl: string, recipientKid: string, queueId: string,
  recipientIdentityId: IngressEnvelopeV1['recipientIdentityId'],
  recipientDeviceId: IngressEnvelopeV1['recipientDeviceSnapshot'][number],
  rawJwe: unknown,
): IngressEnvelopeV1 {
  const protectedPayload = new TextEncoder().encode(JSON.stringify(rawJwe))
  return {
    version: 1,
    ingressId: canonicalHash(label, { mediatorUrl, recipientKid, queueId }),
    protocol: 'didcomm',
    recipientIdentityId,
    recipientDeviceSnapshot: [recipientDeviceId],
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    transportMetadata: {},
    sourceEvidence: new Uint8Array(0),
    protectedPayload,
    protectedPayloadHash: sha256Bytes(protectedPayload),
  }
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
  let walletRelationshipManager: WalletRelationshipManager | undefined
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
      updateRememberedVaultCard(next, {
        current: () => vault,
        remember: status => { vault = status },
      })
    }
    const runWalletVaultSyncOnce = async (): Promise<void> => {
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
      }
    }
    // A hung underlying fetch (no timeout of its own -- MimiClientTransport
    // never had one) would otherwise leave a round of sync stuck forever:
    // `syncBusy` stays wedged true, so every later trigger's
    // `if (syncBusy) return` then silently no-ops, permanently, with no
    // error ever logged -- exactly what "an initial reload-triggered
    // catch-up eventually works, but nothing new arrives after that" looks
    // like from outside (found live on the local-identity path, 2026-09-02,
    // whose runMimiSync carries the same guard for the same reason). Racing
    // against a timeout can't cancel the stuck fetch itself, but it unblocks
    // THIS code so the next trigger (an SSE wake-up, or the next interactive
    // action) gets a fresh try instead of finding everything wedged on.
    let syncBusy = false
    const synchronizeWalletVault = async (): Promise<void> => {
      if (syncBusy) return
      syncBusy = true
      try {
        await withVaultSyncTimeout(runWalletVaultSyncOnce())
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error)
        setWalletVaultStatus({
          state: 'error', coordinatorUrl: mimiSelfBaseUrl, vaultId: ensured.room.roomId as never, devices: members, detail,
        })
        console.warn('[did.md Wallet MIMI Vault sync]', detail)
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
        const walletDidCommProjector = new DidCommIngressProjector({
          identityId: device.did,
          actorDeviceId: device.credential.deviceKid,
          resolveOwnKey: async kid => {
            if (kid === didCommDevice.xKid) return { kid, x25519PrivateKey: didCommDevice.x25519PrivateKey }
            const contact = await walletContactKeyReader.forOwnKid(kid)
            return contact ? { kid, x25519PrivateKey: contact.ownX25519PrivateKey } : null
          },
          resolveSenderKey: resolveAnyDidCommSenderKey,
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
          startRelationshipWatch(
            relationshipWatchKids, mediatorUrl, { did, xKid, xPriv }, resolveAnyDidCommSenderKey,
            message => handleWalletDidCommMessage(message, xKid, mediatorUrl),
            error => console.warn('[did.md Wallet relationship watch]', error),
          )
        }
        walletRelationshipManager = createWalletRelationshipManager({
          identityId: device.did,
          frontDoor: { xKid: didCommDevice.xKid, x25519PrivateKey: didCommDevice.x25519PrivateKey },
          reader: walletContactKeyReader,
          sink: walletContactKeySink,
          startWatch: startWalletRelationshipWatch,
        })
        handleWalletDidCommMessage = async (message, recipientKid, mediatorUrl) => {
            // A Wallet account carries no group-chat or mail-bridge handling
            // (both live in the local-identity boot path's own onMessage). Its
            // only branch is the DidCommIngressProjector below, which throws
            // for every type outside ping/basicmessage/relationship -- and a
            // throw here does NOT drop the message: watchMediator leaves it
            // unacknowledged on purpose, so the mediator re-delivers the very
            // same message on every reconnect, where it fails identically,
            // forever. Retrying only ever helps a transient failure; an
            // unsupported type is permanent, so drop it deliberately (and
            // visibly) instead, exactly as the local-identity path drops a
            // group message whose invite has not arrived. The Pickup ACK that
            // follows this return is the point: it is what keeps the queue
            // moving for every message behind this one.
            const dropped = message.plaintext as DidCommPlaintext
            if (!isProjectableDidCommIngress(dropped)) {
              console.warn(`[did.md Wallet DIDComm] dropping unsupported message type ${dropped.type} from ${message.senderKid}`)
              return
            }
            const envelope = didCommMediatorIngressEnvelope(
              'biset/didcomm-wallet-mediator-ingress/v1', mediatorUrl, recipientKid, message.ackId,
              device.did, device.credential.deviceKid, message.rawJwe,
            )
            await ingestTransportIngress(envelope, walletDidCommProjector, vaultStore)
            // Projecting INIT records the audit event.  Accepting it here is
            // the missing second half: register the private receiver, store
            // its encrypted contact key, then send the DIDComm ACCEPT.  The
            // Pickup ACK is intentionally delayed until all three succeed.
            await walletRelationshipManager!.handleMessage(message, recipientKid, mediatorUrl)
            await refreshInbox(readModel)
            void synchronizeWalletVault()
        }
        const watch = watchMediator({
          mediatorUrl: didCommDevice.mediatorUrl,
          own: { did: didCommDevice.did, xKid: didCommDevice.xKid, xPriv: didCommDevice.x25519PrivateKey },
          resolveSenderKey: resolveAnyDidCommSenderKey,
          onMessage: message => handleWalletDidCommMessage(message, didCommDevice.xKid, didCommDevice.mediatorUrl),
          onError: error => console.warn('[did.md Wallet DIDComm watch]', error),
        })
        mediatorPollHandles.push({ stop: () => watch.close() })
        // Relationship keys survive reloads as encrypted Vault records.
        // Re-open their Pickup watches before accepting new messages so an
        // existing Biset conversation cannot disappear after refresh.
        await restoreRelationshipWatches(walletContactKeyReader, startWalletRelationshipWatch)
      } catch (error) {
        didComm = { xKid: didCommDevice.xKid, mediatorUrl: didCommDevice.mediatorUrl, error: error instanceof Error ? error.message : String(error) }
        console.warn('[did.md Wallet DIDComm]', error)
      }
      }
    } catch (error) {
      console.warn('[did.md Wallet DIDComm]', error)
    }
    const sendWalletMessage = async (input: ReplySendInput): Promise<void> => {
      if (!activeDidCommDevice || !walletRelationshipManager) throw new Error('DIDComm is still connecting for this Wallet session')
      if (input.toAddrs.length !== 1 || !input.toAddrs[0]?.startsWith('did:')) {
        throw new Error('A did.md Wallet session can currently compose to one DID recipient')
      }
      const toDid = input.toAddrs[0]
      // First contact creates a private did:peer relationship and waits for
      // its authenticated ACCEPT. Ordinary content never rides the public
      // Wallet device kid, so the first message has the same privacy and
      // retry boundary as every later message in the conversation.
      const contact = await walletRelationshipManager.ensureContact(toDid)
      const sent = await sendRelationshipMessage(contact, input.body, input.subject)
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
  // Cleared unconditionally, before any branch: a re-entry into bootClient()
  // (a Wallet disconnect, most notably) must not leave a PRIOR session's
  // MIMI Vault watch or mediator polls running against the new session's own
  // vault/readModel.
  if (mimiVaultWatchHandle !== undefined) { mimiVaultWatchHandle.close(); mimiVaultWatchHandle = undefined }
  for (const handle of mediatorPollHandles) handle.stop()
  mediatorPollHandles = []

  // A did.md Wallet session is the ONLY account this client has since N1
  // (2026-09-05). The seed-derived local IdentityRecord path that used to
  // run here -- the local IdentityRecord store, did:webvh genesis/restore,
  // mail submission and ingress, DIDComm group chat, the transport outbox,
  // OpenPGP enablement and MIMI checkpoint create/restore -- was removed
  // wholesale; did.md issues the identity now and none of that has a
  // wallet-side equivalent yet (tasks/N1-remove-native-login.md).
  //
  // Not yet inlined into this function on purpose: flattening the call
  // structure is S4's job, not this change's.
  if (await configureWalletAccountIfPresent()) {
    showApp()
    showAccountPage()
    return
  }
  // Nothing owns these local databases -- see ALL_LOCAL_DATABASE_NAMES's
  // comment. With no Wallet session there is no account on this device at
  // all, so every one of them (biset-identity included, now that nothing
  // else holds an open connection to it) is stale by definition.
  await deleteLocalDatabases(ALL_LOCAL_DATABASE_NAMES)
  configureAccountPage({ did: null })
  showApp()
  showAccountPage()
}

/** Keeps the initial public API explicit while account routing is implemented. */
export function accountKind(session: AccountSession): AccountSession['kind'] {
  return session.kind
}

bootClient()
