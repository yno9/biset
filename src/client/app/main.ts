import {
  buildActorSequencer,
  buildLocalJmapReadModel,
  buildWalletVaultCryptoBoundary,
} from '../identity/bootstrap.ts'
import { IndexedDbVaultStore } from '../store/vault/store.ts'
import { VaultSyncClient, resolveOwnDeviceKids, vaultSyncChunkBytes, walletVaultSyncTransport, type VaultSyncMessage } from '../didcomm/vault-sync.ts'
import { discoverMaxReceiveBytes } from '../../protocol/didcomm/discover-features.ts'
import { rebuildLocalJmapProjection } from '../store/vault/projection-rebuild.ts'
import { VaultProjector } from '../store/vault/projector.ts'
import { VAULT_SYNC_STATE_REQUEST, VAULT_SYNC_STATE_RESPONSE, VAULT_SYNC_UPDATE } from '../../protocol/didcomm/vault-sync-protocol.ts'
import { setOnWalletConnected } from './ui/account-create.ts'
import {
  beginDidMdWalletFinalizeEnrollment,
  beginDidMdWalletDocumentEdit,
  beginDidMdWalletLogin,
  beginDidMdRemoveOtherDevices,
  beginDidMdRotationKeyRenewal,
  approvedRotationSeed,
  completeDidMdWalletCallback,
  disconnectDidMdWallet,
  openDidMdWalletBisetDidCommDevice,
  openDidMdWalletVaultDevice,
  restoreDidMdWalletSession,
  didMdWalletReconnectState,
  DID_MD_JUST_CONNECTED_KEY,
} from '../identity/wallet/did-md-oauth.ts'
import { refreshInbox, showApp, showSysMsg } from './ui/shell.ts'
import { configureCompose } from './ui/thread.ts'
import type { ReplySendInput } from './ui/thread.ts'
import { configureAccountPage, configureMarkdownVaultToggle, showAccountPage, updateVaultCardStatus, type VaultCardStatus } from './ui/account-page.ts'
import { configureComposePage } from './ui/compose-page.ts'
import { readBisetConfig } from './ui/config.ts'
import { VaultBackedLocalJmapMutationSink } from '../store/projection/vault-mutation-sink.ts'
import { DidCommIngressProjector, isProjectableDidCommIngress } from '../didcomm/ingress-projector.ts'
import { resolveDidCommSenderKey } from '../../protocol/didcomm/webvh-resolve.ts'
import { didCommThreadId } from '../didcomm/basicmessage.ts'
import { answerTrustPing } from '../didcomm/send-message.ts'
import { isPingResponse } from '../../protocol/didcomm/trust-ping.ts'
import { didcommGroupAddress, groupConversation, parseDidCommGroupAddress } from '../didcomm/group-chat.ts'
import { registerWithMediator, type MediatorPollHandle } from '../didcomm/mediator-sync.ts'
import { watchMediatorLive } from '../didcomm/mediator-live.ts'
import { preferredMediatorUrl, isTorEnvironment, sameMediatorUrl } from '../didcomm/mediator-endpoints.ts'
import { mediatorInbox } from '../../protocol/didcomm/mediator-device.ts'
import { ingestTransportIngress } from '../store/vault/ingress-ingest.ts'
import type { IngressEnvelopeV1 } from '../../protocol/ingress.ts'
import { canonicalBytes, canonicalHash, sha256Bytes } from '../../protocol/canonical.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SenderKeyNotPublishedError } from '../../protocol/didcomm/webvh-resolve.ts'
import { decodePeerDid2, publicKeyOf } from '../../protocol/didcomm/peer.ts'
import type { DidCommPlaintext } from '../../protocol/didcomm/message.ts'
import { RelationshipSeedReader, RelationshipSeedSink, relationshipSeedRecord } from '../store/vault/relationship-seed.ts'
import { createRelationshipSeedAuthority, type RelationshipSeedAuthority } from '../didcomm/relationship-seed-bootstrap.ts'
import { publishedRotationKey, rotationSigningKey } from '../didcomm/rotation-key.ts'
import { fetchCurrentLog, freshFetch } from '../identity/webvh/log-io.ts'
import { entryVersionNumber } from '../../protocol/webvh/log.ts'
import { equalBytes } from '../../protocol/canonical.ts'
import { createWalletDidCommOutbox, type WalletDidCommOutbox } from '../identity/wallet/didcomm-outbox.ts'
import { MarkdownDirectoryConnection, observeMarkdownDirectory, removeMarkdownMirrorFile, scanMarkdownProjection, writeMarkdownProjection, type MarkdownMirrorFile } from '../store/vault/markdown-directory.ts'
import { MarkdownSelfWriteGuard, markdownStatusMutation } from '../store/vault/markdown-mirror.ts'
import { createJmapExport, decodeJmapExport, encodeJmapExport, importJmapExport } from '../store/vault/jmap-export.ts'
import { buildOutboundRfc5322 } from '../mail/rfc5322-builder.ts'
import { submitDidCommMail } from '../mail/didcomm-submit.ts'

let mediatorPollHandles: MediatorPollHandle[] = []

function downloadFile(bytes: Uint8Array, filename: string): void { const url = URL.createObjectURL(new Blob([bytes.slice()])); const link = document.createElement('a'); link.href = url; link.download = filename; link.click(); setTimeout(() => URL.revokeObjectURL(url), 0) }
function chooseFile(): Promise<Uint8Array> { return new Promise((resolve, reject) => { const input = document.createElement('input'); input.type = 'file'; input.accept = '.json,.biset,application/json'; input.onchange = () => { const file = input.files?.[0]; if (!file) { reject(new Error('No import file selected')); return } void file.arrayBuffer().then(value => resolve(new Uint8Array(value)), reject) }; input.click() }) }

/**
 * New-client bootstrap. The only branch this makes is "does this device
 * already have an identity locally": with none, this lands on the account
 * page in its zero-identity state (the signup form mounted inline --
 * account-page.ts's own showAccountPage) -- src.bak's ACTUAL default page
 * whenever there's no session (`if (!sessions.length) showMenuPage('/account')`),
 * not a separate full-page overlay (corrected 2026-08-25 after drifting into
 * inventing that instead). With one, it opens the vault UI (read model +
 * reply-send, PLAN.md §7) against the first local identity's vault, and
 * restores the Wallet-authorized identity's local encrypted read model and
 * begins DIDComm Vault synchronization.
 */
// Registered once, at module load -- a plain function reference, not an
// import back into this module (see account-create.ts's own note on why:
// this file is the bundle's entry point, and a dynamic `import('../../../main.ts')`
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
setOnWalletConnected(async session => {
  await bootClient(session)
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
//
// `biset-did-md-wallet` (did-md-store.ts) was missing from this list --
// Disconnect Wallet left the did.md session/device/OAuth-grant database
// behind entirely. A leftover session there is exactly the kind of residue
// that can resurface as another identity's data once a browser profile is
// reused for a different Wallet identity (a live-suspected contributor to
// "checkpoint archive object identity does not match", 2026-09-15).
// `biset-identity` never named a real database (grep confirms zero
// `indexedDB.open` call anywhere ever used it) and is dropped as dead.
const ALL_LOCAL_DATABASE_NAMES = [
  'biset-did-md-wallet', 'biset-mls-keypackages', 'biset-mls-self-group',
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

async function disconnectWalletAndLocalData(): Promise<void> {
  await disconnectDidMdWallet()
  await deleteLocalDatabases(ALL_LOCAL_DATABASE_NAMES)
}

function resolveAnyDidCommSenderKey(kid: string): Promise<Uint8Array> {
  if (kid.startsWith('did:peer:2.')) {
    // Self-certifying: a kid this did:peer does not contain never will.
    try { return Promise.resolve(publicKeyOf(decodePeerDid2(kid.split('#', 1)[0]!), kid)) } catch { return Promise.reject(new SenderKeyNotPublishedError(kid)) }
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

/** Stores the seed a Wallet approval published the rotation key of (the
 * approval's candidate, kept sealed in the session until the Vault is open)
 * -- if the DID document still publishes that key and the Vault lacks it --
 * and forgets the candidate either way. */
async function storeApprovedRotationSeed(did: string, reader: RelationshipSeedReader, sink: RelationshipSeedSink, authority: RelationshipSeedAuthority): Promise<void> {
  const approved = await approvedRotationSeed()
  if (!approved) return
  try {
    const log = await fetchCurrentLog(did, freshFetch())
    const published = publishedRotationKey(log.last.state as Parameters<typeof publishedRotationKey>[0])
    const stored = (await reader.readAll()).some(value => equalBytes(value.seed, approved.seed))
    if (published === rotationSigningKey(approved.seed).publicKeyMultibase && !stored) {
      await sink.store(relationshipSeedRecord(did, approved.seed, entryVersionNumber(log.last.versionId)))
      authority.refresh()
    }
    await approved.forget()
  } finally { approved.seed.fill(0) }
}

async function configureWalletAccountIfPresent(
  callbackSession?: Awaited<ReturnType<typeof completeDidMdWalletCallback>>,
): Promise<boolean> {
  let session = callbackSession
  if (!session) {
    try {
      session = await restoreDidMdWalletSession()
    } catch (error) {
      console.warn('[did.md Wallet restore]', error instanceof Error ? error.message : error)
      return false
    }
  }
  if (!session) return false
  let vault: VaultCardStatus | undefined
  let didComm: { xKid: string; mediatorUrl: string; error?: string } | undefined
  let activeDidCommDevice: { did: string; xKid: string; x25519PrivateKey: Uint8Array; mediatorDeviceSecret: Uint8Array } | undefined
  let walletDidCommOutbox: WalletDidCommOutbox | undefined
  // Set when the identity's rotation key needs a Wallet approval (account page).
  let rotationKeyState: 'unpublished' | 'lost' | 'stale' | undefined
  let exportMessages: (() => Promise<void>) | undefined
  let importMessages: (() => Promise<void>) | undefined
  try {
    const config = readBisetConfig()
    const { mediatorUrls } = config
    const device = await openDidMdWalletVaultDevice()
    const vaultStore = await IndexedDbVaultStore.open()
    let vaultSync: VaultSyncClient | undefined
    let deviceEvents = await vaultStore.readVaultEvents(device.did)
    // This identity's devices are the keyAgreement keys its DID document
    // lists now. Historical event actors are audit history, not devices:
    // using them here made every past login remain in the UI.
    let currentVaultDeviceKid: string | undefined
    let currentVaultDeviceKids: string[] = []
    const refreshVaultDevices = async () => {
      currentVaultDeviceKids = await resolveOwnDeviceKids(device.did)
    }
    const vaultDevices = () => currentVaultDeviceKids
      .map(deviceId => ({ deviceId, current: deviceId === currentVaultDeviceKid }))
      .sort((left, right) => Number(right.current) - Number(left.current) || left.deviceId.localeCompare(right.deviceId))
    const boundary = buildWalletVaultCryptoBoundary(vaultStore, { did: device.did, deviceId: device.deviceId })
    const readModel = buildLocalJmapReadModel(vaultStore, device.did)
    const vaultProjector = new VaultProjector(vaultStore, boundary.resolver)
    const sequencer = await buildActorSequencer(vaultStore, device.did, device.deviceId)
    const mutationSink = new VaultBackedLocalJmapMutationSink({
      accountId: `biset:${device.did}`,
      identityId: device.did,
      actorDeviceId: device.deviceId,
      nextActorSeq: () => sequencer.nextActorSeq(),
      initialParents: () => sequencer.initialParents(),
      activeSegment: () => boundary.activeSegment(),
      signer: boundary.author,
      committer: vaultStore,
      onCrdtCommitted: async events => {
        deviceEvents.push(...events.map(event => ({ ...event, identityId: device.did })))
        await vaultProjector.recomputeEmails(device.did, events.flatMap(event => event.targetIds))
        if (vaultSync) void vaultSync.push(events).catch(error => console.warn('[did.md Wallet Vault Sync push]', error instanceof Error ? error.message : error))
      },
    })
    exportMessages = async () => {
      const exported = await createJmapExport({ identityId: device.did, snapshot: await readModel.snapshot(), events: await vaultStore.readVaultEvents(device.did), download: blobId => readModel.download(blobId) })
      // Plain JSON: whoever can open this account's dashboard already sees
      // everything the file contains.
      downloadFile(encodeJmapExport(exported), `biset-messages-${exported.exportedAt.replaceAll(':', '-')}.json`)
    }
    importMessages = async () => {
      const file = decodeJmapExport(await chooseFile())
      // The file is plain JSON that anyone could have written. Its own
      // identity must be this account (importJmapExport refuses otherwise),
      // and the user confirms what it claims before anything is committed;
      // every message it adds is marked $imported.
      if (file.identityId !== device.did) throw new Error('This export belongs to another account')
      if (!confirm(`Import ${file.emails.length} messages and ${file.contactCards?.length ?? 0} contacts exported from this account on ${new Date(file.exportedAt).toLocaleString()}? Messages it adds are marked as imported.`)) return
      const result = await importJmapExport(file, { identityId: device.did, actorDeviceId: device.deviceId, snapshot: await readModel.snapshot(), events: await vaultStore.readVaultEvents(device.did), nextActorSeq: () => sequencer.nextActorSeq(), initialParents: () => sequencer.initialParents(), activeSegment: () => boundary.activeSegment(), signer: boundary.author, commit: records => vaultStore.commitIncomingRecords(records) })
      if (result.events.length) { await vaultProjector.recomputeEmails(device.did, result.events.flatMap(event => event.targetIds)); if (vaultSync) await vaultSync.push(result.events); await refreshInbox(readModel) }
      showSysMsg(`Import: ${result.added} added, ${result.skipped} skipped, ${result.excluded} excluded, ${result.missingBodies} missing bodies; contacts ${result.contactsAdded} added, ${result.contactsUpdated} updated`)
    }
    const markdownDirectories = await MarkdownDirectoryConnection.open()
    const markdownGuard = new MarkdownSelfWriteGuard()
    let sendMarkdownDraft: ((file: MarkdownMirrorFile) => Promise<void>) | undefined
    let markdownRoot = await markdownDirectories.restore(device.did)
    let markdownObserver: { disconnect(): void; supported: boolean } | undefined
    const startMarkdownMirror = async (root: FileSystemDirectoryHandle): Promise<void> => {
      markdownObserver?.disconnect()
      await writeMarkdownProjection(root, readModel, device.did, markdownGuard)
      markdownObserver = observeMarkdownDirectory(root, () => {
        void scanMarkdownProjection(root, markdownGuard).then(async files => {
          const snapshot = await readModel.snapshot()
          for (const file of files) {
            const thread = snapshot.emails.filter(email => email.threadId === file.parsed.frontmatter.id)
            const status = file.parsed.frontmatter.status.trim().toLowerCase()
            const shouldSend = status === 'send' || /(^|\n)!b(?:\n|$)/.test(file.parsed.draft)
            if (shouldSend && sendMarkdownDraft) { await sendMarkdownDraft(file); await removeMarkdownMirrorFile(root, file.path); continue }
            if (!thread.length || !status) continue
            const mutation = markdownStatusMutation(status, thread, snapshot)
            if (mutation) await mutationSink.emailSet({ accountId: `biset:${device.did}`, ...mutation }, snapshot)
          }
          await writeMarkdownProjection(root, readModel, device.did, markdownGuard)
        }).catch(error => console.warn('[Markdown Vault]', error))
      })
    }
    if (markdownRoot) void startMarkdownMirror(markdownRoot).catch(error => console.warn('[Markdown Vault restore]', error))
    configureMarkdownVaultToggle({
      enabled: () => markdownRoot !== undefined,
      observerSupported: () => markdownObserver?.supported ?? false,
      async rescan() { if (markdownRoot) await startMarkdownMirror(markdownRoot) },
      async toggle() {
        if (markdownRoot) {
          markdownObserver?.disconnect(); markdownObserver = undefined; markdownRoot = undefined
          await markdownDirectories.remove(device.did)
          return
        }
        const picker = (window as unknown as { showDirectoryPicker(options?: { mode?: 'read' | 'readwrite' }): Promise<FileSystemDirectoryHandle> }).showDirectoryPicker
        markdownRoot = await picker({ mode: 'readwrite' })
        await markdownDirectories.save(device.did, markdownRoot)
        await startMarkdownMirror(markdownRoot)
      },
    })
    // A group conversation is whatever its messages say (group-chat.ts):
    // its participants are those of its latest message.
    const walletGroupConversation = async (thid: string) => groupConversation(thid, (await readModel.snapshot()).emails)
    // The relationship seed: Vault records, read and written like every
    // other private credential, and carried to siblings by Vault Sync.
    const walletSeedReader = new RelationshipSeedReader({ identityId: device.did, objects: vaultStore, events: vaultStore, segmentKeys: boundary.resolver })
    const walletSeedSink = new RelationshipSeedSink({
      identityId: device.did, actorDeviceId: device.deviceId,
      nextActorSeq: () => sequencer.nextActorSeq(), initialParents: () => sequencer.initialParents(),
      activeSegment: () => boundary.activeSegment(), currentSnapshot: () => readModel.snapshot(),
      signer: boundary.author, committer: vaultStore,
      onCommitted: async event => {
        deviceEvents.push({ ...event, identityId: device.did })
        if (vaultSync) await vaultSync.push([event])
      },
    })
    // The Wallet branch returns before the ordinary local-identity boot
    // path, which normally loads this projection.  Restore the existing
    // local inbox before rendering so a page reload never looks like it
    // discarded a Wallet account's encrypted history.
    await refreshInbox(readModel).catch(error => console.warn('[did.md Wallet inbox restore]', error))

    vault = { state: 'checking', coordinatorUrl: 'didcomm', vaultId: device.did as never, detail: 'Connecting encrypted Vault sync', devices: vaultDevices() }
    // DIDComm has its own X25519 leaf, never the MLS signing leaf and never
    // a did.md controller key. Wallet published the public leaf and mediator
    // route during the explicit consent that enrolled it; this registration
    // only proves possession of the local X25519 private key to the mediator.
    // A corrupt or independently revoked DIDComm envelope must not make the
    // otherwise healthy Vault sync look unavailable. It has its own sealed
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
        currentVaultDeviceKid = didCommDevice.xKid
        await refreshVaultDevices()
        if (!currentVaultDeviceKids.includes(didCommDevice.xKid)) {
          throw new Error('This device is no longer listed in your DID document; reconnect did.md Wallet')
        }
        const frontDoorInbox = mediatorInbox({ did: didCommDevice.did, xKid: didCommDevice.xKid, xPriv: didCommDevice.x25519PrivateKey }, didCommDevice.mediatorDeviceSecret)
        // PLAN-tor.md D-5/3-3: dial this mediator's onion entrance only when
        // this page itself is being served over Tor (isTorEnvironment, D-6) --
        // an ordinary browser always gets canonical, with no `.onion` fetch
        // ever attempted (I-3). Falls back to canonical if no onion is
        // configured for this device (I-5's exact pre-Tor behavior), and
        // also if the onion entrance itself fails to register (D-5's table:
        // Tor environment prefers onion, "failed -> clearnet").
        let activeMediatorUrl = preferredMediatorUrl(
          { canonicalUrl: didCommDevice.mediatorUrl, onionUrl: didCommDevice.mediatorOnionUrl },
          isTorEnvironment(),
        )
        let mediator: Awaited<ReturnType<typeof registerWithMediator>>
        try {
          mediator = await registerWithMediator(activeMediatorUrl, frontDoorInbox)
        } catch (error) {
          if (activeMediatorUrl === didCommDevice.mediatorUrl) throw error
          console.warn('[did.md Wallet DIDComm register] onion entrance unreachable, falling back to canonical', error instanceof Error ? error.message : error)
          activeMediatorUrl = didCommDevice.mediatorUrl
          mediator = await registerWithMediator(activeMediatorUrl, frontDoorInbox)
        }
        if (mediator.xKid !== didCommDevice.routingKid) throw new Error('Mediator routing key changed since Wallet authorization; enable messaging again')
        didComm = { xKid: didCommDevice.xKid, mediatorUrl: didCommDevice.mediatorUrl }
        activeDidCommDevice = didCommDevice
        // Restore is "only while an existing sibling is reachable" (no
        // recovery-mailbox fallback): a cold device pulls state from an
        // online sibling via the ordinary bootstrap request below, and a
        // fresh Vault with no siblings simply starts empty.
        vaultSync = new VaultSyncClient(device.did, didCommDevice.xKid, vaultStore,
          walletVaultSyncTransport({ did: didCommDevice.did, xKid: didCommDevice.xKid, xPriv: didCommDevice.x25519PrivateKey }),
          async result => {
            if (result.addedEventIds.length) deviceEvents = await vaultStore.readVaultEvents(device.did)
            if (result.targetIds.length || result.addedEventIds.length) await vaultProjector.recomputeEmails(device.did, result.targetIds)
          },
          // Sized to what this identity's mediator says it takes; a mediator
          // that does not say gets the conservative default.
          vaultSyncChunkBytes(await discoverMaxReceiveBytes(mediator, frontDoorInbox).catch(() => undefined)))
        await refreshInbox(readModel)
        // Mediator registration and the transport above are both live at
        // this point; nothing past here can throw its way back to the
        // 'checking' state left set above, so mark the card connected now
        // rather than leaving it stuck on its initial value forever.
        updateRememberedVaultCard(
          { state: 'connected', coordinatorUrl: 'didcomm', vaultId: device.did as never, devices: vaultDevices() },
          { current: () => vault, remember: status => { vault = status } },
        )
        // A fresh browser and a long-idle browser use the same pull route:
        // ask every sibling (one message to this identity's own DID) what
        // this device's state lacks.
        // The seed's authority is the DID document (PLAN-refactor.md §4.2).
        // A seed a Wallet approval just published is stored in the Vault here,
        // where it reaches every sibling; the account page offers a renewal
        // when the document's key needs one.
        const seedAuthority = createRelationshipSeedAuthority({
          ownKid: didCommDevice.xKid,
          seeds: walletSeedReader,
          readLog: async () => (await fetchCurrentLog(device.did, freshFetch())).entries,
        })
        await storeApprovedRotationSeed(device.did, walletSeedReader, walletSeedSink, seedAuthority)
          .catch(error => console.warn('[did.md Wallet relationship seed]', error instanceof Error ? error.message : error))
        try {
          const status = await seedAuthority.status()
          if (status.state === 'unpublished' || status.state === 'lost' || status.state === 'stale') rotationKeyState = status.state
          else if (status.state === 'pending') console.info('[did.md Wallet] waiting for the relationship seed from another device')
        } catch (error) {
          console.warn('[did.md Wallet relationship seed status]', error instanceof Error ? error.message : error)
        }
        void vaultSync.requestState()
          .catch(error => console.warn('[did.md Wallet Vault Sync bootstrap]', error instanceof Error ? error.message : error))
        // Enrollment alone only lets the mediator queue messages.  Open the
        // device-bound live Pickup watch as well, then project every durable
        // DIDComm delivery into this browser's encrypted local Vault. Every
        // message arrives at this device's own key in the DID document.
        const walletDidCommProjector = new DidCommIngressProjector({
          identityId: device.did,
          actorDeviceId: device.deviceId,
          resolveOwnKey: kid => kid === didCommDevice.xKid ? { kid, x25519PrivateKey: didCommDevice.x25519PrivateKey } : null,
          resolveSenderKey: resolveAnyDidCommSenderKey,
          async alreadyProcessed() { return false },
          nextActorSeq: () => sequencer.nextActorSeq(),
          initialParents: () => sequencer.initialParents(),
          activeSegment: () => boundary.activeSegment(),
          currentSnapshot: () => readModel.snapshot(),
          signer: boundary.author,
        })
        // A mediator dropped copies for one of this device's inboxes (it was
        // dormant, or full): every one of them also reached a sibling, so
        // catch up from the siblings' Vault.
        const catchUpFromSiblings = () => {
          void vaultSync?.requestState().catch(error => console.warn('[did.md Wallet Vault Sync catch-up]', error instanceof Error ? error.message : error))
        }
        const reportedOutboxFailures = new Set<string>()
        walletDidCommOutbox = createWalletDidCommOutbox({
          identityId: device.did,
          store: vaultStore,
          readModel,
          mutationSink,
          frontDoor: { fromKid: didCommDevice.xKid, x25519PrivateKey: didCommDevice.x25519PrivateKey },
          onDelivered: () => undefined,
          onError: (error, item) => {
            const reason = error instanceof Error ? error.message : String(error)
            console.warn(`[did.md Wallet DIDComm outbox] ${item.emailId} -> ${item.toDid}:`, reason)
            // Said once per message, recipient and reason: the row is retried
            // every few seconds, and the same failure each time is no news.
            const key = `${item.outboundEventId}\u0000${item.toDid}\u0000${reason}`
            if (reportedOutboxFailures.has(key)) return
            reportedOutboxFailures.add(key)
            showSysMsg(`Could not send to ${item.toDid} yet (it stays queued and will be retried): ${reason}`)
          },
        })
        const handleWalletDidCommMessage = async (message: { plaintext: unknown; senderKid: string; ackId: string; rawJwe: unknown }, recipientKid: string, mediatorUrl: string): Promise<void> => {
            // Besides Vault Sync, the only branch is the DidCommIngressProjector
            // below, which throws for every type it cannot project -- and a
            // throw here does NOT drop the message: watchMediatorLive leaves it
            // unacknowledged on purpose, so the mediator re-delivers the very
            // same message on every reconnect, where it fails identically,
            // forever. Retrying only ever helps a transient failure; an
            // unsupported type is permanent, so drop it deliberately (and
            // visibly) instead. The Pickup ACK that
            // follows this return is the point: it is what keeps the queue
            // moving for every message behind this one.
            const candidate = message.plaintext as { type?: unknown }
            if (vaultSync && (candidate.type === VAULT_SYNC_UPDATE || candidate.type === VAULT_SYNC_STATE_REQUEST || candidate.type === VAULT_SYNC_STATE_RESPONSE)) {
              await vaultSync.receive(message.plaintext as VaultSyncMessage, message.senderKid)
              deviceEvents = await vaultStore.readVaultEvents(device.did)
              // A sibling login may have added its device key to the DID
              // document just before sending this sync message. Re-resolve the
              // public device list instead of deriving it from event history.
              if (vault) {
                await refreshVaultDevices()
                updateRememberedVaultCard(
                  { ...vault, devices: vaultDevices() },
                  { current: () => vault, remember: status => { vault = status } },
                )
              }
              // Merging the CRDT log/object store (above) never by itself
              // updates the SEPARATELY stored local JMAP projection the
              // inbox actually renders from -- a sibling's message became
              // durable in this browser's Vault but stayed permanently
              // invisible until a full rebuild re-derives the projection
              // from every event/object this identity now has, including
              // whatever this sync just added ("one device's own sent
              // message never appeared on the other", found live,
              // 2026-09-15). Skipped for a bare STATE_REQUEST, which never
              // adds anything of this device's own.
              if (candidate.type !== VAULT_SYNC_STATE_REQUEST) {
                // The CRDT/object merge above is the durable source of
                // truth and has ALREADY succeeded by this point -- a
                // failure re-deriving the projection from it (any single
                // incompatible historical event breaks the ENTIRE replay,
                // since this rebuilds from ALL of this identity's events
                // every time) must not be treated as this sync message
                // having failed. Before this guard, such a failure
                // propagated out of onMessage, which mediator-live.ts
                // never acks -- the same message then redelivers on every
                // reconnect and fails identically forever, permanently
                // wedging delivery to this device entirely ("完全に届かな
                // い", found live, 2026-09-15). The data is safe either way;
                // only the inbox's rendering of it is what's at risk here.
                try {
                  const projection = await rebuildLocalJmapProjection({
                    identityId: device.did, records: vaultStore, resolver: boundary.resolver,
                  })
                  await vaultStore.writeProjection(device.did, projection, { state: projection.state })
                  await refreshInbox(readModel)
                } catch (error) {
                  console.warn('[did.md Wallet Vault Sync projection rebuild]', error instanceof Error ? error.message : error)
                }
              }
              return
            }
            const dropped = message.plaintext as DidCommPlaintext
            // The answer to a ping this side sent: arriving was its whole job.
            if (isPingResponse(dropped)) return
            if (!isProjectableDidCommIngress(dropped)) {
              console.warn(`[did.md Wallet DIDComm] dropping unsupported message type ${dropped.type} from ${message.senderKid}`)
              return
            }
            // A direct DIDComm delivery becomes local Vault records below.
            // Mirror those newly committed records to siblings as well: two
            // watches for the same private kid normally see the same live
            // frame, but one sibling can ACK first or be reconnecting.
            // Vault Sync is the durable convergence path for that race.
            const eventIdsBeforeIngress = new Set(deviceEvents.map(event => event.id))
            const envelope = didCommMediatorIngressEnvelope(
              'biset/didcomm-wallet-mediator-ingress/v1', mediatorUrl, recipientKid, message.ackId,
              device.did, device.deviceId, message.rawJwe,
            )
            const ingress = await ingestTransportIngress(envelope, walletDidCommProjector, vaultStore)
            if (ingress.targetIds.length) await vaultProjector.recomputeEmails(device.did, ingress.targetIds)
            else await vaultProjector.rebuildAll(device.did)
            // Trust Ping 2.0: answer one that asked. Best-effort: the ping is
            // already recorded, and a lost answer is exactly what a ping
            // exists to reveal to its sender.
            void answerTrustPing(dropped, {
              frontDoor: { fromKid: didCommDevice.xKid, x25519PrivateKey: didCommDevice.x25519PrivateKey },
            }).then(result => { if (result && !result.ok) console.warn('[did.md Wallet Trust Ping response]', result.error) })
              .catch(error => console.warn('[did.md Wallet Trust Ping response]', error instanceof Error ? error.message : error))
            const eventsAfterIngress = await vaultStore.readVaultEvents(device.did)
            const newlyCommitted = eventsAfterIngress.filter(event => !eventIdsBeforeIngress.has(event.id))
            deviceEvents = eventsAfterIngress
            if (vaultSync && newlyCommitted.length) {
              void vaultSync.push(newlyCommitted)
                .catch(error => console.warn('[did.md Wallet Vault Sync ingress push]', error instanceof Error ? error.message : error))
            }
            await refreshInbox(readModel, { forceRender: document.querySelector('#focused-thread-card .t-messages') !== null })
        }
        const watch = watchMediatorLive({
          mediatorUrl: activeMediatorUrl,
          inbox: frontDoorInbox,
          resolveSenderKey: resolveAnyDidCommSenderKey,
          onMessage: message => handleWalletDidCommMessage(message, didCommDevice.xKid, activeMediatorUrl),
          onError: error => console.warn('[did.md Wallet DIDComm watch]', error),
          onMissed: catchUpFromSiblings,
        })
        mediatorPollHandles.push({ stop: () => watch.close() })
        // A durable intent might predate this tab (or the previous send's
        // network attempt). Flushing must never delay initial UI rendering.
        // Retry independently of incoming mediator traffic; failure leaves
        // its row durable for the next pass.
        void walletDidCommOutbox.flush()
        const retryTimer = setInterval(() => { void walletDidCommOutbox!.flush() }, 10_000)
        mediatorPollHandles.push({ stop: () => clearInterval(retryTimer) })
      } catch (error) {
        didComm = { xKid: didCommDevice.xKid, mediatorUrl: didCommDevice.mediatorUrl, error: error instanceof Error ? error.message : String(error) }
        console.warn('[did.md Wallet DIDComm]', error)
      }
      }
    } catch (error) {
      console.warn('[did.md Wallet DIDComm]', error)
    }
    // A DIDComm chat message is committed locally first (the durable
    // outbox), then sent to each recipient's public DID from this device's
    // own key. `thid` makes it part of a group conversation: the same
    // message, addressed to every participant (group-chat.ts).
    const queueWalletChatMessage = async (recipients: string[], input: ReplySendInput, group?: { thid: string }): Promise<void> => {
      if (!walletDidCommOutbox) throw new Error('DIDComm is still connecting for this Wallet session')
      if (recipients.length === 0) throw new Error('A DIDComm message needs a recipient')
      const now = new Date().toISOString()
      const emailId = crypto.randomUUID()
      const messageId = crypto.randomUUID()
      const snapshot = await readModel.snapshot()
      await mutationSink.commitMailMessage({
        email: {
          id: emailId,
          // A group conversation is its `thid`, carried by every message of it.
          threadId: group ? didcommGroupAddress(group.thid) : didCommThreadId(device.did, recipients[0]!),
          mailboxIds: { outbox: true }, keywords: { '$seen': true },
          receivedAt: now, sentAt: now, from: [{ email: device.did }], to: recipients.map(email => ({ email })),
          ...(input.subject ? { subject: input.subject } : {}),
        },
        rawRfc5322: new TextEncoder().encode(input.body),
        didComm: recipients.map(toDid => ({ messageId, toDid })),
      }, snapshot)
      await refreshInbox(readModel)
      await walletDidCommOutbox.flush()
      await refreshInbox(readModel)
    }
    const sendWalletMessage = async (input: ReplySendInput): Promise<void> => {
      if (input.toAddrs.length > 0 && input.toAddrs.every(address => address.includes('@'))) {
        const mailFrom = `${session.handle.split('.', 1)[0]}@did.md`
        const now = new Date().toISOString()
        const emailId = crypto.randomUUID()
        const messageId = crypto.randomUUID()
        const rawRfc5322 = buildOutboundRfc5322({ messageId, from: mailFrom, to: input.toAddrs, subject: input.subject, body: input.body, inReplyTo: input.inReplyTo, references: input.references })
        const snapshot = await readModel.snapshot()
        // This commit is the durable outbox: submission happens only after it
        // is encrypted and committed. A rejected/failed request leaves it in
        // outbox for a later retry rather than silently losing the draft.
        await mutationSink.commitMailMessage({
          email: { id: emailId, threadId: input.references?.[0] ?? input.inReplyTo ?? messageId, mailboxIds: { outbox: true }, keywords: { '$seen': true }, receivedAt: now, sentAt: now, from: [{ email: mailFrom }], to: input.toAddrs.map(email => ({ email })), ...(input.subject ? { subject: input.subject } : {}), ...(input.inReplyTo ? { inReplyTo: input.inReplyTo } : {}), size: rawRfc5322.length },
          rawRfc5322,
        }, snapshot)
        await refreshInbox(readModel)
        if (!activeDidCommDevice) throw new Error('DIDComm messaging is not enabled for this Wallet')
        await submitDidCommMail({ fromKid: activeDidCommDevice.xKid, x25519PrivateKey: activeDidCommDevice.x25519PrivateKey, messageId, mailFrom, rcptTo: input.toAddrs, rawRfc5322 })
        const afterSubmit = await readModel.snapshot()
        await mutationSink.commitIntents([
          { kind: 'transport.result', targetIds: [emailId], payload: { emailId, messageId, status: 'accepted', occurredAt: new Date().toISOString(), transport: 'didcomm-mail-bridge' } },
          { kind: 'mailbox.set', targetIds: [emailId], payload: { emailId, mailboxIds: { sent: true } } },
        ], afterSubmit)
        await refreshInbox(readModel)
        return
      }
      if (!activeDidCommDevice || !walletDidCommOutbox) throw new Error('DIDComm is still connecting for this Wallet session')
      const snapshotBeforeSend = await readModel.snapshot()
      const replyThread = input.inReplyTo ? snapshotBeforeSend.emails.find(email => email.id === input.inReplyTo)?.threadId : undefined
      // A reply in a group conversation goes to every participant of its
      // latest message but this identity (reply-all; PLAN-refactor.md §8).
      if (replyThread?.startsWith('didcomm-group:')) {
        const thid = parseDidCommGroupAddress(replyThread)
        const conversation = await walletGroupConversation(thid)
        if (!conversation) throw new Error('This DIDComm group conversation is unavailable on this device')
        await queueWalletChatMessage(conversation.participants.filter(participant => participant !== device.did), input, { thid })
        return
      }
      if (input.toAddrs.length === 0 || !input.toAddrs.every(address => address.startsWith('did:'))) throw new Error('A did.md Wallet session composes to DID recipients only')
      const recipients = [...new Set(input.toAddrs)].filter(address => address !== device.did)
      // Several recipients start a group conversation of its own.
      if (recipients.length >= 2) {
        await queueWalletChatMessage(recipients, input, { thid: crypto.randomUUID() })
        return
      }
      await queueWalletChatMessage(recipients, input)
    }
    sendMarkdownDraft = async file => {
      const snapshot = await readModel.snapshot(); const thread = snapshot.emails.filter(email => email.threadId === file.parsed.frontmatter.id)
      await sendWalletMessage({ toAddrs: [file.parsed.frontmatter.contact], subject: file.parsed.frontmatter.subject ?? '', body: file.parsed.draft.replace(/(^|\n)!b(?:\n|$)/g, '$1').trim(), ...(thread.at(-1) ? { inReplyTo: thread.at(-1)!.id } : {}) })
    }
    configureCompose({
      selfAddress: device.did,
      selfDid: activeDidCommDevice ? device.did : undefined,
      sendReply: sendWalletMessage,
      onError: message => { showSysMsg(message); console.warn('[did.md Wallet send]', message) },
      didcommGroup: {
        membersOf: async thid => (await walletGroupConversation(thid))?.participants ?? [],
        groupName: async thid => (await walletGroupConversation(thid))?.name,
      },
    })
    configureComposePage({
      selfAddress: device.did,
      selfDid: activeDidCommDevice ? device.did : undefined,
      sendMessage: sendWalletMessage,
      onError: message => { showSysMsg(message); console.warn('[did.md Wallet compose]', message) },
    })
  } catch (error) {
    vault = { state: 'error', coordinatorUrl: 'didcomm', detail: error instanceof Error ? error.message : String(error) }
    console.warn('[did.md Wallet Vault]', error)
  }
  // Keep the configured Mediator visible after an intentional logout.  No
  // xKid is invented here: the grey state is configuration only, and its
  // Log in action creates/registers a fresh device before asking Wallet to
  // publish it.
  const configuredMediator = readBisetConfig().mediatorUrls.find(url => {
    try { return Boolean(new URL(url).host) } catch { return false }
  })
  const mediatorCard = didComm ?? (configuredMediator
    ? { mediatorUrl: new URL(configuredMediator).toString(), loggedOut: true as const }
    : undefined)
  // The configured onion paired with this card's mediator (same index as
  // `mediatorUrls`) pre-fills the "Enable Tor" prompt; nothing publishes it
  // until the user confirms.
  const configuredOnionUrl = mediatorCard
    ? readBisetConfig().mediatorOnionUrls[readBisetConfig().mediatorUrls.findIndex(url => sameMediatorUrl(url, mediatorCard.mediatorUrl))]
    : undefined
  configureAccountPage({
    did: session.did,
    ...(exportMessages ? { onExportMessages: exportMessages } : {}),
    ...(importMessages ? { onImportMessages: importMessages } : {}),
    wallet: {
      handle: session.handle,
      deviceJkt: session.deviceJkt,
      capabilityExpiresAt: session.capabilityExpiresAt,
      deviceKid: session.deviceKid,
      ...(mediatorCard ? { didComm: { ...mediatorCard, ...(configuredOnionUrl ? { onionUrl: configuredOnionUrl } : {}) } } : {}),
      // Publishes the DIDComm mediator device -- the one enrollment step
      // that still needs a DID Document edit (other people's DIDComm
      // senders have to be able to find the route publicly).
      onEnableMessaging: async () => {
        const config = readBisetConfig()
        return beginDidMdWalletFinalizeEnrollment(config.mediatorUrls, config)
      },
      // Same same-tab Wallet approval as onEnableMessaging, just pointed at
      // an explicit mediator URL (the Mediator card's "Edit server") instead
      // of always taking this deployment's configured default -- reuses
      // beginDidMdWalletDocumentEdit as-is, since it already accepts
      // an array and takes its first valid entry (bisetMediatorFor).
      onEditMediator: async (mediatorUrl: string) => beginDidMdWalletDocumentEdit({ mediatorUrls: [mediatorUrl], configuration: readBisetConfig() }),
      onEnableTor: async (onionUrl: string) => beginDidMdWalletDocumentEdit({ mediatorUrls: [mediatorCard!.mediatorUrl], mediatorOnionUrls: [onionUrl], configuration: readBisetConfig() }),
      onLogOutMediator: async () => beginDidMdWalletDocumentEdit({ removeMediator: true, configuration: readBisetConfig() }),
      onDisconnect: async () => {
        await disconnectWalletAndLocalData()
        await bootClient()
      },
    },
    vault,
    onRemoveOtherDevices: async () => beginDidMdRemoveOtherDevices(readBisetConfig()),
    ...(rotationKeyState ? { rotationKey: { state: rotationKeyState, onRenew: async () => beginDidMdRotationKeyRenewal(readBisetConfig()) } } : {}),
    showMessage: showSysMsg,
  })
  return true
}

export async function bootClient(callbackSession?: Awaited<ReturnType<typeof completeDidMdWalletCallback>>): Promise<void> {
  // Cleared unconditionally, before any branch: a re-entry into bootClient()
  // (a Wallet disconnect, most notably) must not leave a PRIOR session's
  // mediator polls running against the new session's own
  // vault/readModel.
  for (const handle of mediatorPollHandles) handle.stop()
  mediatorPollHandles = []

  // Consume an OAuth callback before attempting an ordinary refresh of the
  // stored Wallet capability.  A DID-document edit intentionally makes the
  // old capability's document snapshot stale; refreshing it first used to
  // clear the otherwise valid session and briefly render account creation,
  // only for account-create.ts to consume the callback and restore it again.
  // Callback completion saves the replacement session atomically before the
  // account UI below reads it.
  //
  // Not guarded before, this could throw (an invalid/expired code, a
  // network error) as an unhandled rejection out of the top-level
  // `bootClient()` call at the bottom of this file -- aborting boot before
  // showApp()/showAccountPage() ever ran, leaving a blank page with no
  // visible error. account-create.ts's own callback handler still gets a
  // chance to show the user what went wrong once the account page actually
  // renders below.
  let completedWalletEdit = callbackSession
  if (!completedWalletEdit) {
    try {
      completedWalletEdit = await completeDidMdWalletCallback()
    } catch (error) {
      console.warn('[did.md Wallet callback]', error instanceof Error ? error.message : error)
    }
  }

  // A did.md Wallet session is the ONLY account this client has since N1
  // (2026-09-05). The seed-derived local IdentityRecord path that used to
  // run here -- the local IdentityRecord store, did:webvh genesis/restore,
  // mail submission and ingress, DIDComm group chat, the transport outbox,
  // OpenPGP enablement and self-hosted checkpoint create/restore -- was removed
  // wholesale; did.md issues the identity now and none of that has a
  // wallet-side equivalent yet (tasks/N1-remove-native-login.md).
  //
  // Not yet inlined into this function on purpose: flattening the call
  // structure is S4's job, not this change's.
  // Callback completion has already exchanged the one-time code, validated
  // the new capability, and atomically saved its replacement session. Do
  // not immediately refresh that brand-new session again: a transient
  // refresh/propagation failure used to clear it and make a successful
  // Vault rotation look exactly like a logout.
  if (await configureWalletAccountIfPresent(completedWalletEdit)) {
    // NOT showAccountPage() here -- this branch also runs on a plain page
    // refresh/reload (the module-level `bootClient()` call at the bottom of
    // this file), which has an existing session and nothing to do with
    // signup. Forcing the account page every time landed you back there no
    // matter what you'd been reading before hitting reload (found live,
    // 2026-09-09: single-column mode always bounced to /account on refresh).
    // The actual "just signed up" case still gets its own account-page
    // landing explicitly, from setOnWalletConnected's own callback below --
    // this call site only ever needed it for that one case, never for an
    // ordinary returning session.
    showApp()
    if (completedWalletEdit || sessionStorage.getItem(DID_MD_JUST_CONNECTED_KEY) === '1') {
      sessionStorage.removeItem(DID_MD_JUST_CONNECTED_KEY)
      showAccountPage()
    }
    return
  }
  const reconnect = await didMdWalletReconnectState()
  if (reconnect?.expired) {
    configureAccountPage({
      did: reconnect.did,
      wallet: {
        handle: reconnect.handle, deviceJkt: '', capabilityExpiresAt: reconnect.capabilityExpiresAt, reconnectRequired: true,
        onReconnect: async () => {
          const config = readBisetConfig()
          const popup = location.protocol === 'file:' ? window.open('', 'did-md-wallet') ?? undefined : undefined
          return beginDidMdWalletLogin(config.mediatorUrls, popup, config)
        },
        onDisconnect: async () => { await disconnectWalletAndLocalData(); await bootClient() },
      },
      showMessage: showSysMsg,
    })
    showApp()
    showAccountPage()
    showSysMsg(`The capability for ${reconnect.handle} expired. Reconnect did.md Wallet; local Vault and message databases were preserved.`)
    return
  }
  // A missing/unreadable Wallet session is not proof that local Vault data
  // is orphaned: callback races, temporary AS failures, or storage errors
  // can all reach this branch. Destructive cleanup is therefore reserved
  // for the explicit Disconnect action above.
  configureAccountPage({ did: null })
  showApp()
  showAccountPage()
}

/** Keeps the initial public API explicit while account routing is implemented. */
bootClient()
