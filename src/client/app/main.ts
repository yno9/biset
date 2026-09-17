import type { AccountSession } from '../store/projection/transport.ts'
import {
  buildActorSequencer,
  buildLocalJmapReadModel,
  buildWalletVaultCryptoBoundary,
} from '../identity/bootstrap.ts'
import { IndexedDbVaultStore } from '../store/vault/store.ts'
import { VaultSyncClient, resolveVaultSyncSiblingRoutes, walletVaultSyncTransport, type VaultSyncMessage } from '../didcomm/vault-sync.ts'
import { rewrapVaultSegmentsForGeneration } from '../store/vault/vault-key-rotation.ts'
import { VAULT_CONTENT_KEY_GROUP_ID } from '../store/vault/vault-content-key.ts'
import { rebuildLocalJmapProjection } from '../store/vault/projection-rebuild.ts'
import { VaultProjector } from '../store/vault/projector.ts'
import { VAULT_SYNC_STATE_REQUEST, VAULT_SYNC_STATE_RESPONSE, VAULT_SYNC_UPDATE } from '../../protocol/didcomm/vault-sync-protocol.ts'
import { setOnWalletConnected } from './ui/account-create.ts'
import {
  beginDidMdWalletFinalizeEnrollment,
  beginDidMdWalletDocumentEdit,
  beginDidMdWalletLogin,
  beginDidMdVaultKeyRotation,
  completeDidMdVaultKeyRotation,
  completeDidMdWalletCallback,
  disconnectDidMdWallet,
  openDidMdWalletBisetDidCommDevice,
  openDidMdWalletBisetDevice,
  openDidMdWalletRelationshipSecret,
  openDidMdWalletVaultContentKeys,
  restoreDidMdWalletSession,
  didMdWalletReconnectState,
  didMdVaultKeyRotationStatus,
  walletVaultSyncKeys,
  DID_MD_JUST_CONNECTED_KEY,
} from '../identity/wallet/did-md-oauth.ts'
import { refreshInbox, showApp, showSysMsg } from './ui/shell.ts'
import { configureCompose } from './ui/thread.ts'
import type { ReplySendInput } from './ui/thread.ts'
import { configureAccountPage, configureMarkdownVaultToggle, showAccountPage, updateVaultCardStatus, type VaultCardStatus } from './ui/account-page.ts'
import { configureComposePage } from './ui/compose-page.ts'
import { readBisetConfig } from './ui/config.ts'
import { VaultBackedLocalJmapMutationSink } from '../store/projection/vault-mutation-sink.ts'
import { DidCommIngressProjector, didCommMessageDedupeId, isProjectableDidCommIngress, resolveDidCommSenderDid } from '../didcomm/ingress-projector.ts'
import { resolveDidCommSenderKey } from '../../protocol/didcomm/webvh-resolve.ts'
import { didCommThreadId } from '../didcomm/basicmessage.ts'
import { sendGroupInvite } from '../didcomm/send-message.ts'
import { buildDidCommGroupMessageVaultRecord, GROUP_INVITE, GROUP_MESSAGE, groupInviteBodyOf, groupMessageBodyOf, groupRosterFromMessages, didcommGroupAddress, parseDidCommGroupAddress, randomDidCommGroupId } from '../didcomm/group-chat.ts'
import { IndexedDbDidCommGroupChatStore } from '../didcomm/group-chat-store.ts'
import { registerWithMediator, type MediatorPollHandle } from '../didcomm/mediator-sync.ts'
import { watchMediatorMultiplexed } from '../didcomm/mediator-multiplex-watch.ts'
import type { DidCommSender } from '../../protocol/didcomm/mediator-transport.ts'
import type { DeliveredMessage } from '../../protocol/didcomm/mediator-pickup.ts'
import { ingestTransportIngress } from '../store/vault/ingress-ingest.ts'
import type { IngressEnvelopeV1 } from '../../protocol/ingress.ts'
import { canonicalBytes, canonicalHash, sha256Bytes } from '../../protocol/canonical.ts'
import { memberKids } from '../mls/group.ts'
import { encodeMlsDeviceCredential } from '../mls/device-credential.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import { ContactKeyReader } from '../store/vault/contact-key-reader.ts'
import { ContactKeyVaultSink } from '../store/vault/contact-key-sink.ts'
import type { ContactKeyV1 } from '../store/vault/contact-key.ts'
import { decodePeerDid2, publicKeyOf } from '../../protocol/didcomm/peer.ts'
import { relationshipMediatorService } from '../didcomm/relationship.ts'
import type { DidCommPlaintext } from '../../protocol/didcomm/message.ts'
import { ingestVaultDelivery } from '../store/vault/delivery-ingest.ts'
import { MimiClientTransport } from '../mimi/client-transport.ts'
import {
  createWalletRelationshipManager,
  type RelationshipWatchStarter,
  type WalletRelationshipManager,
} from '../identity/wallet/relationship.ts'
import { createWalletDidCommOutbox, type WalletDidCommOutbox } from '../identity/wallet/didcomm-outbox.ts'
import { MarkdownDirectoryConnection, observeMarkdownDirectory, removeMarkdownMirrorFile, scanMarkdownProjection, writeMarkdownProjection, type MarkdownMirrorFile } from '../store/vault/markdown-directory.ts'
import { MarkdownSelfWriteGuard, markdownStatusMutation } from '../store/vault/markdown-mirror.ts'
import { createJmapExport, decodeJmapExport, decryptJmapExport, encodeJmapExport, encryptJmapExport, importJmapExport, type JmapExportEnvelopeV1 } from '../store/vault/jmap-export.ts'
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
  const watch = watchMediatorMultiplexed({ mediatorUrl, own, resolveSenderKey, onMessage, onError })
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
  let activeDidCommDevice: { did: string; xKid: string; x25519PrivateKey: Uint8Array; mediatorControlDid: string; mediatorControlKid: string; mediatorControlPrivateKey: Uint8Array } | undefined
  let walletRelationshipManager: WalletRelationshipManager | undefined
  let walletDidCommOutbox: WalletDidCommOutbox | undefined
  let exportMessages: (() => Promise<void>) | undefined
  let importMessages: (() => Promise<void>) | undefined
  try {
    const config = readBisetConfig()
    const { mediatorUrls } = config
    const device = await openDidMdWalletBisetDevice()
    const walletVaultKeys = await openDidMdWalletVaultContentKeys()
    if (walletVaultKeys.did !== device.did) throw new Error('did.md Wallet Vault Content Key belongs to another identity')
    const vaultContentKeys = {
      async currentGeneration(identityId: string) {
        if (identityId !== walletVaultKeys.did) throw new Error('Vault Content Key identity does not match this Wallet session')
        return walletVaultKeys.generation
      },
      async keyForGeneration(identityId: string, generation: string) {
        if (identityId !== walletVaultKeys.did) return undefined
        return walletVaultKeys.keys[generation]?.slice()
      },
    }
    const vaultStore = await IndexedDbVaultStore.open()
    let vaultSync: VaultSyncClient | undefined
    let deviceEvents = await vaultStore.readVaultEvents(device.did)
    // Current Vault membership is the set of self-verifying Biset DIDComm
    // leaves that survived the current generation's public DID commit.
    // Historical event actors are audit history, not active devices: using
    // them here made every past login remain in the UI after VCK rotation.
    let currentVaultDeviceKid: string | undefined
    let currentVaultDeviceKids: string[] = []
    const refreshVaultDevices = async () => {
      currentVaultDeviceKids = (await resolveVaultSyncSiblingRoutes(device.did)).map(route => route.kid)
    }
    const vaultDevices = () => currentVaultDeviceKids
      .map(deviceId => ({ deviceId, current: deviceId === currentVaultDeviceKid }))
      .sort((left, right) => Number(right.current) - Number(left.current) || left.deviceId.localeCompare(right.deviceId))
    const boundary = buildWalletVaultCryptoBoundary(vaultStore, vaultStore, {
      did: device.did,
      deviceKid: device.credential.deviceKid,
      signaturePrivateKey: device.signaturePrivateKey,
      credential: device.credential,
      rootPublicKey: device.rootPublicKey,
    }, vaultContentKeys)
    const readModel = buildLocalJmapReadModel(vaultStore, device.did, vaultContentKeys)
    const vaultProjector = new VaultProjector(vaultStore, boundary.resolver, boundary.signer)
    const vaultRotation = await didMdVaultKeyRotationStatus()
    if (vaultRotation?.phase === 'rewrap') {
      if (walletVaultKeys.generation !== vaultRotation.toGeneration) throw new Error('Vault key rotation does not match the current public generation')
      await rewrapVaultSegmentsForGeneration({ identityId: device.did, fromGeneration: vaultRotation.fromGeneration, toGeneration: vaultRotation.toGeneration, keys: vaultContentKeys, segments: vaultStore, wraps: vaultStore, signer: boundary.signer })
      await completeDidMdVaultKeyRotation()
    }
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
      onCrdtCommitted: async events => {
        deviceEvents.push(...events.map(event => ({ ...event, identityId: device.did })))
        await vaultProjector.recomputeEmails(device.did, events.flatMap(event => event.targetIds))
        if (vaultSync) {
          void resolveVaultSyncSiblingRoutes(device.did, activeDidCommDevice?.xKid)
            .then(routes => vaultSync!.pushToSiblings(routes.map(route => route.kid), events))
            .catch(error => console.warn('[did.md Wallet Vault Sync push]', error instanceof Error ? error.message : error))
        }
      },
    })
    exportMessages = async () => {
      const exported = await createJmapExport({ identityId: device.did, snapshot: await readModel.snapshot(), events: await vaultStore.readVaultEvents(device.did), download: blobId => readModel.download(blobId) })
      const plaintext = confirm('Export unencrypted plaintext JMAP? Choose Cancel for the recommended encrypted export.')
      let bytes: Uint8Array; let suffix: string
      if (plaintext) { bytes = encodeJmapExport(exported); suffix = 'json' }
      else { const current = await vaultContentKeys.currentGeneration(device.did); const key = await vaultContentKeys.keyForGeneration(device.did, current); if (!key) throw new Error('Current Vault Content Key is unavailable'); try { bytes = canonicalBytes(await encryptJmapExport(exported, current, key) as never); suffix = 'biset' } finally { key.fill(0) } }
      downloadFile(bytes, `biset-messages-${exported.exportedAt.replaceAll(':', '-')}.${suffix}`)
    }
    importMessages = async () => {
      const bytes = await chooseFile(); const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as { kind?: string }
      let file
      if (parsed.kind === 'biset.jmap-export-encrypted') { const envelope = parsed as JmapExportEnvelopeV1; const key = await vaultContentKeys.keyForGeneration(device.did, envelope.generation); if (!key) throw new Error(`Vault Content Key generation ${envelope.generation} is unavailable`); try { file = await decryptJmapExport(envelope, key) } finally { key.fill(0) } }
      else file = decodeJmapExport(bytes)
      const result = await importJmapExport(file, { identityId: device.did, actorDeviceId: device.credential.deviceKid, snapshot: await readModel.snapshot(), events: await vaultStore.readVaultEvents(device.did), nextActorSeq: () => sequencer.nextActorSeq(), initialParents: () => sequencer.initialParents(), activeSegment: () => boundary.activeSegment(), signer: boundary.signer, commit: records => vaultStore.commitIncomingRecords(records) })
      if (result.events.length) { await vaultProjector.recomputeEmails(device.did, result.events.flatMap(event => event.targetIds)); if (vaultSync) { const routes = await resolveVaultSyncSiblingRoutes(device.did, activeDidCommDevice?.xKid); await vaultSync.pushToSiblings(routes.map(route => route.kid), result.events) } await refreshInbox(readModel) }
      showSysMsg(`Import: ${result.added} added, ${result.skipped} skipped, ${result.excluded} excluded, ${result.missingBodies} missing bodies`)
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
        const picker = (window as Window & { showDirectoryPicker(options?: { mode?: 'read' | 'readwrite' }): Promise<FileSystemDirectoryHandle> }).showDirectoryPicker
        markdownRoot = await picker({ mode: 'readwrite' })
        await markdownDirectories.save(device.did, markdownRoot)
        await startMarkdownMirror(markdownRoot)
      },
    })
    // Relationship keys are Biset-local, encrypted Vault records.  The
    // Wallet contributes only its public Root key so this browser can verify
    // those records after a reload; no Wallet controller private key enters
    // Biset at any point.
    const walletEventVerifier = boundary.signer
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
      onCommitted: async event => {
        deviceEvents.push({ ...event, identityId: device.did })
        if (vaultSync) { const routes = await resolveVaultSyncSiblingRoutes(device.did, activeDidCommDevice?.xKid); await vaultSync.pushToSiblings(routes.map(route => route.kid), [event]) }
      },
    })
    const walletGroupChatStore = new IndexedDbDidCommGroupChatStore()
    const loadWalletGroupRoster = async (groupId: string) => {
      const cached = await walletGroupChatStore.load(groupId)
      if (cached) return cached
      const recovered = groupRosterFromMessages(groupId, device.did, (await readModel.snapshot()).emails)
      if (!recovered) return undefined
      const now = new Date().toISOString()
      const roster = { groupId, ...recovered, createdAt: now, updatedAt: now }
      await walletGroupChatStore.save(roster)
      return roster
    }
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
          throw new Error('This device is not enrolled in the current Vault generation; reconnect did.md Wallet')
        }
        const mediatorControl = { did: didCommDevice.mediatorControlDid, xKid: didCommDevice.mediatorControlKid, xPriv: didCommDevice.mediatorControlPrivateKey }
        const mediatorRecipient = { did: didCommDevice.did, xKid: didCommDevice.xKid, xPriv: didCommDevice.x25519PrivateKey }
        const mediator = await registerWithMediator(didCommDevice.mediatorUrl, mediatorControl, undefined, didCommDevice.xKid)
        if (mediator.xKid !== didCommDevice.routingKid) throw new Error('Mediator routing key changed since Wallet authorization; enable messaging again')
        didComm = { xKid: didCommDevice.xKid, mediatorUrl: didCommDevice.mediatorUrl }
        activeDidCommDevice = didCommDevice
        // Restore is "only while an existing sibling is reachable" (no
        // recovery-mailbox fallback): a cold device pulls state from an
        // online sibling via the ordinary bootstrap request below, and a
        // fresh Vault with no siblings simply starts empty.
        vaultSync = new VaultSyncClient(device.did, vaultStore, boundary.signer, walletVaultSyncKeys,
          walletVaultSyncTransport({ did: didCommDevice.did, xKid: didCommDevice.xKid, xPriv: didCommDevice.x25519PrivateKey }),
          async result => {
            if (result.addedEventIds.length) deviceEvents = await vaultStore.readVaultEvents(device.did)
            if (result.targetIds.length || result.addedEventIds.length) await vaultProjector.recomputeEmails(device.did, result.targetIds)
          })
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
        // ask every currently published sibling what this CRDT state lacks.
        // The transport re-resolves immediately before each reply/send.
        void resolveVaultSyncSiblingRoutes(device.did, didCommDevice.xKid)
          .then(routes => Promise.all(routes.map(route => vaultSync!.requestState(route.kid))))
          .catch(error => console.warn('[did.md Wallet Vault Sync bootstrap]', error instanceof Error ? error.message : error))
        // Enrollment alone only lets the mediator queue messages.  Open the
        // device-bound live Pickup watch as well, then project every durable
        // DIDComm delivery into this browser's encrypted local Vault.
        // Public first-contact messages resolve from did:webvh.  Once a
        // relationship is established, continuing DIDComm traffic is signed
        // by a did:peer key embedded in its own identifier instead.
        // A relationship INIT registers its temporary did:peer key before
        // the ACCEPT can arrive, but that key is intentionally persisted only
        // after the ACCEPT authenticates it. Keep the active watch's key
        // available to the projector during that narrow interval.
        const watchedRecipientPrivateKeys = new Map<string, Uint8Array>()
        const walletDidCommProjector = new DidCommIngressProjector({
          identityId: device.did,
          actorDeviceId: device.credential.deviceKid,
          resolveOwnKey: async kid => {
            if (kid === didCommDevice.xKid) return { kid, x25519PrivateKey: didCommDevice.x25519PrivateKey }
            const watched = watchedRecipientPrivateKeys.get(kid)
            if (watched) return { kid, x25519PrivateKey: watched }
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
          watchedRecipientPrivateKeys.set(xKid, xPriv)
          startRelationshipWatch(
            relationshipWatchKids, mediatorUrl, { did, xKid, xPriv }, resolveAnyDidCommSenderKey,
            message => handleWalletDidCommMessage(message, xKid, mediatorUrl),
            error => console.warn('[did.md Wallet relationship watch]', error),
          )
        }
        const restoreWalletRelationshipWatches = () => restoreRelationshipWatches(
          walletContactKeyReader,
          startWalletRelationshipWatch,
          error => console.warn('[did.md Wallet relationship restore]', error instanceof Error ? error.message : error),
          (counterpartyDid, error) => console.warn(`[did.md Wallet relationship restore] ${counterpartyDid}:`, error instanceof Error ? error.message : error),
        )
        walletRelationshipManager = createWalletRelationshipManager({
          identityId: device.did,
          frontDoor: { xKid: didCommDevice.xKid, x25519PrivateKey: didCommDevice.x25519PrivateKey },
          relationshipSecret: await openDidMdWalletRelationshipSecret(),
          reader: walletContactKeyReader,
          sink: walletContactKeySink,
          startWatch: startWalletRelationshipWatch,
        })
        walletDidCommOutbox = createWalletDidCommOutbox({
          identityId: device.did,
          store: vaultStore,
          readModel,
          mutationSink,
          ensureContact: toDid => walletRelationshipManager!.ensureContact(toDid),
          onDelivered: () => undefined,
          onError: (error, item) => console.warn(
            `[did.md Wallet DIDComm outbox] ${item.emailId} -> ${item.toDid}:`,
            error instanceof Error ? error.message : error,
          ),
        })
        const handleWalletGroupMessage = async (message: DeliveredMessage): Promise<void> => {
          const plaintext = message.plaintext as DidCommPlaintext
          if (plaintext.type === GROUP_INVITE) {
            const body = groupInviteBodyOf(plaintext)
            if (!body) throw new TypeError('DIDComm group invite body is invalid')
            await walletGroupChatStore.merge(body.groupId, { members: body.members, ...(body.name ? { name: body.name } : {}), updatedAt: new Date().toISOString() })
            for (const member of body.members) {
              if (member !== device.did) void walletRelationshipManager!.ensureContact(member).catch(error => console.warn('[did.md Wallet group mesh]', error))
            }
            return
          }
          const body = groupMessageBodyOf(plaintext)
          if (!body) throw new TypeError('DIDComm group message body is invalid')
          const senderDid = await resolveDidCommSenderDid(message.senderKid, kid => walletContactKeyReader.forCounterpartyKid(kid).then(contact => contact?.counterpartyDid ?? null))
          if (!senderDid) throw new TypeError('DIDComm group sender is not associated with a contact')
          const roster = await loadWalletGroupRoster(body.groupId)
          if (!roster) {
            console.warn(`[did.md Wallet group] dropping message for unknown group ${body.groupId}`)
            return
          }
          const receivedAt = new Date().toISOString()
          const record = await buildDidCommGroupMessageVaultRecord({
            content: body.content,
            emailId: didCommMessageDedupeId(message.senderKid, plaintext.id),
            groupId: body.groupId,
            senderDid,
            otherMembers: roster.members.filter(member => member !== senderDid),
            receivedAt,
            sentAt: body.sentAt ?? (plaintext.created_time ? new Date(plaintext.created_time * 1000).toISOString() : receivedAt),
            ...(body.subject ? { subject: body.subject } : {}),
          }, {
            identityId: device.did, actorDeviceId: device.credential.deviceKid,
            nextActorSeq: () => sequencer.nextActorSeq(), initialParents: () => sequencer.initialParents(),
            activeSegment: () => boundary.activeSegment(), currentSnapshot: () => readModel.snapshot(), signer: boundary.signer,
          })
          await vaultStore.commitLocalMutation({ identityId: device.did, ...record })
          deviceEvents.push(...record.events.map(event => ({ ...event, identityId: device.did })))
          await vaultProjector.recomputeEmails(device.did, record.events.flatMap(event => event.targetIds))
          if (vaultSync) void resolveVaultSyncSiblingRoutes(device.did, activeDidCommDevice?.xKid).then(routes => vaultSync!.pushToSiblings(routes.map(route => route.kid), record.events)).catch(error => console.warn('[did.md Wallet Vault Sync group push]', error))
        }
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
            const candidate = message.plaintext as { type?: unknown }
            if (vaultSync && (candidate.type === VAULT_SYNC_UPDATE || candidate.type === VAULT_SYNC_STATE_REQUEST || candidate.type === VAULT_SYNC_STATE_RESPONSE)) {
              const syncResult = await vaultSync.receive(message.plaintext as VaultSyncMessage, message.senderKid)
              deviceEvents = await vaultStore.readVaultEvents(device.did)
              // A cold sibling receives ContactKey records only AFTER the
              // boot-time restore below has already scanned its empty vault.
              // Start watches for those imported private recipient keys now;
              // the Set in startWalletRelationshipWatch makes this idempotent.
              if (candidate.type !== VAULT_SYNC_STATE_REQUEST && syncResult?.addedEventIds.length) {
                await restoreWalletRelationshipWatches()
              }
              // A sibling login may have published a current-generation leaf
              // immediately before sending this sync message. Re-resolve the
              // public membership instead of deriving it from event history.
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
                // propagated out of onMessage, which mediator-watch.ts
                // never acks -- the same message then redelivers on every
                // reconnect and fails identically forever, permanently
                // wedging delivery to this device entirely ("完全に届かな
                // い", found live, 2026-09-15). The data is safe either way;
                // only the inbox's rendering of it is what's at risk here.
                try {
                  const projection = await rebuildLocalJmapProjection({
                    identityId: device.did, records: vaultStore, resolver: boundary.resolver, verifier: boundary.signer,
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
            if (dropped.type === GROUP_INVITE || dropped.type === GROUP_MESSAGE) {
              await handleWalletGroupMessage(message)
              await refreshInbox(readModel)
              return
            }
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
              device.did, device.credential.deviceKid, message.rawJwe,
            )
            const ingress = await ingestTransportIngress(envelope, walletDidCommProjector, vaultStore)
            if (ingress.targetIds.length) await vaultProjector.recomputeEmails(device.did, ingress.targetIds)
            else await vaultProjector.rebuildAll(device.did)
            // Projecting INIT records the audit event.  Accepting it here is
            // the missing second half: register the private receiver, store
            // its encrypted contact key, then send the DIDComm ACCEPT.  The
            // Pickup ACK is intentionally delayed until all three succeed.
            await walletRelationshipManager!.handleMessage(message, recipientKid, mediatorUrl)
            const eventsAfterIngress = await vaultStore.readVaultEvents(device.did)
            const newlyCommitted = eventsAfterIngress.filter(event => !eventIdsBeforeIngress.has(event.id))
            deviceEvents = eventsAfterIngress
            if (vaultSync && newlyCommitted.length) {
              void resolveVaultSyncSiblingRoutes(device.did, activeDidCommDevice?.xKid)
                .then(routes => vaultSync!.pushToSiblings(routes.map(route => route.kid), newlyCommitted))
                .catch(error => console.warn('[did.md Wallet Vault Sync ingress push]', error instanceof Error ? error.message : error))
            }
            await refreshInbox(readModel, { forceRender: document.querySelector('#focused-thread-card .t-messages') !== null })
        }
        const watch = watchMediatorMultiplexed({
          mediatorUrl: didCommDevice.mediatorUrl,
          own: mediatorControl,
          recipient: mediatorRecipient,
          resolveSenderKey: resolveAnyDidCommSenderKey,
          onMessage: message => handleWalletDidCommMessage(message, didCommDevice.xKid, didCommDevice.mediatorUrl),
          onError: error => console.warn('[did.md Wallet DIDComm watch]', error),
        })
        mediatorPollHandles.push({ stop: () => watch.close() })
        // Relationship keys survive reloads as encrypted Vault records.
        // Re-open their Pickup watches before accepting new messages so an
        // existing Biset conversation cannot disappear after refresh.
        //
        // Neither error handler is optional here: restoreRelationshipWatches
        // defaults to re-throwing when omitted, and a single counterparty
        // stuck in a permanent (non-transient) state -- most notably two
        // independently-initiated, non-superseding ContactKeyV1 records for
        // the same counterparty, "ambiguous; explicit rotation is required"
        // (credential-store.ts's selectUnsuperseded, deliberately fail-
        // closed) -- used to abort configureWalletAccountIfPresent entirely,
        // taking down boot for every OTHER, perfectly healthy contact too
        // (found live, 2026-09-15). One bad relationship must not block the
        // whole account from loading; it only ever needs a fix for that one
        // counterparty, never a full restart.
        await restoreWalletRelationshipWatches()
        // A durable intent might predate this tab (or the previous send's
        // network attempt). A first-contact flush can wait for an ACCEPT for
        // up to a minute, so it must never delay initial UI rendering.
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
    const queueWalletGroupMessage = async (groupId: string, members: string[], input: ReplySendInput, flush = true): Promise<void> => {
      const recipients = members.filter(member => member !== device.did)
      if (recipients.length === 0) throw new Error('A DIDComm group needs another member')
      const now = new Date().toISOString()
      const emailId = crypto.randomUUID()
      const messageId = crypto.randomUUID()
      const snapshot = await readModel.snapshot()
      await mutationSink.commitMailMessage({
        email: {
          id: emailId, threadId: didcommGroupAddress(groupId), mailboxIds: { outbox: true }, keywords: { '$seen': true },
          receivedAt: now, sentAt: now, from: [{ email: device.did }], to: recipients.map(email => ({ email })),
          ...(input.subject ? { subject: input.subject } : {}),
        },
        rawRfc5322: new TextEncoder().encode(input.body),
        didComm: recipients.map(toDid => ({ messageId, toDid })),
      }, snapshot)
      await refreshInbox(readModel)
      // A new group can contain people this device has never contacted.
      // Do not make the compose button wait for each relationship ACCEPT
      // (up to a minute per person) before showing the locally durable
      // message. The caller starts its invitation/flush work afterwards.
      if (flush) {
        await walletDidCommOutbox!.flush()
        await refreshInbox(readModel)
      }
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
      if (!activeDidCommDevice || !walletRelationshipManager || !walletDidCommOutbox) throw new Error('DIDComm is still connecting for this Wallet session')
      const snapshotBeforeSend = await readModel.snapshot()
      const replyThread = input.inReplyTo ? snapshotBeforeSend.emails.find(email => email.id === input.inReplyTo)?.threadId : undefined
      if (replyThread?.startsWith('didcomm-group:')) {
        const groupId = parseDidCommGroupAddress(replyThread)
        const roster = await loadWalletGroupRoster(groupId)
        if (!roster) throw new Error('This DIDComm group roster is unavailable on this device')
        await queueWalletGroupMessage(groupId, roster.members, input)
        return
      }
      if (input.toAddrs.length >= 2 && input.toAddrs.every(address => address.startsWith('did:'))) {
        const groupId = randomDidCommGroupId()
        const members = [device.did, ...input.toAddrs]
        await walletGroupChatStore.save({ groupId, members, ...(input.subject ? { name: input.subject } : {}), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() })
        // Persist and render the sent group message immediately. A recipient
        // must see its GROUP_INVITE before its first GROUP_MESSAGE, so each
        // independent background task sends the invite before asking the
        // durable outbox to deliver that recipient's row.
        await queueWalletGroupMessage(groupId, members, input, false)
        for (const toDid of input.toAddrs) {
          void (async () => {
            try {
              const contact = await walletRelationshipManager.ensureContact(toDid)
              const invited = await sendGroupInvite(contact, { groupId, members, ...(input.subject ? { name: input.subject } : {}) })
              if (!invited.ok) throw new Error(invited.error)
              // Flush only this member. A global flush here lets the first
              // completed invite send another member's GROUP_MESSAGE before
              // that member's own GROUP_INVITE, which the receiver correctly
              // drops as an unknown group.
              await walletDidCommOutbox!.flush(toDid)
              await refreshInbox(readModel)
            } catch (error) {
              console.warn(`[did.md Wallet group invite] ${toDid}:`, error)
            }
          })()
        }
        return
      }
      if (input.toAddrs.length !== 1 || !input.toAddrs[0]?.startsWith('did:')) throw new Error('A did.md Wallet session composes to DID recipients only')
      const toDid = input.toAddrs[0]
      const now = new Date().toISOString()
      const emailId = crypto.randomUUID()
      const messageId = crypto.randomUUID()
      const snapshot = await readModel.snapshot()
      await mutationSink.commitMailMessage({
        email: {
          id: emailId,
          threadId: didCommThreadId(device.did, toDid),
          mailboxIds: { outbox: true },
          keywords: { '$seen': true },
          receivedAt: now,
          sentAt: now,
          from: [{ email: device.did }],
          to: [{ email: toDid }],
          ...(input.subject ? { subject: input.subject } : {}),
        },
        rawRfc5322: new TextEncoder().encode(input.body),
        didComm: [{ messageId, toDid }],
      }, snapshot)
      await refreshInbox(readModel)
      // First contact is established inside the flusher. It waits for a
      // signed ACCEPT and sends only on the private did:peer route; a
      // network or handshake failure retains this exact intent for retry.
      await walletDidCommOutbox.flush()
      await refreshInbox(readModel)
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
        membersOf: async groupId => (await loadWalletGroupRoster(groupId))?.members ?? [],
        groupName: async groupId => (await loadWalletGroupRoster(groupId))?.name,
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
  configureAccountPage({
    did: session.did,
    ...(exportMessages ? { onExportMessages: exportMessages } : {}),
    ...(importMessages ? { onImportMessages: importMessages } : {}),
    wallet: {
      handle: session.handle,
      deviceJkt: session.deviceJkt,
      capabilityExpiresAt: session.capabilityExpiresAt,
      deviceKid: session.deviceKid,
      ...(mediatorCard ? { didComm: mediatorCard } : {}),
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
      onLogOutMediator: async () => beginDidMdWalletDocumentEdit({ removeMediator: true, configuration: readBisetConfig() }),
      onDisconnect: async () => {
        await disconnectWalletAndLocalData()
        await bootClient()
      },
    },
    vault,
    onRotateVaultKey: async () => beginDidMdVaultKeyRotation(readBisetConfig()),
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
export function accountKind(session: AccountSession): AccountSession['kind'] {
  return session.kind
}

bootClient()
