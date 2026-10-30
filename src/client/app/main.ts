import { mountNetworkActivity } from 'lft/net-activity-ui'
import { watchNetwork } from 'lft/net-activity'
import { networkNotes, networkRules } from './ui/network-declaration.ts'
import { preloadSignup } from './ui/signup-preload.ts'
import { startUpdates } from './ui/update.ts'
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
import {
  beginDidMdDocumentEdit,
  type DidMdDocumentChange,
  beginDidMdWalletLogin,
  approvedRotationSeed,
  prepareDidMdMovedDidLoginRequest,
  didMdSessionMovedTo,
  completeDidMdWalletCallback,
  disconnectDidMdWallet,
  openDidMdWalletBisetDidCommDevice,
  openDidMdWalletVaultDevice,
  peekDidMdWalletSession,
  type DidMdActiveSession,
  restoreDidMdWalletSession,
  didMdWalletReconnectState,
  currentWallet,
  allowHandleDomain,
  DID_MD_JUST_CONNECTED_KEY,
} from '../identity/wallet/did-md-oauth.ts'
import { markSeenDone, setMarkSeenHandler } from './ui/seen.ts'
import { setOwnDid } from './ui/did-display.ts'
import { PROFILE_CHANGED } from './ui/account/profile.ts'
import { randomDisplayName } from './ui/account/default-name.ts'
import { refreshInbox, setEncryptedMailOpener, setSignedNameHandler, showApp, showSysMsg } from './ui/shell.ts'
import { labelForDid } from './ui/did-display.ts'
import { configureCompose, type ReplySendInput } from './ui/reply-box.tsx'
import { configureAccountPage, configureComposePage, configureMarkdownVaultToggle, setOnWalletConnected, showAccountPage, showComposePage, updateVaultCardStatus, type VaultCardStatus } from './ui/pages/index.ts'
import { savedPage } from './ui/state.ts'
import { startRouting } from './ui/route.ts'
import { clearPlainStorage } from './local-data.ts'
import { sendComposedWhenReady, sendProblem, takePendingSend } from './ui/pages/compose-page.tsx'
import { setReplyDraft } from './ui/reply-box.tsx'
import { NOTEPAD_THREAD_ID } from './ui/thread-model.ts'
import { readBisetConfig } from './ui/config.ts'
import { installDitoApprover, requestAliasChange } from './ui/approve-dialog.tsx'
import { ditoEmbedOrigin } from '../identity/wallet/dito-embed.ts'
import { mountApp } from './ui/app.tsx'
import { VaultBackedLocalJmapMutationSink } from '../store/projection/vault-mutation-sink.ts'
import { DidCommIngressProjector, isProjectableDidCommIngress } from '../didcomm/ingress-projector.ts'
import { resolveDidCommSenderKey } from '../../protocol/didcomm/sender-key.ts'
import { didCommThreadId } from '../didcomm/basicmessage.ts'
import { answerTrustPing, sendDidCommMessage } from '../didcomm/send-message.ts'
import { didcommGroupAddress, groupConversation, parseDidCommGroupAddress } from '../didcomm/group-chat.ts'
import { registerWithMediator, type MediatorPollHandle } from '../didcomm/mediator-sync.ts'
import { watchMediatorLive } from '../didcomm/mediator-live.ts'
import { preferredMediatorUrl, isTorEnvironment, sameMediatorUrl } from '../didcomm/mediator-endpoints.ts'
import { mediatorInbox } from '../../protocol/didcomm/mediator-device.ts'
import { ingestTransportIngress } from '../store/vault/ingress-ingest.ts'
import type { IngressEnvelopeV1 } from '../../protocol/ingress.ts'
import { bytesToBase64url, canonicalBytes, canonicalHash, sha256Bytes } from '../../protocol/canonical.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SenderKeyNotPublishedError } from '../../protocol/didcomm/sender-key.ts'
import { decodePeerDid2, publicKeyOf } from '../../protocol/didcomm/peer.ts'
import type { DidCommPlaintext } from '../../protocol/didcomm/message.ts'
import { GenerationSeedReader, GenerationSeedSink, generationSeedRecord } from '../store/vault/generation-seed.ts'
import { createGenerationSeedAuthority, type GenerationSeedAuthority } from '../didcomm/generation-seed-bootstrap.ts'
import { publishedRotationKey, rotationSigningKey } from '../didcomm/rotation-key.ts'
import { createRotationManager, type RotationManager } from '../didcomm/rotation-manager.ts'
import { autocryptKeyPatch, contactAvatar, contactCryptoKey, ownCryptoKeyPatch, contactAvatarPatch, contactDisplayName, ownAvatarPatch, ownNamePatch, type ContactSetPayload, type LocalJmapContactCard, contactCardForDid, contactNamePatch, contactSetIntent, currentAutocryptKey, didContactPatch } from '../store/projection/contacts.ts'
import { fromPriorKeyResolver, verifyFromPrior } from '../../protocol/didcomm/from-prior.ts'
import { signingKeyResolver } from '../../protocol/didcomm/jws.ts'
import { expandEndpoint } from '../../protocol/didcomm/mediator-endpoint.ts'
import { didCommRouteFromDocument } from '../../protocol/didcomm/doc-route.ts'
import { resolveDidDocument } from '../../protocol/did-resolve.ts'
import { sendFrontDoorMessage } from '../didcomm/front-door-send.ts'
import { isBasicMessage, pgpArmorOf } from '../didcomm/basicmessage.ts'
import { isPing } from '../../protocol/didcomm/trust-ping.ts'
import { fetchCurrentLog, freshFetch } from '../identity/log-io.ts'
import { entryVersionNumber } from '../../protocol/vh/log.ts'
import { equalBytes } from '../../protocol/canonical.ts'
import { createWalletDidCommOutbox, type WalletDidCommOutbox } from '../identity/wallet/didcomm-outbox.ts'
import { MarkdownDirectoryConnection, observeMarkdownDirectory, removeMarkdownMirrorFile, scanMarkdownProjection, writeMarkdownProjection, type MarkdownMirrorFile } from '../store/vault/markdown-directory.ts'
import { MarkdownSelfWriteGuard, markdownStatusMutation } from '../store/vault/markdown-mirror.ts'
import { createJmapExport, decodeJmapExport, encodeJmapExport, importJmapExport } from '../store/vault/jmap-export.ts'
import { resolveMailAddressDid, resolveRecipient } from '../didcomm/address-resolver.ts'
import { ownPgp, type OwnPgp } from '../pgp/own.ts'
import { handleSecureJoin, inviteUrl, SECURE_JOIN_SUBJECT } from '../pgp/securejoin.ts'
import { beginJoin, handleJoinStep, localPendingJoins, parseInvite, type JoinContext } from '../pgp/securejoin-join.ts'
import { bridgeHostOf, mailAddressOfBridgeDid, ownAutocryptFor, shouldEncrypt } from '../pgp/autocrypt.ts'
import { composeEncryptedMail } from '../pgp/compose.ts'
import type { OwnProfile } from '../pgp/mime.ts'
import type { ProfileConfig } from './ui/account/profile.ts'
import { autocryptKeydata } from '../pgp/keyring.ts'
import { openStoredMail } from '../pgp/open.ts'
import { PGP_KEY_CHANGED, type PgpCardConfig } from './ui/account/pgp-card.tsx'
import { configureDidResolution, verifiedVhAddress } from '../../protocol/did-resolve.ts'
import { StoredVersionMemory } from '../identity/version-memory.ts'
import { StoredDidLinks } from '../identity/did-links.ts'
import { StoredVhPlaces } from '../identity/vh-places.ts'
import { identityKey, sameIdentity } from '../../protocol/vh/identifier.ts'

let mediatorPollHandles: MediatorPollHandle[] = []

// Where a did:vh's log is looked for, and the memory that refuses an older or forked copy of any log.
// The bar across the top and the host the page is talking to, lit while it is on the network (lft: local first toolkit, ../lft).
mountNetworkActivity({ label: 'top-right', rules: networkRules(), notes: networkNotes })
// What the wallet's frame does on the network is reported here, and joins the log.
{ const wallet = ditoEmbedOrigin(); if (wallet) watchNetwork().receiveFrom([wallet]) }
startUpdates()
allowHandleDomain(readBisetConfig().identityDomain)
configureDidResolution({ watchers: readBisetConfig().vhWatchers, memory: new StoredVersionMemory(), links: new StoredDidLinks(), places: new StoredVhPlaces() })

function downloadFile(bytes: Uint8Array, filename: string): void { const url = URL.createObjectURL(new Blob([bytes.slice()])); const link = document.createElement('a'); link.href = url; link.download = filename; link.click(); setTimeout(() => URL.revokeObjectURL(url), 0) }
function chooseFile(): Promise<Uint8Array> { return new Promise((resolve, reject) => { const input = document.createElement('input'); input.type = 'file'; input.accept = '.json,.biset,application/json'; input.onchange = () => { const file = input.files?.[0]; if (!file) { reject(new Error('No import file selected')); return } void file.arrayBuffer().then(value => resolve(new Uint8Array(value)), reject) }; input.click() }) }

/**
 * New-client bootstrap. The only branch this makes is "does this device
 * already have an identity locally": with none, this lands on the account
 * page in its zero-identity state (the signup form mounted inline --
 * the account page's own showAccountPage) -- src.bak's ACTUAL default page
 * whenever there's no session (`if (!sessions.length) showMenuPage('/account')`),
 * not a separate full-page overlay (corrected 2026-08-25 after drifting into
 * inventing that instead). With one, it opens the vault UI (read model +
 * reply-send, PLAN.md §7) against the first local identity's vault, and
 * restores the Wallet-authorized identity's local encrypted read model and
 * begins DIDComm Vault synchronization.
 */
// Registered once, at module load -- a plain function reference, not an
// import back into this module (see pages/new-user-page.tsx's own note on why:
// this file is the bundle's entry point, and a dynamic `import('../../../main.ts')`
// there used to make it also reachable via another module's import edge,
// which silently broke bundling -- bootClient was defined but never invoked).
//
// Lands back on the account page after bootClient's normal has-identity
// flow finishes -- src.bak's own signup handler ends the same way
// (`showMenuPage('/account')`), showing the just-created identity's card,
// not the (empty, since nothing's arrived yet) inbox bootClient's own
// showApp() renders by default. showAccountPage lives here, not in
// pages/new-user-page.tsx, for the identical reason bootClient does: importing it from there
// would close an import cycle.
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
//
// `biset-markdown-mirror` (the Markdown vault's chosen folder) was missing too, and so were the plain-storage records below.
const ALL_LOCAL_DATABASE_NAMES = [
  'biset-did-md-wallet', 'biset-mls-keypackages', 'biset-mls-self-group',
  'biset-vault-core', 'biset-didcomm-group-chat', 'biset-markdown-mirror',
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

/** Disconnects, purges what this browser kept (databases and plain storage), and starts the app over with a page load, so that nothing of the
 * identity is left in memory either (the messages, drafts and the like are state of this page). */
async function disconnectWalletAndLocalData(): Promise<void> {
  await disconnectDidMdWallet()
  await deleteLocalDatabases(ALL_LOCAL_DATABASE_NAMES)
  clearPlainStorage()
  location.replace('/')
  // The page is going away: whatever called this has nothing more to do.
  await new Promise<void>(() => {})
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
async function storeApprovedRotationSeed(did: string, identityId: string, reader: GenerationSeedReader, sink: GenerationSeedSink, authority: GenerationSeedAuthority): Promise<void> {
  const approved = await approvedRotationSeed()
  if (!approved) return
  try {
    const log = await fetchCurrentLog(did, freshFetch())
    const published = publishedRotationKey(log.last.state as Parameters<typeof publishedRotationKey>[0])
    const stored = (await reader.readAll()).some(value => equalBytes(value.seed, approved.seed))
    if (published === rotationSigningKey(approved.seed).publicKeyMultibase && !stored) {
      await sink.store(generationSeedRecord(identityId, approved.seed, entryVersionNumber(log.last.versionId)))
      authority.refresh()
    }
    await approved.forget()
  } finally { approved.seed.fill(0) }
}

// An approved edit changes the session (new DIDComm key, rotation key): rebuild the page from it.
// Without an in-page approver the call navigates to the Wallet and never returns here.
async function editDocument(change: DidMdDocumentChange, config: ReturnType<typeof readBisetConfig>): Promise<void> {
  await bootClient(await beginDidMdDocumentEdit(change, config))
}

// Boot timing (console.info "[boot] ..."): how long each wait before the app shows takes.
const bootStartedAt = performance.now()
async function timed<T>(label: string, work: Promise<T>): Promise<T> {
  const startedAt = performance.now()
  try { return await work } finally { console.info(`[boot] ${label} +${Math.round(performance.now() - startedAt)}ms (at ${Math.round(performance.now() - bootStartedAt)}ms)`) }
}

// Bumped by every boot: work still running from an earlier one must not touch what a later one set up.
let bootGeneration = 0

async function configureWalletAccountIfPresent(
  callbackSession?: Awaited<ReturnType<typeof completeDidMdWalletCallback>>,
): Promise<boolean> {
  let session = callbackSession
  // A stored session is this browser's own, checked when it was saved: what it names is on screen at
  // once, and the Wallet is asked to refresh it in the background (below).
  let refreshing: Promise<DidMdActiveSession | undefined> | undefined
  if (!session) {
    session = await peekDidMdWalletSession()
    if (session) {
      refreshing = timed('restoreDidMdWalletSession', restoreDidMdWalletSession())
      refreshing.catch(() => {}) // the outcome is read at the end; this only keeps an early failure from going unhandled
    }
  }
  if (!session) return false
  // What the page shows of the session: replaced when the Wallet's refresh answers.
  let active: DidMdActiveSession = session
  const generation = bootGeneration
  const stale = (): boolean => generation !== bootGeneration
  let vault: VaultCardStatus | undefined
  let didComm: { xKid: string; mediatorUrl: string; connecting?: boolean; error?: string } | undefined
  let activeDidCommDevice: { did: string; xKid: string; x25519PrivateKey: Uint8Array; mediatorDeviceSecret: Uint8Array } | undefined
  let walletDidCommOutbox: WalletDidCommOutbox | undefined
  // Set when the identity's rotation key needs a Wallet approval (account page).
  let rotationKeyState: 'unpublished' | 'lost' | 'stale' | undefined
  let pgpCard: PgpCardConfig | undefined
  let profileCard: ProfileConfig | undefined
  let exportMessages: (() => Promise<void>) | undefined
  let importMessages: (() => Promise<void>) | undefined
  // The account page as the state stands: called once what is local is ready, and again as each
  // thing the network confirms (the mediator, the key notice) changes it.
  const publishAccount = (): void => {
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
    // The configured onion paired with this card's mediator (same index as `mediatorUrls`) pre-fills the "Enable Tor" prompt (a
    // card already at an onion address offers that one); nothing publishes it until the user confirms.
    const configuredOnionUrl = mediatorCard
      ? readBisetConfig().mediatorOnionUrls[readBisetConfig().mediatorUrls.findIndex(url => sameMediatorUrl(url, mediatorCard.mediatorUrl))]
        ?? (readBisetConfig().mediatorOnionUrls.find(url => sameMediatorUrl(url, mediatorCard.mediatorUrl)))
      : undefined
    configureAccountPage({
      did: active.did,
      ...(exportMessages ? { onExportMessages: exportMessages } : {}),
      ...(importMessages ? { onImportMessages: importMessages } : {}),
      wallet: {
        handle: active.handle,
        deviceJkt: active.deviceJkt,
        capabilityExpiresAt: active.capabilityExpiresAt,
        deviceKid: active.deviceKid,
        ...(mediatorCard ? { didComm: { ...mediatorCard, ...(configuredOnionUrl ? { onionUrl: configuredOnionUrl } : {}) } } : {}),
        // Publishes the DIDComm mediator device -- the one enrollment step
        // that still needs a DID Document edit (other people's DIDComm
        // senders have to be able to find the route publicly).
        onEnableMessaging: async () => {
          const config = readBisetConfig()
          return editDocument({ kind: 'mediator', mediatorUrls: config.mediatorUrls }, config)
        },
        // Same same-tab Wallet approval as onEnableMessaging, just pointed at
        // an explicit mediator URL (the Mediator card's "Edit server") instead
        // of always taking this deployment's configured default -- reuses
        // beginDidMdDocumentEdit as-is, since it already accepts
        // an array and takes its first valid entry (bisetMediatorFor).
        onEditMediator: async (mediatorUrl: string) => editDocument({ kind: 'mediator', mediatorUrls: [mediatorUrl] }, readBisetConfig()),
        // Tor is the same edit as a new server, with the onion address as its default: the DID document then names that one mediator.
        onEnableTor: async (onionUrl: string) => editDocument({ kind: 'mediator', mediatorUrls: [onionUrl] }, readBisetConfig()),
        onLogOutMediator: async () => editDocument({ kind: 'leaveMediator' }, readBisetConfig()),
        onChangeAlias: async () => {
          // dito moves the DID to the new address in its frame. The tab then goes to dito's save page, as
          // the sign-up does: the password manager offers to update the saved account there, and its last
          // page signs this device in under the new DID (the request prepared here) and returns.
          const moved = await requestAliasChange()
          // The log is at the new address now (the old one is gone): the session follows before anything else can fail.
          await didMdSessionMovedTo(moved.host)
          const login = await prepareDidMdMovedDidLoginRequest(moved.did, moved.host, readBisetConfig())
          const origin = ditoEmbedOrigin()
          if (!origin) throw new Error('Changing the alias needs the embedded wallet.')
          location.assign(`${origin}/authorize${login}`)
        },
        onDisconnect: async () => {
          await disconnectWalletAndLocalData()
        },
      },
      vault,
      ...(pgpCard ? { pgp: pgpCard } : {}),
      ...(profileCard ? { profile: profileCard } : {}),
      onRemoveOtherDevices: async () => editDocument({ kind: 'rotation', removeOtherDevices: true }, readBisetConfig()),
      ...(rotationKeyState ? { rotationKey: { state: rotationKeyState, onRenew: async () => editDocument({ kind: 'rotation' }, readBisetConfig()) } } : {}),
      showMessage: showSysMsg,
    })
  }
  // Set once the local setup below has what it needs: connects to the mediator (the network half).
  let startConnect: (() => Promise<void>) | undefined
  // The Wallet's answer to the background refresh of the stored session. A newer capability replaces
  // what the page shows; a session the Wallet turned down was cleared, so boot again for what
  // follows (reconnect or sign-up); a failure that left the session alone (offline) leaves the page be.
  const refreshSession = (): void => {
    refreshing?.then(refreshed => {
      if (stale() || !refreshed) return
      active = refreshed
      publishAccount()
    }, async error => {
      if (stale()) return
      console.warn('[did.md Wallet restore]', error instanceof Error ? error.message : error)
      if (await peekDidMdWalletSession()) showSysMsg(`Could not refresh the Wallet session yet: ${error instanceof Error ? error.message : String(error)}`)
      else void bootClient()
    })
  }
  try {
    const config = readBisetConfig()
    const { mediatorUrls } = config
    const onionMediatorUrls = config.mediatorOnionUrls
    const device = await timed('openDidMdWalletVaultDevice', openDidMdWalletVaultDevice())
    // What every local store and every address of this identity in stored data is keyed by: stable across an
    // alias change (the DID's host), unlike `device.did`, which is for talking to others.
    const identityId = identityKey(device.did)
    setOwnDid(device.did)
    const vaultStore = await timed('IndexedDbVaultStore.open', IndexedDbVaultStore.open())
    let vaultSync: VaultSyncClient | undefined
    let deviceEvents = await timed('readVaultEvents', vaultStore.readVaultEvents(identityId))
    // This identity's devices are the keyAgreement keys its DID document
    // lists now. Historical event actors are audit history, not devices:
    // using them here made every past login remain in the UI.
    let currentVaultDeviceKid: string | undefined
    let currentVaultDeviceKids: string[] = []
    const refreshVaultDevices = async () => {
      currentVaultDeviceKids = await timed('resolveOwnDeviceKids', resolveOwnDeviceKids(device.did))
    }
    const vaultDevices = () => currentVaultDeviceKids
      .map(deviceId => ({ deviceId, current: deviceId === currentVaultDeviceKid }))
      .sort((left, right) => Number(right.current) - Number(left.current) || left.deviceId.localeCompare(right.deviceId))
    const boundary = buildWalletVaultCryptoBoundary(vaultStore, { did: identityId, deviceId: device.deviceId })
    const readModel = buildLocalJmapReadModel(vaultStore, identityId)
    const vaultProjector = new VaultProjector(vaultStore, boundary.resolver)
    const sequencer = await timed('buildActorSequencer', buildActorSequencer(vaultStore, identityId, device.deviceId))
    const mutationSink = new VaultBackedLocalJmapMutationSink({
      accountId: `biset:${identityId}`,
      identityId: identityId,
      actorDeviceId: device.deviceId,
      nextActorSeq: () => sequencer.nextActorSeq(),
      initialParents: () => sequencer.initialParents(),
      activeSegment: () => boundary.activeSegment(),
      signer: boundary.author,
      committer: vaultStore,
      onCrdtCommitted: async events => {
        deviceEvents.push(...events.map(event => ({ ...event, identityId: identityId })))
        await vaultProjector.recomputeEmails(identityId, events.flatMap(event => event.targetIds))
        if (vaultSync) void vaultSync.push(events).catch(error => console.warn('[did.md Wallet Vault Sync push]', error instanceof Error ? error.message : error))
      },
    })
    exportMessages = async () => {
      const exported = await createJmapExport({ identityId: identityId, snapshot: await readModel.snapshot(), events: await vaultStore.readVaultEvents(identityId), download: blobId => readModel.download(blobId) })
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
      if (file.identityId !== identityId) throw new Error('This export belongs to another account')
      if (!confirm(`Import ${file.emails.length} messages and ${file.contactCards?.length ?? 0} contacts exported from this account on ${new Date(file.exportedAt).toLocaleString()}? Messages it adds are marked as imported.`)) return
      const result = await importJmapExport(file, { identityId: identityId, actorDeviceId: device.deviceId, snapshot: await readModel.snapshot(), events: await vaultStore.readVaultEvents(identityId), nextActorSeq: () => sequencer.nextActorSeq(), initialParents: () => sequencer.initialParents(), activeSegment: () => boundary.activeSegment(), signer: boundary.author, commit: records => vaultStore.commitIncomingRecords(records) })
      if (result.events.length) { await vaultProjector.recomputeEmails(identityId, result.events.flatMap(event => event.targetIds)); if (vaultSync) await vaultSync.push(result.events); await refreshInbox(readModel) }
      showSysMsg(`Import: ${result.added} added, ${result.skipped} skipped, ${result.excluded} excluded, ${result.missingBodies} missing bodies; contacts ${result.contactsAdded} added, ${result.contactsUpdated} updated`)
    }
    const markdownDirectories = await MarkdownDirectoryConnection.open()
    const markdownGuard = new MarkdownSelfWriteGuard()
    let sendMarkdownDraft: ((file: MarkdownMirrorFile) => Promise<void>) | undefined
    let markdownRoot = await timed('markdownDirectories.restore', markdownDirectories.restore(identityId))
    let markdownObserver: { disconnect(): void; supported: boolean } | undefined
    const startMarkdownMirror = async (root: FileSystemDirectoryHandle): Promise<void> => {
      markdownObserver?.disconnect()
      await writeMarkdownProjection(root, readModel, identityId, markdownGuard)
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
            if (mutation) await mutationSink.emailSet({ accountId: `biset:${identityId}`, ...mutation }, snapshot)
          }
          await writeMarkdownProjection(root, readModel, identityId, markdownGuard)
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
          await markdownDirectories.remove(identityId)
          return
        }
        const picker = (window as unknown as { showDirectoryPicker(options?: { mode?: 'read' | 'readwrite' }): Promise<FileSystemDirectoryHandle> }).showDirectoryPicker
        markdownRoot = await picker({ mode: 'readwrite' })
        await markdownDirectories.save(identityId, markdownRoot)
        await startMarkdownMirror(markdownRoot)
      },
    })
    // A group conversation is whatever its messages say (group-chat.ts):
    // its participants are those of its latest message.
    const walletGroupConversation = async (thid: string) => groupConversation(thid, (await readModel.snapshot()).emails)
    // The generation seed: Vault records, read and written like every
    // other private credential, and carried to siblings by Vault Sync.
    const walletSeedReader = new GenerationSeedReader({ identityId: identityId, objects: vaultStore, events: vaultStore, segmentKeys: boundary.resolver })
    const walletSeedSink = new GenerationSeedSink({
      identityId: identityId, actorDeviceId: device.deviceId,
      nextActorSeq: () => sequencer.nextActorSeq(), initialParents: () => sequencer.initialParents(),
      activeSegment: () => boundary.activeSegment(), currentSnapshot: () => readModel.snapshot(),
      signer: boundary.author, committer: vaultStore,
      onCommitted: async event => {
        deviceEvents.push({ ...event, identityId: identityId })
        if (vaultSync) await vaultSync.push([event])
      },
    })
    // `label@apex`: the address of an identity at `label.apex` (didmail).
    const ownMailAddress = (() => {
      const domain = device.handle
      const dot = domain.indexOf('.')
      return dot > 0 ? `${domain.slice(0, dot)}@${domain.slice(dot + 1)}` : undefined
    })()
    // The user's OpenPGP key is derived from the generation seed (pgp/derive.ts), not stored: the seed comes from the
    // authority below, once it exists, and from the Vault for the earlier generations.
    let generationSeeds: { current(): Promise<Uint8Array | undefined> } | undefined
    const pgp: OwnPgp | undefined = ownMailAddress ? ownPgp(ownMailAddress, {
      current: async () => generationSeeds?.current(),
      all: async () => (await walletSeedReader.readAll()).map(record => record.seed),
    }) : undefined
    // An encrypted mail is opened where it is shown, with this identity's keys and the key held for its sender.
    // Delta Chat shares its profile in what it signs: the name on a message from a key we hold is the sender's own, and follows
    // it when it changes. The newest message's name is kept on the contact card (a card of its own is made if there is none).
    // A thread that has been open is read: its messages get the $seen keyword (the store keeps it; other devices see it too).
    setMarkSeenHandler(messages => {
      const ids = messages.map(message => message.jmap_id)
      void (async () => {
        const snapshot = await readModel.snapshot()
        const update: Record<string, unknown> = {}
        for (const email of snapshot.emails) if (ids.includes(email.id) && email.keywords['$seen'] !== true) update[email.id] = { keywords: { ...email.keywords, $seen: true } }
        if (Object.keys(update).length === 0) return
        await mutationSink.emailSet({ accountId: `biset:${identityId}`, update }, snapshot)
        await refreshInbox(readModel)
      })().catch(error => console.warn('[mark read]', error instanceof Error ? error.message : error)).finally(() => markSeenDone(ids))
    })
    setSignedNameHandler((did, profile) => {
      void (async () => {
        const snapshot = await readModel.snapshot()
        const card = contactCardForDid(snapshot.contactCards, did)
        const cardId = card?.id ?? didContactPatch(did).cardId
        const writes = [
          profile.name ? contactNamePatch(cardId, card, profile.name, 'signed') : undefined,
          profile.avatar !== undefined ? contactAvatarPatch(cardId, card, profile.avatar) : undefined,
        ].filter((write): write is NonNullable<typeof write> => write !== undefined)
        if (writes.length === 0) return
        await mutationSink.commitIntents([...(card ? [] : [contactSetIntent(didContactPatch(did))]), ...writes.map(contactSetIntent)], snapshot)
        await refreshInbox(readModel)
      })().catch(error => console.warn('[contact name]', error instanceof Error ? error.message : error))
    })
    setEncryptedMailOpener(async (rawBody, email, snapshot) => {
      const card = contactCardForDid(snapshot.contactCards, email.from?.[0]?.email ?? '')
      const held = card && currentAutocryptKey(card)
      return openStoredMail(rawBody, { privateKeys: (await pgp?.all() ?? []).map(key => key.privateKey), senderKeys: held ? [Uint8Array.from(atob(held.keydata), char => char.charCodeAt(0))] : [] })
    })
    // Set where the Secure-Join answers are (below), which needs what is built after this card.
    let joinInvite: ((invite: string) => Promise<{ name: string; address: string }>) | undefined
    // This identity's own name and picture live on its own card in the contact list; what is sent to the people it writes to is made from it.
    const ownCard = async () => contactCardForDid((await readModel.snapshot()).contactCards, identityId)
    const writeOwnCard = async (make: (cardId: string, card: LocalJmapContactCard | undefined) => ContactSetPayload | undefined) => {
      const snapshot = await readModel.snapshot()
      const card = contactCardForDid(snapshot.contactCards, identityId)
      const write = make(card?.id ?? didContactPatch(identityId).cardId, card)
      if (!write) return
      await mutationSink.commitIntents([...(card ? [] : [contactSetIntent(didContactPatch(identityId))]), contactSetIntent(write)], snapshot)
      await refreshInbox(readModel)
    }
    // Writes the key the seed gives to this identity's own card, unless the card names it already; says whether it changed anything.
    let ownKeyChecked = false
    const rememberOwnKey = async (): Promise<boolean> => {
      const key = await pgp?.current()
      if (!key || !ownMailAddress) return false
      const keydata = await autocryptKeydata(key.privateKey, ownMailAddress)
      const before = await ownCard().then(card => card && contactCryptoKey(card)?.fingerprint)
      await writeOwnCard((cardId, card) => ownCryptoKeyPatch(cardId, card, key.fingerprint, keydata))
      return before !== key.fingerprint
    }
    profileCard = {
      async current() { const card = await ownCard(); return { ...(card && contactDisplayName(card) ? { name: contactDisplayName(card)! } : {}), ...(card && contactAvatar(card) ? { avatar: contactAvatar(card)! } : {}) } },
      setName: name => writeOwnCard((cardId, card) => ownNamePatch(cardId, card, name)),
      setAvatar: avatar => writeOwnCard((cardId, card) => ownAvatarPatch(cardId, card, avatar)),
    }
    // A name belongs to an identity from the start: when none is on the own card -- after giving the other devices' Vault a few
    // seconds to bring theirs -- one is made at random and kept there; every device then reads the same one from the Vault.
    setTimeout(() => {
      void ownCard().then(async card => {
        if (card && contactDisplayName(card)) return
        await profileCard!.setName(randomDisplayName())
        window.dispatchEvent(new Event(PROFILE_CHANGED))
      }).catch(error => console.warn('[own display name]', error instanceof Error ? error.message : error))
    }, 5000)
    /** What this identity says about itself in what it signs: its name and picture (the base64 of the image), from its card. */
    const ownProfile = async (): Promise<OwnProfile & { avatarHash?: string }> => {
      const card = await ownCard()
      const name = card && contactDisplayName(card), avatar = card && contactAvatar(card)
      const base64 = avatar?.slice(avatar.indexOf(',') + 1)
      return { ...(name ? { name } : {}), ...(base64 ? { avatarBase64: base64, avatarHash: bytesToBase64url(sha256Bytes(new TextEncoder().encode(avatar!))).slice(0, 16) } : {}) }
    }
    // The picture goes to a contact when it has not got this one: tracked here, per contact, in this browser.
    const sentKey = `biset.profileSent.${identityId}`
    const avatarSentTo = (): Record<string, string> => { try { return JSON.parse(localStorage.getItem(sentKey) ?? '{}') as Record<string, string> } catch { return {} } }
    const markAvatarSent = (did: string, hash: string) => { try { localStorage.setItem(sentKey, JSON.stringify({ ...avatarSentTo(), [did]: hash })) } catch { /* no storage: it is sent again next time */ } }
    if (ownMailAddress && pgp) {
      pgpCard = {
        address: ownMailAddress,
        // The key is remembered on this identity's own card (JSContact cryptoKeys): shown from there at once, and checked against
        // the one the seed gives in the background -- the seed comes only after the DID log has been read.
        async current() {
          const remembered = await ownCard().then(card => card && contactCryptoKey(card))
          if (remembered) {
            if (!ownKeyChecked) { ownKeyChecked = true; void rememberOwnKey().then(changed => { if (changed) window.dispatchEvent(new Event(PGP_KEY_CHANGED)) }).catch(() => { ownKeyChecked = false }) }
            return { fingerprint: remembered.fingerprint, userIds: [`<${ownMailAddress}>`] }
          }
          const key = await pgp.current()
          if (key) void rememberOwnKey().catch(() => undefined)
          return key && { fingerprint: key.fingerprint, userIds: key.userIds }
        },
        onCopyPublic: async () => {
          const key = await pgp.current()
          if (!key) throw new Error('There is no PGP key yet')
          return key.publicArmor
        },
        async inviteLink() {
          const [seed, key] = await Promise.all([generationSeeds?.current(), pgp.current()])
          if (!seed || !key) throw new Error('The key is not ready yet')
          return inviteUrl({ seed, key, address: ownMailAddress, now: Date.now() })
        },
        joinInvite: async invite => {
          if (!joinInvite) throw new Error('Not connected yet')
          return joinInvite(invite)
        },
      }
    }
    // The Wallet branch returns before the ordinary local-identity boot
    // path, which normally loads this projection.  Restore the existing
    // local inbox before rendering so a page reload never looks like it
    // discarded a Wallet account's encrypted history.
    await timed('refreshInbox(restore)', refreshInbox(readModel).catch(error => console.warn('[did.md Wallet inbox restore]', error)))

    vault = { state: 'checking', coordinatorUrl: 'didcomm', vaultId: device.did as never, detail: 'Connecting encrypted Vault sync', devices: vaultDevices() }
    // DIDComm has its own X25519 leaf, never the MLS signing leaf and never
    // a did.md controller key. Wallet published the public leaf and mediator
    // route during the explicit consent that enrolled it; this registration
    // only proves possession of the local X25519 private key to the mediator.
    // A corrupt or independently revoked DIDComm envelope must not make the
    // otherwise healthy Vault sync look unavailable. It has its own sealed
    // device material and its registration is deliberately best-effort.
    let didCommDevice: Awaited<ReturnType<typeof openDidMdWalletBisetDidCommDevice>>
    try { didCommDevice = await timed('openDidMdWalletBisetDidCommDevice', openDidMdWalletBisetDidCommDevice()) }
    catch (error) { console.warn('[did.md Wallet DIDComm]', error) }
    // What is stored is on screen at once, as "connecting"; connect() (below) confirms it with the mediator.
    if (didCommDevice) didComm = { xKid: didCommDevice.xKid, mediatorUrl: didCommDevice.mediatorUrl, connecting: true }
    const connect = async (didCommDevice: NonNullable<Awaited<ReturnType<typeof openDidMdWalletBisetDidCommDevice>>>): Promise<void> => {
        try {
        // URL serialization is canonical at the Wallet boundary (an origin
        // gains its trailing slash), whereas deployment configuration may
        // omit it.  Compare canonical URLs, not their source spellings.
        const authorizedMediator = new URL(didCommDevice.mediatorUrl).toString()
        const configuredMediator = [...mediatorUrls, ...onionMediatorUrls].some(url => {
          try { return new URL(url).toString() === authorizedMediator } catch { return false }
        })
        if (!configuredMediator) throw new Error('Wallet-authorized mediator is not configured by this Biset deployment')
        currentVaultDeviceKid = didCommDevice.xKid
        await timed('refreshVaultDevices', refreshVaultDevices())
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
          mediator = await timed('registerWithMediator', registerWithMediator(activeMediatorUrl, frontDoorInbox))
        } catch (error) {
          if (activeMediatorUrl === didCommDevice.mediatorUrl) throw error
          console.warn('[did.md Wallet DIDComm register] onion entrance unreachable, falling back to canonical', error instanceof Error ? error.message : error)
          activeMediatorUrl = didCommDevice.mediatorUrl
          mediator = await timed('registerWithMediator', registerWithMediator(activeMediatorUrl, frontDoorInbox))
        }
        if (mediator.xKid !== didCommDevice.routingKid) throw new Error('Mediator routing key changed since Wallet authorization; enable messaging again')
        didComm = { xKid: didCommDevice.xKid, mediatorUrl: didCommDevice.mediatorUrl }
        activeDidCommDevice = didCommDevice
        // Restore is "only while an existing sibling is reachable" (no
        // recovery-mailbox fallback): a cold device pulls state from an
        // online sibling via the ordinary bootstrap request below, and a
        // fresh Vault with no siblings simply starts empty.
        vaultSync = new VaultSyncClient(identityId, didCommDevice.xKid, vaultStore,
          walletVaultSyncTransport({ did: didCommDevice.did, xKid: didCommDevice.xKid, xPriv: didCommDevice.x25519PrivateKey }),
          async result => {
            if (result.addedEventIds.length) deviceEvents = await vaultStore.readVaultEvents(identityId)
            if (result.targetIds.length || result.addedEventIds.length) await vaultProjector.recomputeEmails(identityId, result.targetIds)
          },
          // Sized to what this identity's mediator says it takes; a mediator
          // that does not say gets the conservative default.
          vaultSyncChunkBytes(await timed('discoverMaxReceiveBytes', discoverMaxReceiveBytes(mediator, frontDoorInbox).catch(() => undefined))))
        await timed('refreshInbox', refreshInbox(readModel))
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
        const seedAuthority = createGenerationSeedAuthority({
          ownKid: didCommDevice.xKid,
          seeds: walletSeedReader,
          readLog: async () => (await fetchCurrentLog(device.did, freshFetch())).entries,
        })
        generationSeeds = { current: () => seedAuthority.require().then(value => value.seed, () => undefined) }
        await timed('storeApprovedRotationSeed', storeApprovedRotationSeed(device.did, identityId, walletSeedReader, walletSeedSink, seedAuthority))
          .catch(error => console.warn('[did.md Wallet generation seed]', error instanceof Error ? error.message : error))
        try {
          const status = await timed('seedAuthority.status', seedAuthority.status())
          if (status.state === 'unpublished' || status.state === 'lost' || status.state === 'stale') rotationKeyState = status.state
          else if (status.state === 'pending') console.info('[did.md Wallet] waiting for the generation seed from another device')
        } catch (error) {
          console.warn('[did.md Wallet generation seed status]', error instanceof Error ? error.message : error)
        }
        void vaultSync.requestState()
          .catch(error => { console.warn('[did.md Wallet Vault Sync bootstrap]', error instanceof Error ? error.message : error) })
        // DID Rotation (PLAN-refactor.md §4.3, §12.5): every message to a
        // counterparty goes by the route its contact card gives, and a
        // conversation moves to this identity's own did:peer (Y) once the
        // counterparty says it can. Y names the mediator of this identity's
        // public DID document, by DID -- the same on every device.
        let ownMediatorDid: Promise<string | undefined> | undefined
        const mediatorDidOfDocument = () => ownMediatorDid ??= resolveDidDocument(device.did, { fetch: freshFetch() })
          .then(document => {
            // Only a mediator named by DID: Y cannot embed a URL without the
            // mediator's routing key, or what is sent to Y would not be
            // Forward-wrapped and the mediator could not open it.
            const uri = document ? didCommRouteFromDocument(document).endpoint?.uri : undefined
            return typeof uri === 'string' && uri.startsWith('did:') ? uri : undefined
          })
          .catch(error => { ownMediatorDid = undefined; throw error })
        const rotationManager: RotationManager = createRotationManager({
          identityDid: device.did,
          frontDoor: { fromKid: didCommDevice.xKid, x25519PrivateKey: didCommDevice.x25519PrivateKey },
          cards: async () => (await readModel.snapshot()).contactCards,
          async rotation() {
            const [{ seed }, mediatorDid] = await Promise.all([seedAuthority.require(), mediatorDidOfDocument()])
            return mediatorDid ? { seed, mediatorDid } : undefined
          },
          async commit(writes) { await mutationSink.commitIntents(writes.map(contactSetIntent), await readModel.snapshot()) },
          storedSeeds: async () => (await walletSeedReader.readAll()).map(record => record.seed),
          send: (toDid, type, body, options) => sendFrontDoorMessage(toDid, type, body, options),
          async watch(peer) {
            const url = (await expandEndpoint({ uri: decodePeerDid2(peer.did).service[0]!.serviceEndpoint.uri }, freshFetch())).url
            const inbox = mediatorInbox({ did: peer.did, xKid: peer.xKid, xPriv: peer.xPriv }, didCommDevice.mediatorDeviceSecret)
            await registerWithMediator(url, inbox)
            const watch = watchMediatorLive({
              mediatorUrl: url,
              inbox,
              resolveSenderKey: resolveAnyDidCommSenderKey,
              onMessage: message => handleWalletDidCommMessage(message, peer.xKid, url),
              onError: error => console.warn('[did.md Wallet DIDComm rotation watch]', error),
              onMissed: () => catchUpFromSiblings(),
            })
            mediatorPollHandles.push({ stop: () => watch.close() })
          },
          onError: error => console.warn('[did.md Wallet DID Rotation]', error instanceof Error ? error.message : error),
        })
        // Enrollment alone only lets the mediator queue messages.  Open the
        // device-bound live Pickup watch as well, then project every durable
        // DIDComm delivery into this browser's encrypted local Vault. Every
        // message arrives at this device's own key in the DID document.
        const walletDidCommProjector = new DidCommIngressProjector({
          identityId: identityId,
          actorDeviceId: device.deviceId,
          resolveOwnKey: kid => rotationManager.ownKey(kid),
          resolveSenderKey: resolveAnyDidCommSenderKey,
          // Past the host's CDN: a stale document would accept a replaced key.
          verifyFromPrior: (jwt, from) => verifyFromPrior(jwt, from, fromPriorKeyResolver(freshFetch())),
          resolveSigningKey: kid => signingKeyResolver(freshFetch())(kid),
          resolveAddress: did => verifiedVhAddress(did, { fetch: freshFetch() }),
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
          identityId: identityId,
          store: vaultStore,
          readModel,
          mutationSink,
          route: publicDid => rotationManager.route(publicDid),
          fromName: async () => (await ownProfile()).name,
          // To a mail address: this identity's OpenPGP key, which the bridge puts in an Autocrypt header.
          autocrypt: async toDid => ownAutocryptFor(toDid, ownMailAddress ? await pgp?.current().then(key => key && { address: ownMailAddress, privateKey: key.privateKey }) : undefined),
          // To a mail address whose key we hold and who asked for encryption: the message goes as an OpenPGP-encrypted mail.
          encrypt: async (toDid, content, message) => {
            const own = await pgp?.current()
            const host = bridgeHostOf(toDid), toAddress = mailAddressOfBridgeDid(toDid)
            if (!own || !ownMailAddress || !host || !toAddress) return undefined
            const card = contactCardForDid((await readModel.snapshot()).contactCards, toDid)
            const held = card && currentAutocryptKey(card)
            if (!held || !shouldEncrypt(held)) return undefined
            const profile = await ownProfile()
            const sendPicture = profile.avatarBase64 !== undefined && avatarSentTo()[toDid] !== profile.avatarHash
            if (sendPicture) markAvatarSent(toDid, profile.avatarHash!)
            return composeEncryptedMail({
              ...(profile.name ? { fromName: profile.name } : {}), ...(sendPicture ? { avatarBase64: profile.avatarBase64! } : {}),
              id: message.id, ...(message.thid ? { thid: message.thid } : {}), bridgeHost: host, ...(message.subject ? { subject: message.subject } : {}),
              content, sentAt: message.sentAt, fromAddress: ownMailAddress, toAddress,
              own: { privateKey: own.privateKey, keydata: await autocryptKeydata(own.privateKey, ownMailAddress) },
              peerKey: Uint8Array.from(atob(held.keydata), char => char.charCodeAt(0)),
            })
          },
          // A counterparty written to may be one the conversation can move with.
          onDelivered: item => { void rotationManager.offer(item.toDid).catch(() => undefined) },
          onError: (error, item) => {
            const reason = error instanceof Error ? error.message : String(error)
            console.warn(`[did.md Wallet DIDComm outbox] ${item.emailId} -> ${item.toDid}:`, reason)
            // Said once per message, recipient and reason: the row is retried
            // every few seconds, and the same failure each time is no news.
            const key = `${item.outboundEventId}\u0000${item.toDid}\u0000${reason}`
            if (reportedOutboxFailures.has(key)) return
            reportedOutboxFailures.add(key)
            showSysMsg(`Could not send to ${labelForDid(item.toDid)} yet (it stays queued and will be retried): ${reason}`)
          },
        })
        // Delta Chat's Secure-Join, the invited side: an invite link (the account page) is opened in Delta Chat, which then sends
        // two messages that only someone with the invite can make; the answers make this identity a key-contact there.
        const sendSecureJoin = async (to: { did: string }, armored: string, options: { introduction?: boolean }) => {
          const route = await rotationManager.route(to.did)
          const sent = await sendDidCommMessage(route.toDid, '', {
            fromKid: route.fromKid, x25519PrivateKey: route.x25519PrivateKey, subject: SECURE_JOIN_SUBJECT, encrypted: { armored }, ...(options.introduction ? { introduction: true } : {}),
          })
          if (!sent.ok) throw new Error(sent.error)
        }
        // A key a Secure-Join handshake has vouched for: kept on the contact's card, as verified.
        const learnVerifiedKey = async (who: { did: string }, keydata: string, name?: { text: string; source: 'signed' | 'invite' }) => {
          const snapshot = await readModel.snapshot()
          const card = contactCardForDid(snapshot.contactCards, who.did)
          const created = didContactPatch(who.did)
          await mutationSink.commitIntents([
            ...(card ? [] : [contactSetIntent(created)]),
            contactSetIntent(autocryptKeyPatch(card?.id ?? created.cardId, { keydata, seenAt: new Date().toISOString(), preferEncrypt: 'mutual', verified: true })),
            ...(name ? [contactNamePatch(card?.id ?? created.cardId, card, name.text, name.source)].filter((write): write is NonNullable<typeof write> => write !== undefined).map(contactSetIntent) : []),
          ], snapshot)
        }
        const pendingJoins = localPendingJoins(identityId)
        const joinContext = (key: NonNullable<Awaited<ReturnType<NonNullable<typeof pgp>['current']>>>, profile: OwnProfile): JoinContext => ({
          key, address: ownMailAddress!, now: Date.now(), pending: pendingJoins, send: sendSecureJoin, learn: learnVerifiedKey, profile,
        })
        // Opening an invite Delta Chat gave: the first step of the handshake, to the address the invite names.
        joinInvite = async text => {
          const key = await pgp?.current()
          if (!key || !ownMailAddress) throw new Error('The key is not ready yet')
          const invite = parseInvite(text)
          const did = await resolveMailAddressDid(invite.address, readBisetConfig().mailGateways)
          await beginJoin(invite, { did, address: invite.address }, joinContext(key, await ownProfile()))
          return { name: invite.name, address: invite.address }
        }
        const answerSecureJoin = async (message: DidCommPlaintext): Promise<boolean> => {
          const armored = pgpArmorOf(message)
          const fromDid = typeof message.from === 'string' ? message.from : undefined
          const fromAddress = fromDid ? mailAddressOfBridgeDid(fromDid) : undefined
          const seed = await generationSeeds?.current()
          const key = await pgp?.current()
          if (!armored || !fromDid || !fromAddress || !seed || !key || !ownMailAddress) return false
          const party = { did: fromDid, address: fromAddress }
          try {
            const profile = await ownProfile()
            const outcome = await handleSecureJoin(armored, party, {
              seed, key, address: ownMailAddress, now: Date.now(), profile,
              send: (to, answer) => sendSecureJoin(to, answer, {}),
              learn: learnVerifiedKey,
            }) ?? await handleJoinStep(armored, party, joinContext(key, profile))
            if (outcome) console.info(`[did.md Wallet Secure-Join] ${outcome} from ${fromAddress}`)
            return outcome !== undefined
          } catch (error) {
            // Not a valid step (an old invite, a key that does not match): it is not mail either, so it is not shown.
            console.warn('[did.md Wallet Secure-Join] refused:', error instanceof Error ? error.message : error)
            return true
          }
        }
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
              deviceEvents = await vaultStore.readVaultEvents(identityId)
              // A sibling login may have added its device key to the DID
              // document just before sending this sync message. Re-resolve the
              // public device list instead of deriving it from event history.
              if (vault) {
                await timed('refreshVaultDevices', refreshVaultDevices())
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
                    identityId: identityId, records: vaultStore, resolver: boundary.resolver,
                  })
                  await vaultStore.writeProjection(identityId, projection, { state: projection.state })
                  await timed('refreshInbox', refreshInbox(readModel))
                  // A sibling may have started a move: watch its inbox here too.
                  await rotationManager.sync()
                } catch (error) {
                  console.warn('[did.md Wallet Vault Sync projection rebuild]', error instanceof Error ? error.message : error)
                }
              }
              return
            }
            const dropped = message.plaintext as DidCommPlaintext
            // Discover Features: answered here, never recorded (did-rotation.ts).
            if (await rotationManager.handleDiscoverFeatures(dropped, message.senderKid, recipientKid)) return
            // A step of Delta Chat's Secure-Join (pgp/securejoin.ts) is answered here and never shown; an ordinary mail goes on.
            if (isBasicMessage(dropped) && await answerSecureJoin(dropped)) return
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
              identityId, device.deviceId, message.rawJwe,
            )
            const ingress = await ingestTransportIngress(envelope, walletDidCommProjector, vaultStore)
            if (ingress.targetIds.length) await vaultProjector.recomputeEmails(identityId, ingress.targetIds)
            else await vaultProjector.rebuildAll(identityId)
            // Trust Ping 2.0: answer one that asked. Best-effort: the ping is
            // already recorded, and a lost answer is exactly what a ping
            // exists to reveal to its sender.
            const receivingKey = rotationManager.ownKey(recipientKid)
            if (receivingKey) void answerTrustPing(dropped, {
              key: { fromKid: receivingKey.kid, x25519PrivateKey: receivingKey.x25519PrivateKey },
            }).then(result => { if (result && !result.ok) console.warn('[did.md Wallet Trust Ping response]', result.error) })
              .catch(error => console.warn('[did.md Wallet Trust Ping response]', error instanceof Error ? error.message : error))
            // What this message taught the contact cards (a counterparty's
            // move, a confirmation) may start or end a watch; and a
            // counterparty that moved, or that writes, may be one this
            // identity moves with too.
            await rotationManager.sync()
            if (isBasicMessage(dropped) || isPing(dropped)) {
              const publicDid = await rotationManager.counterpartyOf(message.senderKid)
              if (publicDid && !publicDid.startsWith('did:peer:')) {
                void (typeof dropped.from_prior === 'string' ? rotationManager.start(publicDid) : rotationManager.offer(publicDid))
                  .catch(error => console.warn('[did.md Wallet DID Rotation]', error instanceof Error ? error.message : error))
              }
            }
            const eventsAfterIngress = await vaultStore.readVaultEvents(identityId)
            const newlyCommitted = eventsAfterIngress.filter(event => !eventIdsBeforeIngress.has(event.id))
            deviceEvents = eventsAfterIngress
            if (vaultSync && newlyCommitted.length) {
              void vaultSync.push(newlyCommitted)
                .catch(error => console.warn('[did.md Wallet Vault Sync ingress push]', error instanceof Error ? error.message : error))
            }
            await refreshInbox(readModel)
        }
        if (stale()) return
        const watch = watchMediatorLive({
          mediatorUrl: activeMediatorUrl,
          inbox: frontDoorInbox,
          resolveSenderKey: resolveAnyDidCommSenderKey,
          onMessage: message => handleWalletDidCommMessage(message, didCommDevice.xKid, activeMediatorUrl),
          onError: error => console.warn('[did.md Wallet DIDComm watch]', error),
          onMissed: catchUpFromSiblings,
        })
        mediatorPollHandles.push({ stop: () => watch.close() })
        void rotationManager.sync()
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
      publishCompose()
      publishAccount()
    }
    startConnect = didCommDevice && (() => connect(didCommDevice))
    // A DIDComm chat message is committed locally first (the durable
    // outbox), then sent to each recipient's public DID from this device's
    // own key. `thid` makes it part of a group conversation: the same
    // message, addressed to every participant (group-chat.ts).
    const queueWalletChatMessage = async (recipients: string[], input: ReplySendInput, group?: { thid: string }, inReplyTo?: string): Promise<void> => {
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
          threadId: group ? didcommGroupAddress(group.thid) : didCommThreadId(identityId, recipients[0]!),
          mailboxIds: { outbox: true }, keywords: { '$seen': true },
          receivedAt: now, sentAt: now, from: [{ email: identityId }], to: recipients.map(email => ({ email })),
          ...(input.subject ? { subject: input.subject } : {}),
          messageId,
          ...(inReplyTo ? { inReplyTo } : {}),
        },
        rawRfc5322: new TextEncoder().encode(input.body),
        didComm: recipients.map(toDid => ({ messageId, toDid })),
      }, snapshot)
      await refreshInbox(readModel)
      await walletDidCommOutbox.flush()
      await refreshInbox(readModel)
    }
    const sendWalletMessage = async (input: ReplySendInput): Promise<void> => {
      if (!activeDidCommDevice || !walletDidCommOutbox) throw new Error('DIDComm is still connecting for this Wallet session')
      const snapshotBeforeSend = await readModel.snapshot()
      const replyThread = input.inReplyTo ? snapshotBeforeSend.emails.find(email => email.id === input.inReplyTo)?.threadId : undefined
      // A reply in a group conversation goes to every participant of its
      // latest message but this identity (reply-all; PLAN-refactor.md §8).
      if (replyThread?.startsWith('didcomm-group:')) {
        const thid = parseDidCommGroupAddress(replyThread)
        const conversation = await walletGroupConversation(thid)
        if (!conversation) throw new Error('This DIDComm group conversation is unavailable on this device')
        await queueWalletChatMessage(conversation.participants.filter(participant => !sameIdentity(participant, device.did)), input, { thid })
        return
      }
      // A mail address is another name for a DID (address-resolver.ts).
      const toDids = await Promise.all(input.toAddrs.map(address => resolveRecipient(address, readBisetConfig().mailGateways)))
      if (toDids.length === 0 || !toDids.every(address => address.startsWith('did:'))) throw new Error('A did.md Wallet session composes to DID recipients or mail addresses only')
      const recipients = [...new Set(toDids)].filter(address => !sameIdentity(address, device.did))
      // Several recipients start a group conversation of its own.
      if (recipients.length >= 2) {
        await queueWalletChatMessage(recipients, input, { thid: crypto.randomUUID() })
        return
      }
      // A reply to the one counterparty answers the message it replies to.
      const answered = input.inReplyTo && recipients.length === 1 ? snapshotBeforeSend.emails.find(email => email.id === input.inReplyTo) : undefined
      await queueWalletChatMessage(recipients, input, undefined, answered?.id)
    }
    // The Notepad: a message to oneself. It is written into the vault like any message (so every device of the identity has it) and
    // queued for nobody, since there is no one to send it to.
    const writeNote = async (body: string): Promise<void> => {
      const now = new Date().toISOString()
      const snapshot = await readModel.snapshot()
      await mutationSink.commitMailMessage({
        email: {
          id: crypto.randomUUID(), threadId: NOTEPAD_THREAD_ID, mailboxIds: { sent: true }, keywords: { '$seen': true },
          receivedAt: now, sentAt: now, from: [{ email: identityId }], to: [{ email: identityId }], messageId: crypto.randomUUID(),
        },
        rawRfc5322: new TextEncoder().encode(body),
      }, snapshot)
      await refreshInbox(readModel)
    }
    sendMarkdownDraft = async file => {
      const snapshot = await readModel.snapshot(); const thread = snapshot.emails.filter(email => email.threadId === file.parsed.frontmatter.id)
      await sendWalletMessage({ toAddrs: [file.parsed.frontmatter.contact], subject: file.parsed.frontmatter.subject ?? '', body: file.parsed.draft.replace(/(^|\n)!b(?:\n|$)/g, '$1').trim(), ...(thread.at(-1) ? { inReplyTo: thread.at(-1)!.id } : {}) })
    }
    // DIDComm is the identity's own DID once the mediator is (or is being) connected; a failed one is not.
    const publishCompose = (): void => {
    const selfDid = didComm && !didComm.error ? device.did : undefined
    configureCompose({
      selfAddress: identityId,
      selfDid,
      sendReply: sendWalletMessage,
      sendNote: writeNote,
      onError: message => { showSysMsg(message); console.warn('[did.md Wallet send]', message) },
      didcommGroup: {
        membersOf: async thid => (await walletGroupConversation(thid))?.participants ?? [],
        groupName: async thid => (await walletGroupConversation(thid))?.name,
      },
    })
    configureComposePage({
      selfAddress: identityId,
      selfDid,
      sendMessage: sendWalletMessage,
      onError: message => { showSysMsg(message); console.warn('[did.md Wallet compose]', message) },
    })
    }
    publishCompose()
  } catch (error) {
    vault = { state: 'error', coordinatorUrl: 'didcomm', detail: error instanceof Error ? error.message : String(error) }
    console.warn('[did.md Wallet Vault]', error)
  }
  publishAccount()
  void startConnect?.()
  refreshSession()
  return true
}

export /** Sends the message that was waiting for the account (ui/pages/compose-page.tsx's savePendingSend) once the account's DIDComm is connected. A failure
 * leaves it in the new message's box for the writer to send by hand. */
async function sendWhenReady(body: string): Promise<void> {
  sendProblem.set(undefined)
  try {
    await sendComposedWhenReady(body)
    setReplyDraft('new', '')
  } catch (error) {
    // Said where the message is (under the island, staying), and in the console in full: a toast was gone before it could be read.
    console.error('[send after sign-up]', error)
    sendProblem.set(error instanceof Error ? error.message : String(error))
    showComposePage()
  }
}

async function bootClient(callbackSession?: Awaited<ReturnType<typeof completeDidMdWalletCallback>>): Promise<void> {
  bootGeneration++
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
  // only for the new-user page to consume the callback and restore it again.
  // Callback completion saves the replacement session atomically before the
  // account UI below reads it.
  //
  // Not guarded before, this could throw (an invalid/expired code, a
  // network error) as an unhandled rejection out of the top-level
  // `bootClient()` call at the bottom of this file -- aborting boot before
  // showApp()/showAccountPage() ever ran, leaving a blank page with no
  // visible error. the new-user page's own callback handler still gets a
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
  // run here -- the local IdentityRecord store, did:vh genesis/restore,
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
  if (await timed('configureWalletAccountIfPresent (total)', configureWalletAccountIfPresent(completedWalletEdit))) {
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
    // What was being written when the account had to be made is back in its box, and goes out as soon as the account can send. That is the
    // page to land on (not the account's, which a sign-up otherwise lands on): a message that fails to go has to be seen where it is.
    const pendingBody = takePendingSend()
    startRouting()
    console.info(`[boot] app shown at ${Math.round(performance.now() - bootStartedAt)}ms`)
    const justConnected = completedWalletEdit || sessionStorage.getItem(DID_MD_JUST_CONNECTED_KEY) === '1'
    sessionStorage.removeItem(DID_MD_JUST_CONNECTED_KEY)
    if (pendingBody !== undefined) {
      setReplyDraft('new', pendingBody)
      showComposePage()
      void sendWhenReady(pendingBody)
    } else if (justConnected) {
      showAccountPage()
    } else {
      // The root names nothing to open: it is the account's own page (and the address bar then reads its address).
      if (savedPage() === 'account' || location.pathname === '/') showAccountPage()
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
          return beginDidMdWalletLogin(config.mediatorUrls, config)
        },
        onDisconnect: async () => { await disconnectWalletAndLocalData() },
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
  // The wallet's frames are loaded now, out of sight, so that whatever the person turns to (a new message, the log-in) has them ready.
  preloadSignup()
  // With no account the address bar can still name a message to write (/new, /alice@gmail.com).
  startRouting()
}

mountApp()
installDitoApprover()
/** Keeps the initial public API explicit while account routing is implemented. */
bootClient()
