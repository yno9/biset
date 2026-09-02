import type { AccountSession } from './local-jmap/transport.ts'
import { IndexedDbIdentityRecordStore } from './identity/record-store.ts'
import {
  buildActorSequencer,
  buildLocalJmapProjectionRebuild,
  buildLocalJmapReadModel,
  buildMailSubmitter,
  buildRestoreTransferVerifier,
  buildVaultCryptoBoundary,
  buildVaultDeliveryProjector,
  enableDidComm,
  ensureMimiProviderPublished,
  fromHex,
  mailFromForIdentity,
  maintainSelfGroup,
  migrateLocalSegmentKeysToStorageRoot,
  repairCurrentLocalSegmentKeyWraps,
} from './identity/bootstrap.ts'
import { IndexedDbMlsSelfGroupStore } from './mls/store.ts'
import { IndexedDbMlsKeyPackageStore } from './mls/keypackage-store.ts'
import { IndexedDbVaultStore } from './vault/store.ts'
import { setOnIdentityCreated } from './ui/account-create.ts'
import { refreshInbox, showApp, showSysMsg } from './ui/shell.ts'
import { configureCompose } from './ui/thread.ts'
import type { ReplySendInput } from './ui/thread.ts'
import { configureAccountPage, showAccountPage, updateVaultCardStatus, type VaultCardStatus } from './ui/account-page.ts'
import { configureComposePage } from './ui/compose-page.ts'
import { readBisetConfig } from './ui/config.ts'
import { VaultBackedLocalJmapMutationSink } from './local-jmap/vault-mutation-sink.ts'
import type { LocalJmapMutationSink } from './local-jmap/gateway.ts'
import { LocalJmapGateway, LocalJmapTransport } from './local-jmap/gateway.ts'
import { buildOutboundRfc5322 } from './mail/rfc5322-builder.ts'
import { MailIngressProjector } from './mail/ingress-projector.ts'
import { synchronizeMailIngress } from './mail/ingress-workflow.ts'
import { CoreIngressTransport } from './vault/core-ingress-transport.ts'
import { CoreVaultDeliveryTransport } from './vault/core-delivery-transport.ts'
import type { IngressVerifierProjector } from './vault/ingress-ingest.ts'
import { DidCommIngressProjector } from './didcomm/ingress-projector.ts'
import { resolveDidCommSenderKey } from './didcomm/webvh-resolve.ts'
import { initiateRelationship, sendRelationshipAccept, sendRelationshipMessage, type PendingRelationship } from './didcomm/send-message.ts'
import { MAIL_BRIDGE_INBOUND, mailBridgeInboundBodyOf } from './didcomm/mail-bridge.ts'
import { didCommThreadId } from './didcomm/basicmessage.ts'
import { registerWithMediator, type MediatorPollHandle } from './didcomm/mediator-sync.ts'
import { watchMediator } from './didcomm/mediator-watch.ts'
import type { DidCommSender } from './didcomm/mediator-transport.ts'
import type { DeliveredMessage } from './didcomm/mediator-pickup.ts'
import { ingestTransportIngress } from './vault/ingress-ingest.ts'
import { flushVaultDeliveryOutbox } from './vault/delivery-outbox.ts'
import type { IngressEnvelopeV1 } from './protocol/ingress.ts'
import { base64urlToBytes, canonicalHash, equalBytes, sha256Bytes } from './protocol/canonical.ts'
import { fetchRouting, mimiVaultRoomFromRouting, putRouting, setRoutingMimiVaultRoom, setRoutingName } from './didcomm/webvh-routing.ts'
import { rotateToPreRotatedKey } from './identity/webvh/prerotation.ts'
import { moveWebvhIdentity } from './identity/webvh/move.ts'
import { adoptPendingMove } from './identity/webvh/adopt-move.ts'
import { encodeMultikey } from './identity/webvh/multikey.ts'
import { rotateSelfGroupGeneration, type SelfGroupSigner } from './mls/self-group.ts'
import { decodeKeyPackage, encodeKeyPackage, generateOwnKeyPackage, joinMlsGroup, keyPackageRefOf, memberDeviceCredentialBytes, memberKids, memberList, ownMlsDeviceCredential, ownSignaturePrivateKey, roomMetadataOf, welcomeRecipientRefs, type OwnKeyPackage } from './mls/group.ts'
import { createMlsDeviceCredential, encodeMlsDeviceCredential } from './mls/device-credential.ts'
import { CoordinatorMlsDeliveryTransport } from './mls/coordinator-mls-delivery-transport.ts'
import { CoreRosterInstallTransport } from './mls/core-roster-install-transport.ts'
import { IndexedDbMlsConversationGroupStore, type LoadedConversationGroup } from './mls/conversation-group-store.ts'
import type { ClientState } from './mls/vendor/index.ts'
import { ConversationMlsDeliveryTransport } from './mls-ds/client-transport.ts'
import { watchConversationGroupDeliveries, type ConversationGroupWatch } from './mls/conversation-group-watch.ts'
import { applyConversationGroupLogEntry, buildConversationGroupVaultRecord } from './mls/conversation-group-sync.ts'
import type { ConversationLogEntry } from './protocol/conversation-mls-ds.ts'
import { addMembersToConversationGroup, createConversationGroup, randomConversationGroupId, randomGroupLocalKeypair, setConversationGroupRoomName } from './mls/conversation-group.ts'
import { sendConversationTextMessage } from './mls/conversation-group-egress.ts'
import { parseMlsGroupAddress } from './mls/mimi-content-projector.ts'
import {
  CONVERSATION_GROUP_INVITE, CONVERSATION_GROUP_JOIN_READY, CONVERSATION_GROUP_WELCOME_READY,
  conversationGroupInviteBodyOf, conversationGroupJoinReadyBodyOf, conversationGroupWelcomeReadyBodyOf,
  sendConversationGroupInvite, sendConversationGroupJoinReady, sendConversationGroupWelcomeReady,
} from './mls/conversation-group-invite.ts'
import { conversationKeyPackagePublishSigningBytes, conversationKeyPackageTakeSigningBytes, conversationDeliveriesPullSigningBytes } from './protocol/conversation-mls-ds-signing.ts'
import type { ConversationKeyPackagePublishV1, ConversationKeyPackageTakeV1, ConversationDeliveriesPullV1 } from './protocol/conversation-mls-ds.ts'
import { resolveMimiProviderUrl } from './didcomm/webvh-resolve.ts'
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
import { BisetOid4vpWallet, discoverTrustedAnchorOid4vpIssuer } from './oid4vp/wallet.ts'
import { AnchorOidcPkceClient } from './oidc/client.ts'
import { VaultCoordinatorTransport } from './vault/coordinator-transport.ts'
import { coordinatorStreamCheckpointIsBehind, flushCoordinatorDeliveryOutbox, flushCoordinatorStreamOutbox, synchronizeCoordinatorDelivery, synchronizeCoordinatorStream } from './vault/coordinator-sync.ts'
import { ingestVaultDelivery } from './vault/delivery-ingest.ts'
import { advanceVaultCoordinatorGroup, createAndProvisionVaultCoordinator } from './vault/coordinator-lifecycle.ts'
import type { LocalVaultCoordinatorBindingV1 } from './vault/store.ts'
import { createVaultMlsJoinCandidate, joinVaultMlsFromWelcome, prepareVaultMlsAdd, restoreVaultMlsJoinCandidate } from './mls/vault-group.ts'
import { vaultMlsKeyPackageSigningBytes, vaultMlsMemberRequestSigningBytes, vaultMlsTransitionSigningBytes } from './protocol/vault-mls-ds.ts'
import { vaultCoordinatorCheckpointSigningBytes, vaultCoordinatorPullSigningBytes } from './protocol/coordinator.ts'
import { createRecoveryArchiveSnapshot } from './vault/recovery-archive-export.ts'
import { createCoordinatorCheckpoint, createPortableCoordinatorCheckpoint, deriveCoordinatorRecoveryKek, openCoordinatorCheckpoint, openPortableCoordinatorCheckpoint } from './vault/coordinator-checkpoint.ts'
import { rewrapRecoveryArchiveForCurrentEpoch } from './vault/recovery-archive-rewrap.ts'
import { VAULT_STORAGE_EPOCH, VAULT_STORAGE_GROUP_ID } from './vault/storage-root.ts'
import { MimiClientTransport } from './mls/mimi-client-transport.ts'
import { PersistedMimiVaultSession } from './mls/mimi-vault-session.ts'
import { createMimiVaultRoom, joinMimiVaultRoom } from './mls/mimi-vault-room.ts'
import { sendMimiVaultCheckpoint, synchronizeMimiVault } from './vault/mimi-vault-sync.ts'
import { deliveriesPullSigningBytes } from './mimi/authorizer.ts'

const hex = (value: Uint8Array): string => Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('')
let pollTimer: ReturnType<typeof setInterval> | undefined
let coordinatorPollTimer: ReturnType<typeof setInterval> | undefined
let mediatorPollHandles: MediatorPollHandle[] = []
let autoConnectCoordinator: (() => Promise<void>) | undefined

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
setOnIdentityCreated(async (reason, options) => {
  await bootClient({ coordinatorLoginPopup: options?.coordinatorPopup })
  showAccountPage()
  if (autoConnectCoordinator) {
    showSysMsg(reason === 'restored' ? 'Restoring encrypted Vault from Coordinator…' : 'Connecting encrypted Vault…')
    try {
      await autoConnectCoordinator()
      showSysMsg(reason === 'restored' ? 'Coordinator Vault restored' : 'Vault connected')
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.warn('[coordinator/automatic-connect]', message)
      showSysMsg(`Coordinator connection failed: ${message}`)
    }
  } else {
    try { options?.coordinatorPopup?.close() } catch {}
  }
})

export async function bootClient(options: { coordinatorLoginPopup?: Window } = {}): Promise<void> {
  autoConnectCoordinator = undefined
  // Cleared unconditionally, before any branch -- logout's own re-entry into
  // bootClient() lands on the zero-identity branch below, which returns
  // before the has-identity branch's own clearInterval would ever run,
  // leaving the OLD interval alive and polling a vault store logout just
  // closed. A re-registration below (has-identity branch) replaces this.
  if (pollTimer !== undefined) { clearInterval(pollTimer); pollTimer = undefined }
  if (coordinatorPollTimer !== undefined) { clearInterval(coordinatorPollTimer); coordinatorPollTimer = undefined }
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
    configureAccountPage({ did: null })
    showApp()
    showAccountPage()
    return
  }

  const selfGroupStore = new IndexedDbMlsSelfGroupStore()
  const keyStore = new IndexedDbMlsKeyPackageStore()
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
  // automatically at boot, and every closure that reads it (sendReply,
  // syncMailIngress) has to see the new didCommKid/didCommX25519PrivateKey
  // without needing a page reload.
  let identity = records[0]!
  const readModel = buildLocalJmapReadModel(vaultStore, selfGroupStore, identity.did, identity.masterSeed)
  const { apexDomain, anchorBaseUrl, anchorOidcClientId, coreBaseUrl, mediatorUrls, coordinatorUrl, mimiSelfBaseUrl, conversationMlsDsBaseUrl } = readBisetConfig()
  // A WebVH PUT can succeed while the following MLS submission loses the
  // network. Reconcile the executing leaf before ordinary maintenance so
  // rotation is retryable after reload instead of leaving a stranded Vault.
  if (coordinatorUrl && !mimiSelfBaseUrl) {
    for (const record of records) {
      if (!record.deviceKid) continue
      const stored = await selfGroupStore.load(record.did).catch(() => undefined)
      if (!stored || ownMlsDeviceCredential(stored.state).generation === record.generation) continue
      try {
        const prior = ownMlsDeviceCredential(stored.state)
        const credential = createMlsDeviceCredential(record.did, record.generation, prior.signaturePublicKey, fromHex(record.rootPrivateKey), fromHex(record.signPrivateKey))
        const sign: SelfGroupSigner = bytes => ed25519.sign(bytes, ownSignaturePrivateKey(stored.state))
        const transport = new CoordinatorMlsDeliveryTransport({ baseUrl: coordinatorUrl, deviceCredential: encodeMlsDeviceCredential(credential) })
        await rotateSelfGroupGeneration(selfGroupStore, transport, record.did, record.deviceKid, credential, sign)
      } catch (error) {
        console.warn(`[rotation/reconcile] ${record.did}:`, error instanceof Error ? error.message : error)
      }
    }
  }
  // Catch up MLS and repair every local SegmentKey wrap before any inbox,
  // credential, or relationship reader attempts decryption. Running this
  // near the end of boot used to render an empty inbox first; if a segment
  // had skipped more than one epoch, the transition-only self-grant could
  // not repair it at all on later reloads.
  if (coreBaseUrl && coordinatorUrl && !mimiSelfBaseUrl) {
    for (const record of records) {
      await maintainSelfGroup(selfGroupStore, keyStore, record, { coreBaseUrl, mlsDeliveryBaseUrl: coordinatorUrl, wraps: vaultStore, segments: vaultStore }).catch(e => {
        console.warn(`[maintainSelfGroup] ${record.did}:`, e instanceof Error ? e.message : e)
      })
    }
  }
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
  let coordinatorOidc: AnchorOidcPkceClient | undefined
  let coordinatorOidcInitialization: Promise<AnchorOidcPkceClient> | undefined
  let connectCoordinator: (() => Promise<void>) | undefined
  let createCoordinatorInvitation: (() => Promise<{ invitation: string; expiresAt: string }>) | undefined
  let joinCoordinatorInvitation: ((invitation: string) => Promise<void>) | undefined
  let approveCoordinatorDevice: (() => Promise<void>) | undefined
  let coordinatorBindingActive = false
  let flushCoordinatorOutbox: (() => Promise<{ appendedEntryIds: string[]; failedEntryId?: string; failureReason?: string }>) | undefined
  const mimiVaultConfigured = !!(mimiSelfBaseUrl && identity.deviceKid)
  const coordinatorConfigured = !mimiVaultConfigured && !!(anchorBaseUrl && anchorOidcClientId && coordinatorUrl && identity.deviceKid)
  let vaultDevices = await selfGroupStore.load(identity.did).then(stored => stored
    ? memberKids(stored.state, identity.did).map(deviceId => ({ deviceId, current: deviceId === identity.deviceKid }))
    : []).catch(() => [])
  let vaultCardStatus: VaultCardStatus | undefined = (coordinatorConfigured || mimiVaultConfigured) ? {
    state: 'checking', coordinatorUrl: mimiVaultConfigured ? mimiSelfBaseUrl : coordinatorUrl, detail: mimiVaultConfigured ? 'Opening MIMI Self Vault' : 'Checking saved login session', devices: vaultDevices,
  } : undefined
  const setVaultCard = (next: VaultCardStatus): void => {
    next = { ...next, devices: vaultDevices }
    if (vaultCardStatus && JSON.stringify(vaultCardStatus) === JSON.stringify(next)) return
    vaultCardStatus = next
    updateVaultCardStatus(next)
  }
  const ensureCoordinatorOidc = async (): Promise<AnchorOidcPkceClient> => {
    if (coordinatorOidc) return coordinatorOidc
    if (!coordinatorConfigured) throw new Error('Coordinator login is not configured')
    coordinatorOidcInitialization ??= (async () => {
      const trust = await discoverTrustedAnchorOid4vpIssuer(anchorBaseUrl)
      const wallet = new BisetOid4vpWallet({ identityId: identity.did, generation: identity.generation, trust, store: loginWalletStore })
      if (!(await wallet.current())) {
        await wallet.enroll({
          did: identity.did,
          authenticationVerificationMethod: `did:key:${encodeMultikey(fromHex(identity.signPublicKey))}#${encodeMultikey(fromHex(identity.signPublicKey))}`,
          authenticationPrivateKey: fromHex(identity.signPrivateKey),
        })
      }
      return new AnchorOidcPkceClient({
        issuer: anchorBaseUrl,
        clientId: anchorOidcClientId,
        audience: coordinatorUrl,
        allowedScopes: ['vault.create', 'vault.group.install', 'vault.append', 'vault.pull', 'vault.ack'],
        wallet,
        openPopup: (url, target, features) => {
          const reserved = options.coordinatorLoginPopup
          options.coordinatorLoginPopup = undefined
          if (reserved && !reserved.closed) return reserved
          return window.open(url, target, features)
        },
      })
    })()
    try {
      coordinatorOidc = await coordinatorOidcInitialization
      return coordinatorOidc
    } finally {
      coordinatorOidcInitialization = undefined
    }
  }
  if (coordinatorConfigured) {
    try {
      await ensureCoordinatorOidc()
    } catch (error) {
      console.warn(`[OID4VP enrollment] ${identity.did}:`, error instanceof Error ? error.message : error)
    }
  }
  const initialCoordinatorBinding = await vaultStore.readCoordinatorBinding(identity.did).catch(() => undefined)
  const initialCoordinatorPendingJoin = initialCoordinatorBinding ? undefined : await vaultStore.readCoordinatorPendingJoin(identity.did).catch(() => undefined)
  void initialCoordinatorPendingJoin
  // Signs with the current Sign key (the key routing.json authorization
  // keyAgreement/alsoKnownAs entries are already signed with, webvh-routing.ts's
  // DataIntegrityProof) -- account-page.ts never sees key material itself,
  // only calls this callback.
  const editName = async (name: string): Promise<void> => {
    const signPrivateKey = fromHex(identity.signPrivateKey)
    const signPublicKey = fromHex(identity.signPublicKey)
    await setRoutingName(identity.did, name, { updateKey: encodeMultikey(signPublicKey), privateKey: signPrivateKey }, fetch)
  }
  // did:webvh pre-rotation (identity/webvh/prerotation.ts) — independent of
  // coreBaseUrl/deviceKid, same reasoning as editName above:
  // this is a plain did.jsonl operation against the identity's own domain,
  // nothing to do with the mail/DIDComm core. The Spare Key phrase itself
  // (generate/display/prompt) is handled entirely in account-page.ts, which
  // only ever hands this file the already-revealed key bytes to sign with —
  // same "key stays here" split as editName.
  const rotateKeyRotation = async (revealedPrivateKey: Uint8Array, revealedPublicKey: Uint8Array, nextKeyHash: string): Promise<void> => {
    if (!identity.deviceKid || !coordinatorUrl) throw new Error('This device is not connected to the Coordinator self group')
    const deviceKid = identity.deviceKid
    const generation = await rotateToPreRotatedKey({ did: identity.did, revealedPrivateKey, revealedPublicKey, nextKeyHash })
    const previousCredential = await loginWalletStore.current(identity.did, anchorBaseUrl).catch(() => undefined)
    identity = { ...identity, signPrivateKey: hex(revealedPrivateKey), signPublicKey: hex(revealedPublicKey), generation }
    await recordStore.put(identity)
    if (previousCredential) await loginWalletStore.remove(identity.did, anchorBaseUrl, previousCredential.credentialId)
    if (anchorOidcClientId) await loginWalletStore.removeOidcRefreshSession(identity.did, anchorBaseUrl, anchorOidcClientId)

    const stored = await selfGroupStore.load(identity.did)
    if (!stored) throw new Error('No self-group state for this identity')
    const oldCredential = ownMlsDeviceCredential(stored.state)
    const credential = createMlsDeviceCredential(identity.did, generation, oldCredential.signaturePublicKey, fromHex(identity.rootPrivateKey), revealedPrivateKey)
    const sign: SelfGroupSigner = bytes => ed25519.sign(bytes, ownSignaturePrivateKey(stored.state))
    const transport = new CoordinatorMlsDeliveryTransport({ baseUrl: coordinatorUrl, deviceCredential: encodeMlsDeviceCredential(credential) })
    const state = await rotateSelfGroupGeneration(selfGroupStore, transport, identity.did, deviceKid, credential, sign)
    if (!coreBaseUrl) throw new Error('Self Group roster endpoint is not configured')
    await maintainSelfGroup(selfGroupStore, keyStore, identity, {
      coreBaseUrl, mlsDeliveryBaseUrl: coordinatorUrl, wraps: vaultStore, segments: vaultStore,
    })
    vaultDevices = memberKids(state, identity.did).map(deviceId => ({ deviceId, current: deviceId === identity.deviceKid }))
    await coordinatorOidc?.clear().catch(() => {})
    coordinatorOidc = undefined
    coordinatorBindingActive = false
    flushCoordinatorOutbox = undefined
    if (vaultCardStatus) setVaultCard({ ...vaultCardStatus, state: 'reconnect-required', detail: 'Sign generation rotated. Reconnect once to activate it at the Coordinator.' })
  }
  // did:webvh domain move (identity/webvh/move.ts) — same coreBaseUrl-
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
    onRotateKeyRotation: rotateKeyRotation,
    onMoveIdentity: moveIdentity,
    vault: vaultCardStatus,
    onConnectCoordinator: coordinatorConfigured ? async () => {
      if (!connectCoordinator) throw new Error('Coordinator is still initializing')
      await connectCoordinator()
    } : undefined,
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
    // vaultStore -- selfGroupStore/keyStore/recordStore never closed
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
    try { keyStore.close() } catch { /* best-effort */ }
    try { recordStore.close() } catch { /* best-effort */ }
    try { loginWalletStore.close() } catch { /* best-effort */ }
    const databaseNames = ['biset-identity', 'biset-mls-keypackages', 'biset-mls-self-group', 'biset-vault-core', 'biset-wallet']
    await Promise.all(databaseNames.map(name => new Promise<void>(resolve => {
      const request = indexedDB.deleteDatabase(name)
      request.onsuccess = () => resolve()
      request.onerror = () => resolve()
      request.onblocked = () => resolve()
      setTimeout(resolve, 3000) // a step that never settles must not outlive its budget
    })))
    await bootClient()
  }

  let syncMailIngress: (() => Promise<void>) | undefined
  let flushDidCommTransportOutbox: (() => Promise<void>) | undefined
  // Reply-send needs the same signing/MLS boundary maintainSelfGroup already
  // requires a deviceKid for -- with neither a core to submit through nor a
  // device identity to sign with, the UI stays read-only, matching how this
  // file has always treated a missing coreBaseUrl.
  if (coreBaseUrl && apexDomain && identity.deviceKid) {
    // Captured once, before enableDidComm's own `identity = ...` reassignment
    // below widens `identity.deviceKid` back to `string | undefined` for
    // TypeScript's control-flow narrowing -- enableDidComm never actually
    // touches deviceKid (only didCommKid/didCommX25519PrivateKey), but its
    // return type is the general IdentityRecord, so the narrowing doesn't
    // survive the reassignment even though the value can't actually change.
    const deviceKid = identity.deviceKid
    const boundary = buildVaultCryptoBoundary(vaultStore, vaultStore, selfGroupStore, identity)
    const flushReplicationOutbox = async () => {
      if (coordinatorBindingActive) {
        if (coordinatorOidc?.hasFreshAccessToken() && flushCoordinatorOutbox) {
          const result = await flushCoordinatorOutbox()
          if (result.failedEntryId) console.warn(`[coordinator/outbox] ${result.failedEntryId}: ${result.failureReason ?? 'append failed'}`)
          return result
        }
        // Once an opaque Coordinator binding exists, never leak/fallback to
        // the legacy identity-keyed Core route. Retain the durable outbox
        // until the user renews the short-lived token.
        return { appendedEntryIds: [] }
      }
      return flushVaultDeliveryOutbox(vaultStore, new CoreVaultDeliveryTransport({ baseUrl: coreBaseUrl }), boundary.signer, identity.did)
    }
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

    // Conversation Group (MIMI/mls-ds) delivery wiring -- send, live receive
    // (SSE watch), catch-up receive (pull, via applyConversationGroupLogEntry),
    // and the peer-to-peer invite handshake (conversation-group-invite.ts).
    // Reuses this device's OWN self-group MLS leaf credential
    // (ownMlsDeviceCredential/ownSignaturePrivateKey off selfGroupStore's
    // state) for every Conversation Group KeyPackage this device generates --
    // the same real, DID-bound identity every member's MLS leaf already
    // carries, distinct from the group-local Ed25519 keypair
    // (randomGroupLocalKeypair) that's the ONLY thing the DS itself ever
    // sees (conversation-group.ts's own header explains the split).
    const conversationGroupStore = new IndexedDbMlsConversationGroupStore()
    const conversationGroupWatches = new Map<string, ConversationGroupWatch>()
    // Keyed by groupId. Deliberately in-memory only (the gap between
    // receiving CONVERSATION_GROUP_INVITE and CONVERSATION_GROUP_WELCOME_READY
    // has no ClientState yet, so there's nothing conversation-group-store.ts's
    // schema could hold for it) -- both sides of the handshake are automated
    // (auto-accept, no confirmation UI) and normally close in one round trip;
    // a tab closed mid-handshake just loses the invite, and the inviter has
    // to resend it. Accepted MVP limitation, not a silent gap.
    const pendingConversationGroupJoins = new Map<string, { ownKeyPackage: OwnKeyPackage; ownGroupLocalPrivateKey: Uint8Array; dsBaseUrl: string; dsProviderDid: string; groupName?: string }>()
    // Keyed by groupId, populated only while createAndSendConversationGroup
    // is waiting for its just-invited members to actually join before
    // sending the compose box's own first message (below) -- MLS forward
    // secrecy means a member who joins AFTER a message was sent can never
    // decrypt it (the same property that makes a removed member unable to
    // read anything after their removal), so a "create group, invite, and
    // immediately send" that doesn't wait guarantees the founding message
    // is unreadable by every invitee (found live, 2026-09-01: the very
    // first message a user typed while creating a group never arrived
    // anywhere). `handleConversationGroupJoinReady` (this device acting as
    // inviter) resolves an entry here once every invited member it's
    // waiting on has been added.
    const pendingGroupFounding = new Map<string, { remaining: Set<string>; resolve(): void }>()
    // A live SSE entry (startConversationGroupWatch's onEntry) and a local
    // send/join-handshake step both read-modify-write the SAME stored
    // ClientState+cursor for one group -- conversation-group-sync.ts's own
    // header note ("no internal mutex, the caller serializes") applies here,
    // now that this is the first caller actually running a watch and a send
    // concurrently for the same group. One promise chain per groupId.
    const conversationGroupQueues = new Map<string, Promise<unknown>>()
    function enqueueConversationGroupWork<T>(groupId: string, work: () => Promise<T>): Promise<T> {
      const prior = conversationGroupQueues.get(groupId) ?? Promise.resolve()
      const result = prior.then(work, work)
      conversationGroupQueues.set(groupId, result.catch(() => {}))
      return result
    }

    const startConversationGroupWatch = (groupId: string, stored: Pick<LoadedConversationGroup, 'ownGroupLocalPrivateKey' | 'lastSeenSeq' | 'dsBaseUrl'>): void => {
      if (conversationGroupWatches.has(groupId)) return
      const transport = new ConversationMlsDeliveryTransport({ baseUrl: stored.dsBaseUrl })
      const requesterId = hex(ed25519.getPublicKey(stored.ownGroupLocalPrivateKey))
      const sign = (bytes: Uint8Array) => ed25519.sign(bytes, stored.ownGroupLocalPrivateKey)
      const watch = watchConversationGroupDeliveries({
        transport, groupId, requesterId, sign, afterSeq: stored.lastSeenSeq,
        onEntry: entry => { void enqueueConversationGroupWork(groupId, () => handleConversationGroupEntry(groupId, entry)) },
        onError: error => console.warn(`[conversation-group/watch] ${groupId}:`, error instanceof Error ? error.message : error),
      })
      conversationGroupWatches.set(groupId, watch)
    }

    const handleConversationGroupEntry = async (groupId: string, entry: ConversationLogEntry): Promise<void> => {
      const stored = await conversationGroupStore.load(groupId)
      if (!stored) return // no longer joined locally
      const result = await applyConversationGroupLogEntry(entry, stored.state, groupId, {
        identityId: identity.did,
        actorDeviceId: deviceKid,
        nextActorSeq: () => sequencer.nextActorSeq(),
        initialParents: () => sequencer.initialParents(),
        activeSegment: () => boundary.activeSegment(),
        currentSnapshot: () => readModel.snapshot(),
        signer: boundary.signer,
        async commitVaultRecord(record) { await vaultStore.commitLocalMutation({ identityId: identity.did, ...record }) },
      })
      await conversationGroupStore.save(groupId, result.state, entry.seq, stored.ownGroupLocalPrivateKey, stored.roster, stored.dsBaseUrl, stored.dsProviderDid)
      if (result.committed) {
        await flushReplicationOutbox()
        await refreshInbox(readModel)
      }
    }

    // Network-first, unlike sendDidCommChat's local-first/outbox pattern --
    // the DS's epoch ordering is authoritative for whether this send is even
    // valid (stale epoch, removed from group), so a rejected submission must
    // never leave a local copy behind. Only on success does this build the
    // sender's own Vault copy, via the SAME buildConversationGroupVaultRecord
    // helper handleConversationGroupEntry's receive path uses (mimi
    // encoding stays owned by sendConversationTextMessage either way --
    // this function never touches MimiContent bytes itself).
    const sendConversationGroupMessage = (groupId: string, text: string, inReplyTo?: string): Promise<void> =>
      enqueueConversationGroupWork(groupId, async () => {
        const stored = await conversationGroupStore.load(groupId)
        if (!stored) throw new Error(`No local state for Conversation Group ${groupId}`)
        const transport = new ConversationMlsDeliveryTransport({ baseUrl: stored.dsBaseUrl })
        const senderId = hex(ed25519.getPublicKey(stored.ownGroupLocalPrivateKey))
        const sign = (bytes: Uint8Array) => ed25519.sign(bytes, stored.ownGroupLocalPrivateKey)
        const sent = await sendConversationTextMessage({
          state: stored.state, transport, groupId, deviceKid, senderId, text,
          ...(inReplyTo ? { inReplyTo: base64urlToBytes(inReplyTo) } : {}),
          sign,
        })
        const now = new Date().toISOString()
        const record = await buildConversationGroupVaultRecord({
          content: sent.content, messageId: sent.messageId, groupId, senderDid: didOfKid(deviceKid),
          otherMembers: sent.otherMembers, receivedAt: now,
        }, {
          identityId: identity.did,
          actorDeviceId: deviceKid,
          nextActorSeq: () => sequencer.nextActorSeq(),
          initialParents: () => sequencer.initialParents(),
          activeSegment: () => boundary.activeSegment(),
          currentSnapshot: () => readModel.snapshot(),
          signer: boundary.signer,
        }, () => new Date())
        await vaultStore.commitLocalMutation({ identityId: identity.did, ...record })
        await conversationGroupStore.save(groupId, sent.state, stored.lastSeenSeq, stored.ownGroupLocalPrivateKey, stored.roster, stored.dsBaseUrl, stored.dsProviderDid)
        await flushReplicationOutbox()
        await refreshInbox(readModel)
      })

    // Compose's "2+ DID recipients" branch (sendReply's dispatch, below):
    // creates the group (self-signed, the DS never learns this device's real
    // DID -- createConversationGroup's own header), invites each recipient
    // over the SAME 1:1 front-door DIDComm channel RELATIONSHIP_INIT already
    // uses (conversation-group-invite.ts: "no new crypto"), and sends the
    // compose box's own text as the group's first message.
    const createAndSendConversationGroup = async (toDids: string[], input: ReplySendInput): Promise<void> => {
      if (!conversationMlsDsBaseUrl) throw new Error('Conversation Groups are not configured on this deployment')
      if (!identity.didCommKid || !identity.didCommX25519PrivateKey) throw new Error('Enable DIDComm before starting a group')
      const selfGroup = await selfGroupStore.load(identity.did)
      if (!selfGroup) throw new Error('No self-group state for this identity')
      const kp = await generateOwnKeyPackage(ownMlsDeviceCredential(selfGroup.state), ownSignaturePrivateKey(selfGroup.state))
      const groupId = randomConversationGroupId()
      const transport = new ConversationMlsDeliveryTransport({ baseUrl: conversationMlsDsBaseUrl })
      const created = await createConversationGroup(transport, groupId, kp)
      let groupState = created.state
      const groupLocalSign = (bytes: Uint8Array) => ed25519.sign(bytes, created.ownGroupLocal.privateKey)
      // Set the room name BEFORE inviting anyone, if compose gave one --
      // every invitee's own Welcome embeds the GroupContext as of the
      // commit that added them, so committing the name first means every
      // future joiner inherits it for free (mls/group.ts's own
      // setRoomMetadata header explains the mechanism and why it's not yet
      // MIMI's own AppSync wire format). No separate propagation channel
      // needed -- this REPLACES the old approach of stuffing groupName into
      // the invite DIDComm payload as this device's single source of truth,
      // though that field is still sent too (conversationGroupStore.save's
      // own trailing arg below), as a display hint for the brief window
      // before an invitee has actually joined and has MLS state to read a
      // name from at all.
      if (input.subject) groupState = await setConversationGroupRoomName(groupState, transport, groupId, created.ownGroupLocal.id, input.subject, groupLocalSign)
      await conversationGroupStore.save(groupId, groupState, 0, created.ownGroupLocal.privateKey, [], conversationMlsDsBaseUrl, identity.did, input.subject || undefined)
      startConversationGroupWatch(groupId, { ownGroupLocalPrivateKey: created.ownGroupLocal.privateKey, lastSeenSeq: 0, dsBaseUrl: conversationMlsDsBaseUrl })
      const sendOpts = { fromKid: identity.didCommKid, x25519PrivateKey: fromHex(identity.didCommX25519PrivateKey) }
      const failedInvites: string[] = []
      const invited: string[] = []
      for (const toDid of toDids) {
        const result = await sendConversationGroupInvite(toDid, { groupId, ds: identity.did, ...(input.subject ? { groupName: input.subject } : {}) }, sendOpts)
        if (result.ok) invited.push(toDid)
        else failedInvites.push(toDid)
      }
      if (failedInvites.length) showSysMsg(`Could not invite: ${failedInvites.join(', ')}`)

      // Wait for every successfully-invited DID's join-ready round trip to
      // land (handleConversationGroupJoinReady resolves this as each one
      // completes) before sending -- up to a timeout, matching
      // ensureDidCommContact's own 60s relationship-handshake budget above,
      // since this is the identical shape of wait (an async peer-to-peer
      // round trip this device does not control the other side's timing
      // of). Sends to whoever DID make it in time rather than not at all --
      // a slow/offline invitee misses the founding message (same
      // unavoidable forward-secrecy consequence as before, just now scoped
      // to just them instead of everyone) but the group is not left silent
      // forever waiting on someone who may never respond.
      if (invited.length > 0) {
        showSysMsg('Waiting for invited members to join before sending…')
        const remaining = new Set(invited)
        const allJoined = new Promise<boolean>(resolve => { pendingGroupFounding.set(groupId, { remaining, resolve: () => resolve(true) }) })
        const timedOut = new Promise<boolean>(resolve => setTimeout(() => resolve(false), 60_000))
        const ok = await Promise.race([allJoined, timedOut])
        pendingGroupFounding.delete(groupId)
        if (!ok && remaining.size > 0) showSysMsg(`Still waiting to hear back from: ${[...remaining].join(', ')} -- sending to whoever's in so far`)
      }
      await sendConversationGroupMessage(groupId, input.body)
    }

    // Resumes every group this device already belongs to -- mirrors
    // startRelationshipPoll's own boot-time restore loop just below for the
    // same reason (a page reload must not silently stop listening to a group
    // this device already joined). Best-effort per group: one group's
    // transport failure must not stop the rest from being resumed.
    for (const groupId of await conversationGroupStore.listGroupIds().catch(() => [])) {
      await conversationGroupStore.load(groupId).then(stored => {
        if (stored) startConversationGroupWatch(groupId, stored)
      }).catch(e => console.warn(`[conversation-group/resume] ${groupId}:`, e instanceof Error ? e.message : e))
    }

    interface PendingHandshake {
      pending: PendingRelationship
      promise: Promise<ContactKeyV1>
      resolve(value: ContactKeyV1): void
    }
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
      identity = await enableDidComm(recordStore, identity, didCommReader, didCommSink, { coreBaseUrl, apexDomain, mediatorUrls }).catch(e => {
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

    // Publishes this identity's Conversation Group DS endpoint into its own
    // routing.json (identity/bootstrap.ts's ensureMimiProviderPublished) so a
    // peer this identity later invites into a group it creates can resolve
    // `ds: identity.did` back to an actual URL. Automatic and best-effort,
    // same treatment as enableOpenPgpMail above -- only attempted at all once
    // a Conversation Group DS is actually configured for this deployment;
    // unconfigured (the common case today) skips this entirely, same as
    // createAndSendConversationGroup's own guard.
    if (conversationMlsDsBaseUrl) {
      await ensureMimiProviderPublished(identity, conversationMlsDsBaseUrl)
        .catch(e => console.warn('[ensureMimiProviderPublished]', e instanceof Error ? e.message : e))
    }

    // TODO(mail-plugin bridge redesign): outbound submission via the
    // DIDComm-mediator-plus-mail-plugin will replace CoreMailSubmissionTransport
    // here once the plugin's `submit` message type exists (front-door kid
    // sends directly, no relationship credential/VC layer -- see the
    // redesign discussion). Falls back to buildMailSubmitter's own default
    // for now.
    const submitter = buildMailSubmitter(vaultStore, selfGroupStore, identity, mutationSink, apexDomain, coreBaseUrl)
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

    // A `to` of exactly one DID (not an email address) dispatches over
    // DIDComm instead of mail -- the same "to" field both transports share
    // (thread.ts/compose-page.ts have no separate DID input), branching
    // here rather than in the UI layer. Multiple DIDs at once isn't
    // supported: 1:1 chat only (confirmed with the user, 2026-08-25), and
    // mixing a DID with a real email address in one send has no sane
    // meaning either.
    const ensureDidCommContact = async (toDid: string): Promise<ContactKeyV1> => {
      if (!identity.didCommKid || !identity.didCommX25519PrivateKey) {
        throw new Error('Enable DIDComm in account settings before messaging a DID')
      }
      let contactKey = await contactKeyReader.currentFor(toDid)
      if (!contactKey) {
        let handshake = pendingByCounterparty.get(toDid)
        if (!handshake) {
          const initiated = await initiateRelationship(toDid, {
            fromKid: identity.didCommKid,
            x25519PrivateKey: fromHex(identity.didCommX25519PrivateKey),
          })
          if (!initiated.ok) throw new Error(initiated.error)
          let resolve!: (value: ContactKeyV1) => void
          const promise = new Promise<ContactKeyV1>((resolvePromise) => {
            resolve = resolvePromise
          })
          handshake = { pending: initiated.pending, promise, resolve }
          pendingByOwnKid.set(initiated.pending.peer.xKid, handshake)
          pendingByCounterparty.set(toDid, handshake)
          startRelationshipPoll(initiated.pending.peer.xKid, initiated.pending.peer.xPriv, initiated.pending.peer.did, initiated.pending.mediatorUrl)
        }
        contactKey = await Promise.race([
          handshake.promise,
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`relationship handshake with ${toDid} timed out`)), 60_000)),
        ])
      }
      return contactKey
    }

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
          // A prior attempt delivered and committed the sent transition but
          // crashed before deleting the transport row. Do not send it again.
          if (email.mailboxIds.sent === true && email.mailboxIds.outbox !== true) {
            await vaultStore.removeDidCommOutbox(identity.did, item.outboundEventId)
            continue
          }
          if (!email.blobId) {
            console.warn(`[didcomm/outbox] ${item.emailId}: local message has no body object`)
            continue
          }
          await vaultStore.noteDidCommOutboxAttempt(identity.did, item.outboundEventId, new Date().toISOString())
          try {
            const contactKey = await ensureDidCommContact(item.toDid)
            const content = new TextDecoder().decode(await readModel.download(email.blobId))
            const result = await sendRelationshipMessage(contactKey, content, email.subject, undefined, {
              id: item.messageId,
              sentAt: email.sentAt ?? item.createdAt,
            })
            if (!result.ok) throw new Error(result.error)
            const latest = await readModel.snapshot()
            await mutationSink.commitIntents([{
              kind: 'transport.result',
              targetIds: [item.emailId],
              payload: { emailId: item.emailId, status: 'accepted', occurredAt: new Date().toISOString(), transport: 'didcomm' },
            }, {
              kind: 'mailbox.set',
              targetIds: [item.emailId],
              payload: { emailId: item.emailId, mailboxIds: { sent: true } },
            }], latest)
            await vaultStore.removeDidCommOutbox(identity.did, item.outboundEventId)
            await flushReplicationOutbox()
          } catch (error) {
            console.warn(`[didcomm/outbox] ${item.emailId}:`, error instanceof Error ? error.message : error)
            break
          }
        }
      } finally {
        flushingDidComm = false
      }
    }

    const sendDidCommChat = async (toDid: string, input: ReplySendInput): Promise<void> => {
      if (!identity.didCommKid || !identity.didCommX25519PrivateKey) {
        throw new Error('Enable DIDComm in account settings before messaging a DID')
      }
      const now = new Date().toISOString()
      const emailId = crypto.randomUUID()
      const messageId = crypto.randomUUID()
      const snapshot = await readModel.snapshot()
      await mutationSink.commitMailMessage({
        email: {
          id: emailId,
          threadId: didCommThreadId(identity.did, toDid),
          mailboxIds: { outbox: true },
          keywords: { '$seen': true },
          receivedAt: now,
          sentAt: now,
          from: [{ email: identity.did }],
          to: [{ email: toDid }],
          ...(input.subject ? { subject: input.subject } : {}),
        },
        rawRfc5322: new TextEncoder().encode(input.body),
        didComm: { messageId, toDid },
      }, snapshot)
      await refreshInbox(readModel)
      await flushDidCommTransportOutbox?.()
      await refreshInbox(readModel)
    }

    const sendReply = async (input: ReplySendInput): Promise<void> => {
      if (input.toAddrs.length === 1 && input.toAddrs[0]!.startsWith('mls:')) {
        await sendConversationGroupMessage(parseMlsGroupAddress(input.toAddrs[0]!), input.body, input.inReplyTo)
        return
      }
      if (input.toAddrs.length === 1 && input.toAddrs[0]!.startsWith('did:')) {
        await sendDidCommChat(input.toAddrs[0]!, input)
        return
      }
      // 2+ DID recipients (never mixed with mail -- same rule the 1-DID
      // branch above already applies) starts a new Conversation Group,
      // mirroring src.bak's own "visible.length >= 2" compose branch.
      if (input.toAddrs.length >= 2 && input.toAddrs.every(addr => addr.startsWith('did:'))) {
        await createAndSendConversationGroup(input.toAddrs, input)
        return
      }
      const { rawRfc5322 } = buildOutboundRfc5322({
        from: mailFrom,
        to: input.toAddrs,
        subject: input.subject,
        body: input.body,
        inReplyTo: input.inReplyTo,
        references: input.references,
      })
      const emailId = crypto.randomUUID()
      const now = new Date().toISOString()
      const snapshot = await readModel.snapshot()
      await mutationSink.commitMailMessage({
        email: {
          id: emailId,
          threadId: crypto.randomUUID(),
          mailboxIds: { outbox: true },
          keywords: {},
          receivedAt: now,
          sentAt: now,
          from: [{ email: mailFrom }],
          to: input.toAddrs.map(email => ({ email })),
          subject: input.subject,
        },
        rawRfc5322,
      }, snapshot)
      await transport.call([{ name: 'EmailSubmission/set', callId: 's1', arguments: { create: { s1: { emailId } } } }])
      await refreshInbox(readModel)
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
      // Membership always reads live from THIS device's own locally-held
      // ClientState -- works regardless of conversationMlsDsBaseUrl (a
      // device that only ever receives invites, never creates a group
      // itself, still needs its member-chip strip to render). Inviting a
      // new member needs identity.didCommKid the same way createAndSendConversationGroup
      // does; that guard lives inside the hook itself so the strip renders
      // even before DIDComm is enabled, and only the "+" click fails.
      group: {
        membersOf: async groupId => {
          const stored = await conversationGroupStore.load(groupId)
          return stored ? memberList(stored.state).map(m => m.did) : []
        },
        invite: async (groupId, toDid) => {
          const stored = await conversationGroupStore.load(groupId)
          if (!stored) return { ok: false, error: 'Unknown group' }
          if (!identity.didCommKid || !identity.didCommX25519PrivateKey) return { ok: false, error: 'Enable DIDComm in account settings first' }
          const result = await sendConversationGroupInvite(
            toDid, { groupId, ds: stored.dsProviderDid },
            { fromKid: identity.didCommKid, x25519PrivateKey: fromHex(identity.didCommX25519PrivateKey) },
          )
          return result.ok ? { ok: true } : { ok: false, error: result.error }
        },
        // The MLS-committed name (group.ts's roomMetadataOf) is authoritative
        // -- it's what every member, including a future joiner, actually
        // converges on. The locally-cached invite-time hint
        // (conversationGroupStore's own `groupName`) is only a fallback for
        // the narrow window before this device has ever seen the group's
        // committed metadata at all (e.g. a group created by an old build,
        // before this mechanism existed).
        groupName: async groupId => {
          const stored = await conversationGroupStore.load(groupId)
          if (!stored) return undefined
          return roomMetadataOf(stored.state)?.name ?? stored.groupName
        },
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
    // same synchronizeMailIngress/ingestIngress orchestration either way
    // (that "Mail" in the name predates DIDComm and is otherwise
    // protocol-agnostic already, see ingress-ingest.ts's own header).
    // Shared by the legacy core-pull path (syncMailIngress, right below) and
    // the mediator-poll path (further down): both need "this identity's
    // DIDComm ingress projector, if it has one", and building two divergent
    // copies is exactly the kind of thing that quietly drifts apart.
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

    // Shared with the mediator-poll path's mail-bridge branch (onMessage,
    // further down): a mediator+mail-plugin instance's inbound-mail Forward
    // needs the exact same projector the legacy core-pull path already
    // builds here, not a second divergent copy of the same constructor call.
    const buildMailProjector = (): MailIngressProjector => new MailIngressProjector({
      identityId: identity.did,
      actorDeviceId: identity.deviceKid!,
      nextActorSeq: () => sequencer.nextActorSeq(),
      initialParents: () => sequencer.initialParents(),
      activeSegment: () => boundary.activeSegment(),
      currentSnapshot: () => readModel.snapshot(),
      signer: boundary.signer,
    })

    syncMailIngress = async () => {
      const mailProjector = buildMailProjector()
      const didCommProjector = buildDidCommProjector()
      const projector: IngressVerifierProjector = {
        verifyAndProject: envelope => {
          if (envelope.protocol === 'didcomm' && didCommProjector) return didCommProjector.verifyAndProject(envelope)
          return mailProjector.verifyAndProject(envelope)
        },
      }
      const result = await synchronizeMailIngress({
        identityId: identity.did,
        deviceId: identity.deviceKid!,
        store: vaultStore,
        ingressTransport: new CoreIngressTransport({ baseUrl: coreBaseUrl }),
        deliveryTransport: new CoreVaultDeliveryTransport({ baseUrl: coreBaseUrl }),
        flushDelivery: flushReplicationOutbox,
        signer: boundary.signer,
        projector,
        committer: vaultStore,
      })
      if (result.ingress.ingestedIngressIds.length > 0) await refreshInbox(readModel)
    }

    // Independent, blind mediators (ARC.md's 2026-08-27 redesign): this
    // device registers directly with each one configured (self-heal on
    // every boot -- registerWithMediator's own note) and polls it on its
    // own cadence, entirely separate from the core-pull loop above. A
    // delivered message is bridged into the SAME DidCommIngressProjector
    // (built fresh per call, same as syncMailIngress -- didCommKid/
    // didCommX25519PrivateKey can't change mid-session today, but nothing
    // here assumes that) via the transport-neutral vault commit path, so it
    // lands in the vault exactly like a core-delivered one without creating
    // a core-specific ingress ACK; the resulting vault-delivery pack still
    // syncs to sibling devices through biset-core (Phase 1's own point:
    // ONLY DIDComm delivery moved off it, not this identity's own
    // multi-device sync).
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
          return
        }
        // Conversation Group invite handshake (conversation-group-invite.ts) --
        // none of these three carry Basic Message/relationship content, so
        // they must never reach the generic didCommProjector.verifyAndProject
        // below: it throws "unsupported DIDComm message type" for anything
        // outside its own allow-list (ping/basicmessage/relationship).
        if (plaintext.type === CONVERSATION_GROUP_INVITE || plaintext.type === CONVERSATION_GROUP_JOIN_READY || plaintext.type === CONVERSATION_GROUP_WELCOME_READY) {
          await handleConversationGroupHandshake(plaintext, msg.senderKid)
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
      }

      // Conversation Group invite handshake (conversation-group-invite.ts's
      // own 3-step flow) -- auto-accept, no confirmation UI (confirmed with
      // the user: matches src.bak's synchronous-invite behavior even though
      // this backend's accept is async under the hood). Each step is
      // serialized through enqueueConversationGroupWork under the SAME
      // groupId a concurrent live-watch entry for that group would use, so
      // the two can never race each other's read-modify-write of the
      // group's stored state.
      async function handleConversationGroupHandshake(plaintext: DidCommPlaintext, senderKid: string): Promise<void> {
        const fromDid = didOfKid(senderKid)
        if (plaintext.type === CONVERSATION_GROUP_INVITE) {
          const body = conversationGroupInviteBodyOf(plaintext)
          if (!body) throw new TypeError('conversation group invite body is invalid')
          await enqueueConversationGroupWork(body.groupId, () => handleConversationGroupInvite(body, fromDid))
          return
        }
        if (plaintext.type === CONVERSATION_GROUP_JOIN_READY) {
          const body = conversationGroupJoinReadyBodyOf(plaintext)
          if (!body) throw new TypeError('conversation group join-ready body is invalid')
          await enqueueConversationGroupWork(body.groupId, () => handleConversationGroupJoinReady(body, fromDid))
          return
        }
        const body = conversationGroupWelcomeReadyBodyOf(plaintext)
        if (!body) throw new TypeError('conversation group welcome-ready body is invalid')
        await enqueueConversationGroupWork(body.groupId, () => handleConversationGroupWelcomeReady(body))
      }

      // Step 1 (invitee side): generate a fresh, single-group, throwaway
      // group-local keypair + this device's ordinary MLS KeyPackage (the
      // SAME real device credential every self-group leaf already carries),
      // publish the KeyPackage under that group-local id, tell the inviter
      // it's ready. `body.ds` is the INVITER's own DID -- resolved fresh via
      // resolveMimiProviderUrl rather than trusted as a URL directly, so a
      // later DS migration on the inviter's side needs no re-invite.
      async function handleConversationGroupInvite(body: { groupId: string; ds: string; groupName?: string }, inviterDid: string): Promise<void> {
        if (!identity.didCommKid || !identity.didCommX25519PrivateKey) return
        // A mediator redelivers anything it hasn't seen acked yet, so this
        // exact invite can arrive more than once (found live, 2026-09-01).
        // Minting a FRESH KeyPackage/group-local keypair on every delivery
        // would silently invalidate a Welcome the inviter may have already
        // built against the first one -- joinMlsGroup then throws "No
        // matching secret found", forever (nothing here ever clears the
        // stale pending entry, so a redelivery keeps re-triggering the same
        // mismatch). Idempotent instead: already joined, or already waiting
        // on a Welcome, is a no-op / a re-announce, never a fresh mint.
        if (await conversationGroupStore.load(body.groupId)) return
        const existingPending = pendingConversationGroupJoins.get(body.groupId)
        if (existingPending) {
          const groupLocalId = hex(ed25519.getPublicKey(existingPending.ownGroupLocalPrivateKey))
          const joinReady = await sendConversationGroupJoinReady(
            inviterDid, { groupId: body.groupId, groupLocalId },
            { fromKid: identity.didCommKid, x25519PrivateKey: fromHex(identity.didCommX25519PrivateKey) },
          )
          if (!joinReady.ok) console.warn(`[conversation-group/invite] (redelivered) could not tell ${inviterDid} we're ready:`, joinReady.error)
          return
        }
        const dsBaseUrl = await resolveMimiProviderUrl(body.ds).catch(() => undefined)
        if (!dsBaseUrl) { console.warn(`[conversation-group/invite] ${inviterDid} has no MimiDeliveryService published`); return }
        const selfGroup = await selfGroupStore.load(identity.did)
        if (!selfGroup) { console.warn('[conversation-group/invite] no self-group state yet'); return }
        const kp = await generateOwnKeyPackage(ownMlsDeviceCredential(selfGroup.state), ownSignaturePrivateKey(selfGroup.state))
        const groupLocal = randomGroupLocalKeypair()
        const publish: Omit<ConversationKeyPackagePublishV1, 'signature'> = {
          version: 1, id: groupLocal.id, packages: [encodeKeyPackage(kp.publicPackage)], publishedAt: new Date().toISOString(),
        }
        const transport = new ConversationMlsDeliveryTransport({ baseUrl: dsBaseUrl })
        await transport.publishKeyPackages({ ...publish, signature: ed25519.sign(conversationKeyPackagePublishSigningBytes(publish), groupLocal.privateKey) })
        pendingConversationGroupJoins.set(body.groupId, { ownKeyPackage: kp, ownGroupLocalPrivateKey: groupLocal.privateKey, dsBaseUrl, dsProviderDid: body.ds, groupName: body.groupName })
        const joinReady = await sendConversationGroupJoinReady(
          inviterDid, { groupId: body.groupId, groupLocalId: groupLocal.id },
          { fromKid: identity.didCommKid, x25519PrivateKey: fromHex(identity.didCommX25519PrivateKey) },
        )
        if (!joinReady.ok) console.warn(`[conversation-group/invite] could not tell ${inviterDid} we're ready:`, joinReady.error)
      }

      // Step 2 (inviter side): take the invitee's freshly-published
      // KeyPackage, commit an Add for it, tell the invitee to pull.
      async function handleConversationGroupJoinReady(body: { groupId: string; groupLocalId: string }, inviteeDid: string): Promise<void> {
        if (!identity.didCommKid || !identity.didCommX25519PrivateKey) return
        const stored = await conversationGroupStore.load(body.groupId)
        if (!stored) { console.warn(`[conversation-group/join-ready] no local state for ${body.groupId}`); return }
        const transport = new ConversationMlsDeliveryTransport({ baseUrl: stored.dsBaseUrl })
        const ownGroupLocalId = hex(ed25519.getPublicKey(stored.ownGroupLocalPrivateKey))
        const sign = (bytes: Uint8Array) => ed25519.sign(bytes, stored.ownGroupLocalPrivateKey)
        const take: Omit<ConversationKeyPackageTakeV1, 'signature'> = {
          version: 1, requesterId: ownGroupLocalId, targetId: body.groupLocalId, requestedAt: new Date().toISOString(),
        }
        const taken = await transport.takeKeyPackage({ ...take, signature: sign(conversationKeyPackageTakeSigningBytes(take)) })
        if (!taken) { console.warn(`[conversation-group/join-ready] ${inviteeDid}'s KeyPackage was not available`); return }
        const keyPackage = decodeKeyPackage(taken.keyPackage)
        // The KeyPackage `transport.takeKeyPackage` just returned is gone
        // from the DS's pool NOW, irreversibly, whether or not the commit
        // below actually succeeds -- so a failure here must be retried
        // in-place (fresh state, same already-taken KeyPackage) rather than
        // left to throw uncaught. An uncaught throw here previously
        // propagated all the way to the mediator poll loop, which leaves an
        // `onMessage` failure "queued for retry" -- redelivering this SAME
        // join-ready later, at which point the KeyPackage is ALREADY GONE,
        // so `takeKeyPackage` above returns undefined and the invitee is
        // permanently stuck (found live, 2026-09-01: "KeyPackage was not
        // available", the invitee never joins, and the only way out was
        // re-inviting them with a fresh KeyPackage from scratch).
        let currentState = stored.state
        let nextState: ClientState | undefined
        const attempts = 3
        for (let attempt = 1; attempt <= attempts; attempt++) {
          try {
            nextState = await addMembersToConversationGroup(currentState, transport, body.groupId, ownGroupLocalId, [{ keyPackage, groupLocalId: body.groupLocalId }], sign)
            break
          } catch (error) {
            console.warn(`[conversation-group/join-ready] commit attempt ${attempt}/${attempts} for ${inviteeDid} failed:`, error instanceof Error ? error.message : error)
            if (attempt === attempts) {
              console.warn(`[conversation-group/join-ready] giving up on ${inviteeDid} -- their KeyPackage is now spent; they need a fresh invite to try again`)
              return
            }
            // Someone else's commit landed first (an epoch-conflict is the
            // expected reason, but any rejection gets the same retry --
            // there is nothing better to do with the already-spent
            // KeyPackage than try again from wherever the group actually
            // is now): re-read the current state a live watch entry
            // (handleConversationGroupEntry) may have already advanced
            // concurrently, and retry the exact same Add from there.
            const refreshed = await conversationGroupStore.load(body.groupId)
            if (!refreshed) { console.warn(`[conversation-group/join-ready] group ${body.groupId} vanished mid-retry`); return }
            currentState = refreshed.state
          }
        }
        if (!nextState) return
        await conversationGroupStore.save(body.groupId, nextState, stored.lastSeenSeq, stored.ownGroupLocalPrivateKey, stored.roster, stored.dsBaseUrl, stored.dsProviderDid)
        const welcomeReady = await sendConversationGroupWelcomeReady(
          inviteeDid, { groupId: body.groupId },
          { fromKid: identity.didCommKid, x25519PrivateKey: fromHex(identity.didCommX25519PrivateKey) },
        )
        if (!welcomeReady.ok) console.warn(`[conversation-group/join-ready] could not tell ${inviteeDid} to pull:`, welcomeReady.error)
        // Tell createAndSendConversationGroup's own wait (above) that this
        // member is in, if it's still waiting on this group at all -- a
        // reply/invite issued outside that flow (an existing group's own
        // "+" add-member chip) never populated pendingGroupFounding, so
        // this is a no-op then, same as it is once every invitee this
        // founding wait cared about has already resolved it.
        const founding = pendingGroupFounding.get(body.groupId)
        if (founding) {
          founding.remaining.delete(inviteeDid)
          if (founding.remaining.size === 0) founding.resolve()
        }
        await flushReplicationOutbox()
        await refreshInbox(readModel)
      }

      // Step 3 (invitee side): pull the Welcome the inviter's commit just
      // produced, join, persist real local state (the pending in-memory
      // entry is retired here), start this group's live watch.
      async function handleConversationGroupWelcomeReady(body: { groupId: string }): Promise<void> {
        const pending = pendingConversationGroupJoins.get(body.groupId)
        if (!pending) { console.warn(`[conversation-group/welcome-ready] no pending join for ${body.groupId}`); return }
        const transport = new ConversationMlsDeliveryTransport({ baseUrl: pending.dsBaseUrl })
        const ownGroupLocalId = hex(ed25519.getPublicKey(pending.ownGroupLocalPrivateKey))
        const pull: Omit<ConversationDeliveriesPullV1, 'signature'> = {
          version: 1, groupId: body.groupId, requesterId: ownGroupLocalId, afterSeq: 0, requestedAt: new Date().toISOString(),
        }
        const entries = await transport.pullDeliveries({ ...pull, signature: ed25519.sign(conversationDeliveriesPullSigningBytes(pull), pending.ownGroupLocalPrivateKey) })
        // A group with 2+ pending invitees can have MULTIPLE 'welcome'
        // entries in this same pulled backlog (one per Add commit) -- the
        // first one in seq order is not necessarily ours. A Welcome names
        // the KeyPackageRef(s) it carries secrets for; match against ours
        // rather than grabbing the first 'welcome' unconditionally (found
        // live, 2026-09-01: the SECOND invitee added to a group always
        // grabbed the FIRST invitee's Welcome instead, and joinMlsGroup then
        // threw "No matching secret found" forever -- self-group's own
        // KeyPackage pool, mls/keypackage-store.ts's takeForWelcome, already
        // does this exact match; this path just hadn't been given the same
        // treatment).
        const ownKeyPackageRef = await keyPackageRefOf(pending.ownKeyPackage.publicPackage)
        const welcomeEntry = entries.find(entry => entry.kind === 'welcome' && welcomeRecipientRefs(entry.payload).includes(ownKeyPackageRef))
        if (!welcomeEntry) { console.warn(`[conversation-group/welcome-ready] no matching welcome entry for ${body.groupId}`); return }
        const state = await joinMlsGroup(welcomeEntry.payload, pending.ownKeyPackage, undefined)
        await conversationGroupStore.save(body.groupId, state, welcomeEntry.seq, pending.ownGroupLocalPrivateKey, [], pending.dsBaseUrl, pending.dsProviderDid, pending.groupName)
        pendingConversationGroupJoins.delete(body.groupId)
        startConversationGroupWatch(body.groupId, { ownGroupLocalPrivateKey: pending.ownGroupLocalPrivateKey, lastSeenSeq: welcomeEntry.seq, dsBaseUrl: pending.dsBaseUrl })
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
  await syncMailIngress?.().catch(e => {
    console.warn('[syncMailIngress]', e instanceof Error ? e.message : e)
  })
  // Nothing pulls again after this until the page is reloaded otherwise --
  // there is no push here (PLAN.md §6.1 explicitly leaves DIDComm push out
  // of scope), but a plain periodic pull is a different, much simpler thing
  // that was just never wired as a recurring loop, only this one boot-time
  // call. Found live, 2026-08-25: a message sent between two open sessions
  // only showed up "a long time later" -- actually whenever something else
  // happened to trigger a reboot, not because of any real delay. (Any prior
  // interval was already cleared at the top of this function.)
  if (syncMailIngress || flushDidCommTransportOutbox) {
    const sync = syncMailIngress
    const flushDidComm = flushDidCommTransportOutbox
    pollTimer = setInterval(() => {
      sync?.().catch(e => console.warn('[syncMailIngress/poll]', e instanceof Error ? e.message : e))
      flushDidComm?.().then(() => refreshInbox(readModel)).catch(e => console.warn('[didcomm/outbox/poll]', e instanceof Error ? e.message : e))
    }, 10_000)
  }

  if (coordinatorConfigured) {
    const boundary = buildVaultCryptoBoundary(vaultStore, vaultStore, selfGroupStore, identity)
    const projector = buildVaultDeliveryProjector(selfGroupStore, identity.did, () => readModel.snapshot(), identity.masterSeed)
    let synchronizeCoordinator: (() => Promise<void>) | undefined
    let activeCoordinatorBinding = initialCoordinatorBinding
    type CoordinatorCheckpointState = 'missing' | 'current' | 'restored'
    const restoreLatestCoordinatorCheckpoint = async (
      vaultId: import('./protocol/ids.ts').VaultId,
      route: string,
      transport: VaultCoordinatorTransport,
      options: { forceRewrap?: boolean } = {},
    ): Promise<CoordinatorCheckpointState> => {
      const checkpoint = await transport.pullCheckpoint({ version: 1, vaultId })
      const localCursor = await vaultStore.readDeliveryCursor(identity.did, identity.deviceKid!)
      if (!checkpoint) return 'missing'
      if (!options.forceRewrap && BigInt(checkpoint.coveredSeq) <= BigInt(localCursor)) return 'current'
      if (!identity.masterSeed) throw new Error('Coordinator checkpoint restore requires the identity master seed')
      if (!equalBytes(sha256Bytes(checkpoint.payload), checkpoint.payloadHash)) throw new Error('Coordinator checkpoint payload hash is invalid')
      const recoveryKek = deriveCoordinatorRecoveryKek(fromHex(identity.masterSeed), vaultId, route)
      let snapshot: Awaited<ReturnType<typeof openCoordinatorCheckpoint>> | undefined
      try {
        snapshot = await openCoordinatorCheckpoint(recoveryKek, checkpoint.payload, { vaultId, coveredSeq: checkpoint.coveredSeq, coordinatorUrl: route })
        if (snapshot.identityId !== identity.did) throw new Error('Coordinator checkpoint belongs to another identity')
        const records = await rewrapRecoveryArchiveForCurrentEpoch(snapshot, boundary.epochs, boundary.signer, new Date().toISOString())
        await vaultStore.commitRecoveryArchive({
          identityId: identity.did,
          events: records.events.map(event => ({ ...event, identityId: identity.did })),
          objects: records.objects.map(object => ({ ...object, identityId: identity.did })),
          keyWraps: records.keyWraps,
        })
        for (const segment of snapshot.segmentKeys) await vaultStore.sealAndActivateSegment({ identityId: identity.did, segmentId: segment.segmentId, segmentKey: segment.key, selfGroupId: VAULT_STORAGE_GROUP_ID, epoch: VAULT_STORAGE_EPOCH, sealed: false, createdAt: snapshot.createdAt })
        await migrateLocalSegmentKeysToStorageRoot(vaultStore, vaultStore, identity, selfGroupStore)
        const projection = await buildLocalJmapProjectionRebuild(vaultStore, vaultStore, vaultStore, selfGroupStore, identity.did, identity.masterSeed)()
        await vaultStore.advanceDeliveryCursor(identity.did, identity.deviceKid!, checkpoint.coveredSeq, projection.state, new Date().toISOString())
        await refreshInbox(readModel)
        return 'restored'
      } finally {
        recoveryKek.fill(0)
        if (snapshot) for (const segment of snapshot.segmentKeys) segment.key.fill(0)
      }
    }
    const needsCheckpointRewrap = async (): Promise<boolean> => {
      const current = await boundary.epochs.currentVaultEpoch(identity.did)
      const objects = await vaultStore.readVaultObjects(identity.did)
      for (const segmentId of new Set(objects.map(object => object.segmentId))) {
        if (!(await vaultStore.readSegmentKeyWrap(identity.did, segmentId, current.epoch))) return true
      }
      return false
    }
    const configureCoordinator = (binding: LocalVaultCoordinatorBindingV1, oidc: AnchorOidcPkceClient): void => {
      if (new URL(binding.coordinatorUrl).origin !== new URL(coordinatorUrl).origin) throw new Error('local binding does not match configured Coordinator origin')
      const transport = new VaultCoordinatorTransport({ baseUrl: binding.coordinatorUrl, accessTokens: oidc })
      const memberSigner = {
        memberId: binding.localMemberId,
        async sign(bytes: Uint8Array) { return ed25519.sign(bytes, binding.memberSignaturePrivateKey) },
      }
      activeCoordinatorBinding = binding
      coordinatorBindingActive = true
      flushCoordinatorOutbox = () => flushCoordinatorDeliveryOutbox(
        vaultStore, transport, memberSigner, identity.did,
        binding.groupView.vaultId, binding.groupView.groupEpoch,
      )
      synchronizeCoordinator = async () => {
        // Sequence equality proves delivery completeness, not decryptability.
        // Older local Vaults can have every object and cursor while lacking
        // a wrap for the current self-group epoch. In that case re-apply the
        // complete checkpoint solely to recover SegmentKeys and mint current
        // wraps; commitRecoveryArchive remains additive/idempotent.
        const checkpointState = await restoreLatestCoordinatorCheckpoint(
          binding.groupView.vaultId,
          binding.coordinatorUrl,
          transport,
          { forceRewrap: await needsCheckpointRewrap() },
        )
        const flushed = await flushCoordinatorOutbox!()
        if (flushed.failedEntryId) throw new Error(`Coordinator outbox append failed: ${flushed.failureReason ?? flushed.failedEntryId}`)
        const result = await synchronizeCoordinatorDelivery(
          vaultStore, transport,
          { ingest: item => ingestVaultDelivery(item, boundary.signer, projector, vaultStore) },
          memberSigner, identity.did, identity.deviceKid!, binding.groupView.vaultId,
        )
        if (result.kind === 'restoreRequired') showSysMsg('Coordinator history gap: restore is required')
        if (result.kind === 'synced') {
          if (result.ingestedSequences.length > 0) await refreshInbox(readModel)
          // Existing deployments may already have acknowledged delivery rows
          // whose bodies predate durable checkpoints. Seed the first complete
          // checkpoint even when this client had no new mutation to flush.
          if (!result.pendingAckSequence && (checkpointState === 'missing' || result.ingestedSequences.length > 0 || flushed.appendedEntryIds.length > 0)) {
            if (!identity.masterSeed) throw new Error('Coordinator recovery checkpoint requires the identity master seed')
            const coveredSeq = await vaultStore.readDeliveryCursor(identity.did, identity.deviceKid!)
            const createdAt = new Date().toISOString()
            const snapshot = await createRecoveryArchiveSnapshot(vaultStore, boundary.resolver, identity.did, createdAt)
            const recoveryKek = deriveCoordinatorRecoveryKek(fromHex(identity.masterSeed), binding.groupView.vaultId, binding.coordinatorUrl)
            try {
              const payload = await createCoordinatorCheckpoint(recoveryKek, snapshot, { vaultId: binding.groupView.vaultId, coveredSeq, coordinatorUrl: binding.coordinatorUrl })
              const unsigned = { version: 1 as const, vaultId: binding.groupView.vaultId, writerMemberId: binding.localMemberId, coveredSeq, payloadHash: sha256Bytes(payload), createdAt }
              await transport.putCheckpoint({ ...unsigned, payload, signature: ed25519.sign(vaultCoordinatorCheckpointSigningBytes(unsigned), binding.memberSignaturePrivateKey) })
            } finally {
              recoveryKek.fill(0)
              for (const segment of snapshot.segmentKeys) segment.key.fill(0)
            }
          }
        }
      }
    }
    if (initialCoordinatorBinding && coordinatorOidc) configureCoordinator(initialCoordinatorBinding, coordinatorOidc)
    connectCoordinator = async () => {
      const oidc = await ensureCoordinatorOidc()
      await oidc.authorize()
      let binding = await vaultStore.readCoordinatorBinding(identity.did)
      if (!binding) {
        const transport = new VaultCoordinatorTransport({ baseUrl: coordinatorUrl, accessTokens: oidc })
        const owned = await transport.ownedVaults()
        if (owned.length > 1) throw new Error('More than one Coordinator Vault belongs to this login')
        if (owned.length === 1) {
          if (!joinCoordinatorInvitation) throw new Error('Coordinator join is still initializing')
          await joinCoordinatorInvitation('')
          return
        }
        binding = await createAndProvisionVaultCoordinator(vaultStore, transport, identity.did, coordinatorUrl)
        configureCoordinator(binding, oidc)
        showSysMsg('Coordinator Vault created')
      } else configureCoordinator(binding, oidc)
      await synchronizeCoordinator?.()
    }
    const signedMemberRequest = async (binding: LocalVaultCoordinatorBindingV1, afterEpoch = binding.groupView.groupEpoch) => {
      const unsigned = { version: 1 as const, vaultId: binding.groupView.vaultId, memberId: binding.localMemberId, afterEpoch, requestedAt: new Date().toISOString() }
      return { ...unsigned, signature: ed25519.sign(vaultMlsMemberRequestSigningBytes(unsigned), binding.memberSignaturePrivateKey) }
    }
    createCoordinatorInvitation = async () => {
      const oidc = await ensureCoordinatorOidc()
      await oidc.authorize()
      const binding = activeCoordinatorBinding
      if (!binding) throw new Error('Connect this device to the Coordinator first')
      const transport = new VaultCoordinatorTransport({ baseUrl: binding.coordinatorUrl, accessTokens: oidc })
      return transport.createMlsInvitation(await signedMemberRequest(binding))
    }
    approveCoordinatorDevice = async () => {
      const oidc = await ensureCoordinatorOidc()
      await oidc.authorize()
      const binding = activeCoordinatorBinding
      if (!binding) throw new Error('This device has no Coordinator Vault')
      const transport = new VaultCoordinatorTransport({ baseUrl: binding.coordinatorUrl, accessTokens: oidc })
      const packages = await transport.pullMlsKeyPackages(await signedMemberRequest(binding))
      if (packages.length === 0) return
      const pullUnsigned = { version: 1 as const, vaultId: binding.groupView.vaultId, recipientMemberId: binding.localMemberId, after: '0', requestedAt: new Date().toISOString() }
      const head = await transport.pull({ ...pullUnsigned, signature: ed25519.sign(vaultCoordinatorPullSigningBytes(pullUnsigned), binding.memberSignaturePrivateKey) })
      const floor = deliverySeq(BigInt(head.latestSeq) + 1n)
      const pending = await prepareVaultMlsAdd({ encodedState: binding.vaultMlsState, groupView: binding.groupView, localMemberId: binding.localMemberId, memberSignaturePrivateKey: binding.memberSignaturePrivateKey }, packages[0]!.keyPackage, floor)
      const transitionUnsigned = { version: 1 as const, groupView: pending.groupView, commit: pending.commit, welcomes: [{ memberId: pending.memberId, payload: pending.welcome }], submittedAt: new Date().toISOString() }
      const transition = { ...transitionUnsigned, signature: ed25519.sign(vaultMlsTransitionSigningBytes(transitionUnsigned), binding.memberSignaturePrivateKey) }
      const updated = await advanceVaultCoordinatorGroup(vaultStore, transport, identity.did, {
        groupView: pending.groupView,
        transition,
        vaultMlsState: pending.encodedState,
        localMemberId: binding.localMemberId,
        memberSignaturePrivateKey: binding.memberSignaturePrivateKey,
        updatedAt: new Date().toISOString(),
      })
      pending.confirm()
      configureCoordinator(updated, oidc)
    }
    joinCoordinatorInvitation = async invitation => {
      if (activeCoordinatorBinding) throw new Error('This device already has a Coordinator Vault')
      const oidc = await ensureCoordinatorOidc()
      await oidc.authorize()
      const transport = new VaultCoordinatorTransport({ baseUrl: coordinatorUrl, accessTokens: oidc })
      let pending = await vaultStore.readCoordinatorPendingJoin(identity.did)
      if (pending && Date.parse(pending.expiresAt) <= Date.now()) {
        await vaultStore.clearCoordinatorPendingJoin(identity.did)
        pending = undefined
      }
      const resuming = pending !== undefined
      if (!pending) {
        const vaultId = invitation
          ? (await transport.redeemMlsInvitation({ version: 1, invitation, redeemedAt: new Date().toISOString() })).vaultId
          : await (async () => {
            const owned = await transport.ownedVaults()
            if (owned.length !== 1) throw new Error(owned.length === 0 ? 'No Coordinator Vault exists for this login' : 'More than one Coordinator Vault belongs to this login')
            return owned[0]!.vaultId
          })()
        const candidate = await createVaultMlsJoinCandidate()
        const now = new Date()
        pending = {
          version: 1, identityId: identity.did, coordinatorUrl: coordinatorUrl.replace(/\/$/, ''), vaultId, memberId: candidate.memberId,
          encodedKeyPackage: candidate.encodedKeyPackage,
          initPrivateKey: candidate.ownKeyPackage.privatePackage.initPrivateKey,
          hpkePrivateKey: candidate.ownKeyPackage.privatePackage.hpkePrivateKey,
          signaturePrivateKey: candidate.ownKeyPackage.privatePackage.signaturePrivateKey,
          createdAt: now.toISOString(), expiresAt: new Date(now.getTime() + 10 * 60 * 1000).toISOString(),
        }
        // Persist before publish: a crash after the server accepts the public
        // KeyPackage must not lose the only private half that can open Welcome.
        await vaultStore.writeCoordinatorPendingJoin(pending)
      }
      if (new URL(pending.coordinatorUrl).origin !== new URL(coordinatorUrl).origin) throw new Error('pending join does not match configured Coordinator origin')
      const vaultId = pending.vaultId
      const candidate = restoreVaultMlsJoinCandidate(pending)
      // Recovery is authorized by the root-phrase-derived key and OIDC owner,
      // not by current routing membership. Restore the complete opaque
      // checkpoint before waiting for another device to install the MLS Add.
      await restoreLatestCoordinatorCheckpoint(vaultId, coordinatorUrl, transport)
      const pullWelcome = async () => {
        const requestUnsigned = { version: 1 as const, vaultId, memberId: candidate.memberId, afterEpoch: '0', requestedAt: new Date().toISOString() }
        return transport.pullMlsWelcome({ ...requestUnsigned, signature: ed25519.sign(vaultMlsMemberRequestSigningBytes(requestUnsigned), candidate.memberSignaturePrivateKey) })
      }
      // A crash may have happened after the Add was accepted. In that case
      // the member is already active and re-publishing a KeyPackage is
      // correctly rejected; recover the existing Welcome first.
      let delivered = resuming ? await pullWelcome().catch(() => null) : null
      if (!delivered) {
        const packageUnsigned = { version: 1 as const, vaultId, memberId: candidate.memberId, signaturePublicKey: ed25519.getPublicKey(candidate.memberSignaturePrivateKey), keyPackage: candidate.encodedKeyPackage, publishedAt: pending.createdAt }
        await transport.publishMlsKeyPackage({ ...packageUnsigned, signature: ed25519.sign(vaultMlsKeyPackageSigningBytes(packageUnsigned), candidate.memberSignaturePrivateKey) })
      }
      // Access tokens are intentionally short-lived and getAccessToken never
      // opens a popup outside a user gesture. Keep this wait inside the fresh
      // login window; a timed-out attempt can use a newly issued invitation.
      const deadline = Date.now() + 30_000
      while (Date.now() < deadline) {
        try {
          delivered ??= await pullWelcome()
          if (delivered) {
            const joined = await joinVaultMlsFromWelcome(candidate, delivered.welcome, delivered.groupView)
            const now = new Date().toISOString()
            const binding: LocalVaultCoordinatorBindingV1 = { version: 1, identityId: identity.did, coordinatorUrl: coordinatorUrl.replace(/\/$/, ''), groupView: delivered.groupView, vaultMlsState: joined.encodedState, localMemberId: candidate.memberId, memberSignaturePrivateKey: joined.memberSignaturePrivateKey, createdAt: now, updatedAt: now }
            await vaultStore.commitCoordinatorJoin(binding)
            configureCoordinator(binding, oidc)
            await synchronizeCoordinator?.()
            return
          }
        } catch (error) {
          // Before the existing member installs the Add, this candidate is
          // not active yet and Welcome pull correctly returns 400. Retry.
          console.debug('[coordinator/join-wait]', error instanceof Error ? error.message : error)
        }
        await new Promise(resolve => setTimeout(resolve, 2_000))
      }
      throw new Error('Coordinator membership is pending automatic approval')
    }

    // Coordinator v2 cut-over. Self Group (maintained above through the core
    // RFC 9420 DS) is now the sole device-membership group. Coordinator only
    // stores one OIDC-owner-scoped ordered stream and its latest checkpoint.
    // The v1 lifecycle remains read-only migration code for this release;
    // none of its invite/approve/join entry points are exposed by the UI.
    let streamTransport: VaultCoordinatorTransport | undefined
    let streamVaultId: import('./protocol/ids.ts').VaultId | undefined
    const catchUpSelfGroupBeforeVaultRead = async (): Promise<void> => {
      // A newly restored sibling is authorized by an MLS external commit
      // before it can append anything to this identity's Coordinator stream.
      // Reflect that causally-earlier commit before verifying an event the
      // sibling signed. Boot-time maintenance alone is insufficient: an
      // already-open first device can observe the sibling's checkpoint on
      // the next ten-second Vault poll while its local Self Group is still
      // one epoch behind (found live with 8f41.biset.md, 2026-08-30).
      if (!coreBaseUrl) throw new Error('Self Group roster endpoint is not configured')
      const state = await maintainSelfGroup(selfGroupStore, keyStore, identity, {
        coreBaseUrl, mlsDeliveryBaseUrl: coordinatorUrl,
        wraps: vaultStore, segments: vaultStore,
      })
      if (!state) return
      const nextDevices = memberKids(state, identity.did).map(deviceId => ({ deviceId, current: deviceId === identity.deviceKid }))
      if (JSON.stringify(nextDevices) !== JSON.stringify(vaultDevices)) {
        vaultDevices = nextDevices
        if (vaultCardStatus) setVaultCard(vaultCardStatus)
      }
    }
    const eventCredentialHistory = async (): Promise<Map<string, Uint8Array>> => {
      const credentials = new Map<string, Uint8Array>()
      const stored = await selfGroupStore.load(identity.did)
      if (stored) {
        for (const deviceId of memberKids(stored.state, identity.did)) {
          const credential = memberDeviceCredentialBytes(stored.state, deviceId)
          if (credential) credentials.set(deviceId, credential)
        }
      }
      // One-time bridge for checkpoints written before Vault events carried
      // their own Root-authorized actor credential. The old public roster may
      // still retain a device that has since been removed from the current
      // Self Group, which is exactly the historical key needed to upgrade its
      // already-signed events. New checkpoints become self-contained and no
      // longer depend on this legacy projection.
      if (coreBaseUrl) {
        const projection = await new CoreRosterInstallTransport({ baseUrl: coreBaseUrl }).fetchProjection(identity.did).catch(() => undefined)
        for (const device of projection?.devices ?? []) if (!credentials.has(device.deviceId)) credentials.set(device.deviceId, device.deviceCredential)
      }
      return credentials
    }
    const synchronizeStreamOnce = async (): Promise<{ localSeq: string; latestSeq: string; checkpointSeq?: string } | undefined> => {
      if (!streamTransport || !streamVaultId) return undefined
      const transport = streamTransport
      const vaultId = streamVaultId
      const checkpoint = await transport.pullStreamCheckpoint(vaultId)
      // Pull the checkpoint first, then catch up MLS. Any device whose event
      // can be present in that immutable response necessarily committed its
      // Self Group membership before publishing it, so this ordering closes
      // the join/checkpoint race instead of merely making it less likely.
      await catchUpSelfGroupBeforeVaultRead()
      let checkpointSeq = checkpoint?.coveredSeq
      let checkpointNeedsEventCredentialUpgrade = false
      const checkpointNeedsUpgrade = checkpoint ? (() => { try { return (JSON.parse(new TextDecoder().decode(checkpoint.payload)) as { version?: unknown }).version === 1 } catch { return false } })() : false
      const localCursor = await vaultStore.readDeliveryCursor(identity.did, identity.deviceKid!)
      if (checkpoint && BigInt(checkpoint.coveredSeq) > BigInt(localCursor)) {
        if (!identity.masterSeed) throw new Error('Coordinator checkpoint restore requires the identity master seed')
        if (!equalBytes(sha256Bytes(checkpoint.payload), checkpoint.payloadHash)) throw new Error('Coordinator checkpoint payload hash is invalid')
        let snapshot: Awaited<ReturnType<typeof openCoordinatorCheckpoint>> | undefined
        try {
          snapshot = await openPortableCoordinatorCheckpoint(fromHex(identity.masterSeed), checkpoint.payload, { vaultId, coveredSeq: checkpoint.coveredSeq, coordinatorUrl })
          if (snapshot.identityId !== identity.did) throw new Error('Coordinator checkpoint belongs to another identity')
          if (snapshot.events.some(event => !event.actorCredential)) {
            const credentials = await eventCredentialHistory()
            snapshot.events = snapshot.events.map(event => {
              if (event.actorCredential) return event
              const actorCredential = credentials.get(event.actorDeviceId)
              return actorCredential ? { ...event, actorCredential: actorCredential.slice() } : event
            })
            checkpointNeedsEventCredentialUpgrade = snapshot.events.every(event => !!event.actorCredential)
          }
          const records = await rewrapRecoveryArchiveForCurrentEpoch(snapshot, boundary.epochs, boundary.signer, new Date().toISOString())
          await vaultStore.commitRecoveryArchive({ identityId: identity.did, events: records.events, objects: records.objects.map(object => ({ ...object, identityId: identity.did })), keyWraps: records.keyWraps })
          for (const segment of snapshot.segmentKeys) await vaultStore.sealAndActivateSegment({ identityId: identity.did, segmentId: segment.segmentId, segmentKey: segment.key, selfGroupId: VAULT_STORAGE_GROUP_ID, epoch: VAULT_STORAGE_EPOCH, sealed: false, createdAt: snapshot.createdAt })
          await migrateLocalSegmentKeysToStorageRoot(vaultStore, vaultStore, identity, selfGroupStore)
          const projection = await buildLocalJmapProjectionRebuild(vaultStore, vaultStore, vaultStore, selfGroupStore, identity.did, identity.masterSeed)()
          await vaultStore.advanceDeliveryCursor(identity.did, identity.deviceKid!, checkpoint.coveredSeq, projection.state, new Date().toISOString())
        } finally {
          if (snapshot) for (const segment of snapshot.segmentKeys) segment.key.fill(0)
        }
      }

      const flushed = await flushCoordinatorStreamOutbox(vaultStore, transport, identity.did, vaultId)
      if (flushed.failedEntryId) throw new Error(`Coordinator stream append failed: ${flushed.failureReason ?? flushed.failedEntryId}`)
      const synced = await synchronizeCoordinatorStream(vaultStore, transport, { ingest: item => ingestVaultDelivery(item, boundary.signer, projector, vaultStore) }, identity.did, identity.deviceKid!, vaultId)
      if (synced.ingestedSequences.length > 0) await refreshInbox(readModel)

      // A checkpoint, not device ACKs, is the only server-side compaction
      // boundary. Any device can replace it after reaching the stream head.
      const coveredSeq = await vaultStore.readDeliveryCursor(identity.did, identity.deviceKid!)
      const checkpointBehind = coordinatorStreamCheckpointIsBehind(checkpoint?.coveredSeq, coveredSeq)
      if (coveredSeq === synced.latestSeq && (flushed.appendedEntryIds.length > 0 || checkpointBehind || checkpointNeedsUpgrade || checkpointNeedsEventCredentialUpgrade)) {
        if (!identity.masterSeed) throw new Error('Coordinator checkpoint requires the identity master seed')
        const snapshot = await createRecoveryArchiveSnapshot(vaultStore, boundary.resolver, identity.did, new Date().toISOString())
        try {
          const payload = await createPortableCoordinatorCheckpoint(fromHex(identity.masterSeed), snapshot, { vaultId, coveredSeq })
          await transport.putStreamCheckpoint({ version: 2, vaultId, coveredSeq, payload, payloadHash: sha256Bytes(payload) })
          checkpointSeq = coveredSeq
        } finally {
          for (const segment of snapshot.segmentKeys) segment.key.fill(0)
        }
      }
      return { localSeq: coveredSeq, latestSeq: synced.latestSeq, ...(checkpointSeq === undefined ? {} : { checkpointSeq }) }
    }
    const synchronizeStream = async (): Promise<void> => {
      if (!streamTransport || !streamVaultId) return
      // Keep an already-green card stable during the routine ten-second
      // poll. "Syncing" is useful during first connection/error recovery,
      // but flashing the card blue forever is just visual noise.
      if (vaultCardStatus?.state !== 'connected') {
        setVaultCard({ state: 'syncing', coordinatorUrl, vaultId: streamVaultId, detail: 'Synchronizing encrypted Vault' })
      }
      try {
        const result = await synchronizeStreamOnce()
        setVaultCard({
          state: 'connected', coordinatorUrl, vaultId: streamVaultId,
          ...(result ?? {}), detail: 'Encrypted stream is current',
        })
      } catch (error) {
        let detail = error instanceof Error ? error.message : String(error)
        if (detail === 'Coordinator checkpoint key cannot be unwrapped') {
          // The browser-wide Anchor cookie may have selected another local
          // identity's subject. Never overwrite that subject's checkpoint:
          // discard only this identity-scoped refresh session and require an
          // explicit prompt=login retry with the current Wallet credential.
          await coordinatorOidc?.clear()
          streamTransport = undefined
          coordinatorBindingActive = false
          flushCoordinatorOutbox = undefined
          detail = 'Coordinator login belongs to another identity. Reconnect to authenticate this identity.'
        }
        setVaultCard({ state: 'error', coordinatorUrl, vaultId: streamVaultId, detail })
        if (detail !== (error instanceof Error ? error.message : String(error))) throw new Error(detail, { cause: error })
        throw error
      }
    }
    const activateCoordinatorStream = async (oidc: AnchorOidcPkceClient): Promise<void> => {
      setVaultCard({ state: 'connecting', coordinatorUrl, detail: 'Opening Coordinator stream' })
      streamTransport = new VaultCoordinatorTransport({ baseUrl: coordinatorUrl, accessTokens: oidc })
      streamVaultId = (await streamTransport.defaultStream()).vaultId
      coordinatorBindingActive = true
      flushCoordinatorOutbox = () => flushCoordinatorStreamOutbox(vaultStore, streamTransport!, identity.did, streamVaultId!)
      await synchronizeStream()
    }
    connectCoordinator = async () => {
      setVaultCard({ state: 'connecting', coordinatorUrl, vaultId: streamVaultId, detail: 'Waiting for Anchor login' })
      const oidc = await ensureCoordinatorOidc()
      try {
        await oidc.authorize()
        await activateCoordinatorStream(oidc)
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error)
        setVaultCard({ state: 'error', coordinatorUrl, vaultId: streamVaultId, detail })
        throw error
      }
    }
    synchronizeCoordinator = synchronizeStream
    createCoordinatorInvitation = undefined
    approveCoordinatorDevice = undefined
    joinCoordinatorInvitation = undefined
    autoConnectCoordinator = connectCoordinator
    // A prior explicit login leaves a rotating refresh token in the local
    // wallet. Resume polling without another popup on every ordinary boot.
    void (async () => {
      const oidc = await ensureCoordinatorOidc()
      if (await oidc.hasRefreshSession()) await activateCoordinatorStream(oidc)
      else if (vaultCardStatus?.state === 'checking') setVaultCard({ state: 'reconnect-required', coordinatorUrl, detail: 'No saved login session' })
    })().catch(error => {
      const detail = error instanceof Error ? error.message : String(error)
      setVaultCard({ state: 'error', coordinatorUrl, vaultId: streamVaultId, detail })
      console.warn('[coordinator/session-resume]', detail)
    })
    let coordinatorPollBusy = false
    coordinatorPollTimer = setInterval(() => {
      if (!streamTransport || !streamVaultId) return
      if (coordinatorPollBusy) return
      coordinatorPollBusy = true
      void (async () => {
        await synchronizeCoordinator?.()
      })().catch(error => console.warn('[coordinator/poll]', error instanceof Error ? error.message : error)).finally(() => { coordinatorPollBusy = false })
    }, 10_000)
  } else if (mimiVaultConfigured && identity.deviceKid) {
    // Self/Vault traffic is a normal-mode MIMI room on its isolated provider.
    // There is deliberately no Anchor/OIDC token here: membership plus the
    // MLS leaf signature authenticate every request.
    const provider = new URL(mimiSelfBaseUrl)
    const transport = new MimiClientTransport({ normalBaseUrl: mimiSelfBaseUrl, anonBaseUrl: mimiSelfBaseUrl, selfBaseUrl: mimiSelfBaseUrl })
    let room = await selfGroupStore.loadMimiVault(identity.did)
    const stored = await selfGroupStore.load(identity.did)
    const credential = stored
      ? ownMlsDeviceCredential(stored.state)
      : createMlsDeviceCredential(identity.did, identity.generation, fromHex(identity.signPublicKey), fromHex(identity.rootPrivateKey), fromHex(identity.signPrivateKey))
    const signaturePrivateKey = stored ? ownSignaturePrivateKey(stored.state) : fromHex(identity.signPrivateKey)
    if (credential.deviceKid !== identity.deviceKid) throw new Error('MIMI Vault device credential does not match this identity device')
    const selfGroupId = stored?.selfGroupId ?? 'mimi-vault'
    const routedRoom = await fetchRouting(identity.did, fetch)
      .then(doc => mimiVaultRoomFromRouting(doc, mimiSelfBaseUrl))
      .catch(error => { console.warn('[mimi-vault/routing-read]', error instanceof Error ? error.message : error); return undefined })
    if (!room && routedRoom) {
      await joinMimiVaultRoom({
        identityId: identity.did, deviceId: credential.deviceKid, selfGroupId, roomId: routedRoom, credential, signaturePrivateKey, transport, stateStore: selfGroupStore,
      })
      room = await selfGroupStore.loadMimiVault(identity.did)
    }
    if (!room) {
      await createMimiVaultRoom({
        identityId: identity.did, deviceId: credential.deviceKid, selfGroupId, credential, signaturePrivateKey, transport, stateStore: selfGroupStore,
        providerHost: provider.hostname,
      })
      room = await selfGroupStore.loadMimiVault(identity.did)
    }
    if (!room) throw new Error('MIMI Vault room initialization did not persist')
    // The random room URI is the sole bootstrap pointer for a restored
    // device; it is signed routing metadata, not Vault content or key
    // material. Retry best-effort on each boot if routing is temporarily out.
    await setRoutingMimiVaultRoom(identity.did, room.roomId, mimiSelfBaseUrl, {
      updateKey: encodeMultikey(fromHex(identity.signPublicKey)), privateKey: fromHex(identity.signPrivateKey),
    }, fetch).catch(error => console.warn('[mimi-vault/routing-publish]', error instanceof Error ? error.message : error))
    const mlsCredential = ownMlsDeviceCredential(room.state)
    const session = new PersistedMimiVaultSession({
      identityId: identity.did, mode: 'self', transport, stateStore: selfGroupStore,
      credential: { kind: 'visible', user: identity.did, client: identity.deviceKid, credential: encodeMlsDeviceCredential(mlsCredential), signaturePublicKey: mlsCredential.signaturePublicKey },
      sign: bytes => ed25519.sign(bytes, ownSignaturePrivateKey(room!.state)),
    })
    const boundary = buildVaultCryptoBoundary(vaultStore, vaultStore, selfGroupStore, identity)
    const projector = buildVaultDeliveryProjector(selfGroupStore, identity.did, () => readModel.snapshot(), identity.masterSeed)
    const synchronizeMimi = async (): Promise<void> => {
      setVaultCard({ state: 'syncing', coordinatorUrl: mimiSelfBaseUrl, vaultId: room!.roomId as never, detail: 'Synchronizing encrypted MIMI Vault' })
      // Provider sequence is separate from the Vault event cursor.  Keep it
      // with the encrypted MLS state so historical commits/checkpoints are
      // not replayed on every ten-second poll.
      const beforeSync = await selfGroupStore.loadMimiVault(identity.did)
      const providerCursor = beforeSync?.deliveryCursor ?? 0
      const result = await synchronizeMimiVault({
        pull: value => transport.pullDeliveries('self', value),
        signPull: unsigned => ed25519.sign(deliveriesPullSigningBytes(unsigned), ownSignaturePrivateKey(room!.state)),
        pullRequest: { version: 1, roomId: room!.roomId, requester: { kind: 'visible', user: identity.did, client: identity.deviceKid!, credential: encodeMlsDeviceCredential(ownMlsDeviceCredential(room!.state)), signaturePublicKey: ownMlsDeviceCredential(room!.state).signaturePublicKey }, requestedAt: new Date().toISOString() },
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
          } finally { for (const segment of snapshot.segmentKeys) segment.key.fill(0) }
        },
      })
      if (result.latestSequence > providerCursor) {
        const current = await selfGroupStore.loadMimiVault(identity.did)
        if (!current) throw new Error('MIMI Vault state disappeared while synchronizing')
        await selfGroupStore.saveMimiVault(identity.did, { ...current, deliveryCursor: result.latestSequence })
      }
      if (result.ingestedSequences.length) await refreshInbox(readModel)
      if (result.latestSequence > 1 && result.checkpoints.length === 0 && identity.masterSeed) {
        const snapshot = await createRecoveryArchiveSnapshot(vaultStore, boundary.resolver, identity.did, new Date().toISOString())
        try {
          const payload = await createPortableCoordinatorCheckpoint(fromHex(identity.masterSeed), snapshot, { vaultId: room!.roomId as never, coveredSeq: deliverySeq(BigInt(result.latestSequence)) })
          await sendMimiVaultCheckpoint(payload, result.latestSequence, session)
        } finally { for (const segment of snapshot.segmentKeys) segment.key.fill(0) }
      }
      setVaultCard({ state: 'connected', coordinatorUrl: mimiSelfBaseUrl, vaultId: room!.roomId as never, localSeq: String(await vaultStore.readDeliveryCursor(identity.did, identity.deviceKid!)), latestSeq: String(result.latestSequence), detail: 'Encrypted MIMI Vault is current' })
    }
    await synchronizeMimi()
    let mimiPollBusy = false
    coordinatorPollTimer = setInterval(() => {
      if (mimiPollBusy) return
      mimiPollBusy = true
      void synchronizeMimi().catch(error => {
        const detail = error instanceof Error ? error.message : String(error)
        setVaultCard({ state: 'error', coordinatorUrl: mimiSelfBaseUrl, vaultId: room!.roomId as never, detail })
        console.warn('[mimi-vault/poll]', detail)
      }).finally(() => { mimiPollBusy = false })
    }, 10_000)
  }
}

/** Keeps the initial public API explicit while account routing is implemented. */
export function accountKind(session: AccountSession): AccountSession['kind'] {
  return session.kind
}

bootClient()
