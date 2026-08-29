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
import { didCommThreadId } from './didcomm/basicmessage.ts'
import { registerWithMediator, startMediatorPolling, type MediatorPollHandle } from './didcomm/mediator-sync.ts'
import type { DidCommSender } from './didcomm/mediator-transport.ts'
import type { DeliveredMessage } from './didcomm/mediator-pickup.ts'
import { startMailMediatorPolling } from './didcomm/mail-mediator-sync.ts'
import type { PickupItem } from './mail-mediator/protocol.ts'
import { MailRelationshipCredentialReader } from './vault/mail-relationship-credential-reader.ts'
import { MailRelationshipCredentialVaultSink } from './vault/mail-relationship-credential-sink.ts'
import { ensureMailRelationship } from './identity/mail-relationship.ts'
import { MailMediatorSubmissionTransport } from './vault/mail-mediator-submission-transport.ts'
import { ingestTransportIngress } from './vault/ingress-ingest.ts'
import { flushVaultDeliveryOutbox } from './vault/delivery-outbox.ts'
import type { IngressEnvelopeV1 } from './protocol/ingress.ts'
import { canonicalHash, equalBytes, sha256Bytes } from './protocol/canonical.ts'
import { fetchRouting, putRouting, setRoutingName } from './didcomm/webvh-routing.ts'
import { activatePreRotation, deactivatePreRotation, rotateToPreRotatedKey } from './identity/webvh/prerotation.ts'
import { moveWebvhIdentity } from './identity/webvh/move.ts'
import { adoptPendingMove } from './identity/webvh/adopt-move.ts'
import { encodeMultikey } from './identity/webvh/multikey.ts'
import { removeDeviceVerificationMethod } from './identity/webvh/remove-device-verification-method.ts'
import { removeDeviceFromSelfGroup, type SelfGroupSigner } from './mls/self-group.ts'
import { ownSignaturePrivateKey } from './mls/group.ts'
import { CoordinatorMlsDeliveryTransport } from './mls/coordinator-mls-delivery-transport.ts'
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
  const storedRecords = await recordStore.list().catch(() => [])
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
    adoptPendingMove({ recordStore, record, vaultStore, selfGroupStore, keyPackageStore: keyStore }).catch(e => {
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
  const { apexDomain, anchorBaseUrl, anchorOidcClientId, coreBaseUrl, mediatorUrls, mailMediatorUrls, coordinatorUrl } = readBisetConfig()
  // Catch up MLS and repair every local SegmentKey wrap before any inbox,
  // credential, or relationship reader attempts decryption. Running this
  // near the end of boot used to render an empty inbox first; if a segment
  // had skipped more than one epoch, the transition-only self-grant could
  // not repair it at all on later reloads.
  if (coreBaseUrl && coordinatorUrl) {
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
  const coordinatorConfigured = !!(anchorBaseUrl && anchorOidcClientId && coordinatorUrl && identity.deviceKid)
  let vaultCardStatus: VaultCardStatus | undefined = coordinatorConfigured ? {
    state: 'checking', coordinatorUrl, detail: 'Checking saved login session',
  } : undefined
  const setVaultCard = (next: VaultCardStatus): void => {
    if (vaultCardStatus && JSON.stringify(vaultCardStatus) === JSON.stringify(next)) return
    vaultCardStatus = next
    updateVaultCardStatus(next)
  }
  const ensureCoordinatorOidc = async (): Promise<AnchorOidcPkceClient> => {
    if (coordinatorOidc) return coordinatorOidc
    if (!coordinatorConfigured) throw new Error('Coordinator login is not configured')
    coordinatorOidcInitialization ??= (async () => {
      const trust = await discoverTrustedAnchorOid4vpIssuer(anchorBaseUrl)
      const wallet = new BisetOid4vpWallet({ identityId: identity.did, trust, store: loginWalletStore })
      if (!(await wallet.current())) {
        await wallet.enroll({
          did: identity.did,
          authenticationVerificationMethod: `${identity.did}#key-1`,
          authenticationPrivateKey: fromHex(identity.rootPrivateKey),
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
  // Signs with the ROOT private key (the same key routing.json's own
  // keyAgreement/alsoKnownAs entries are already signed with, webvh-routing.ts's
  // DataIntegrityProof) -- account-page.ts never sees key material itself,
  // only calls this callback.
  const editName = async (name: string): Promise<void> => {
    const rootPrivateKey = fromHex(identity.rootPrivateKey)
    const rootPublicKey = fromHex(identity.rootPublicKey)
    await setRoutingName(identity.did, name, { updateKey: encodeMultikey(rootPublicKey), privateKey: rootPrivateKey }, fetch)
  }
  // Revoke = cut the target device out of MLS membership (so it can't read
  // anything committed after this point, mls/self-group.ts's own
  // removeDeviceFromSelfGroup) + drop its verificationMethod entry from the
  // DID document (so nothing resolving this identity still treats its leaf
  // key as valid).
  //
  // Does NOT touch routing.json's DIDComm keyAgreement entry: since
  // 2026-08-27 (ARC.md's DIDComm mediator redesign) that key is
  // IDENTITY-shared, not per-device (vault/didcomm-credential.ts, same
  // shape as the OpenPGP mail credential) -- every trusted device holds the
  // SAME private key, so there is no longer a per-device entry to look up
  // and remove; doing so the old way would have deleted the one shared
  // entry every REMAINING device still legitimately needs. A revoked device
  // that copied the shared private key before being cut off can still read
  // DIDComm messages addressed to it until the shared key is actively
  // rotated -- the same gap the OpenPGP credential already has
  // (`supersedesFingerprint` chain exists, no rotation UI/trigger wired
  // yet). Rotating the DIDComm credential here, the same way, is real
  // follow-up work, not something this call silently half-does.
  const revokeDevice = async (targetDeviceKid: string): Promise<void> => {
    if (!identity.deviceKid) throw new Error('This device has no MLS credential yet')
    if (!coordinatorUrl) throw new Error('coordinatorUrl not configured')
    const stored = await selfGroupStore.load(identity.did)
    if (!stored) throw new Error('No self-group state for this identity')
    const sign: SelfGroupSigner = bytes => ed25519.sign(bytes, ownSignaturePrivateKey(stored.state))
    const mlsTransport = new CoordinatorMlsDeliveryTransport({ baseUrl: coordinatorUrl })
    await removeDeviceFromSelfGroup(selfGroupStore, mlsTransport, identity.did, identity.deviceKid, targetDeviceKid, sign)
    const rootPrivateKey = fromHex(identity.rootPrivateKey)
    const rootPublicKey = fromHex(identity.rootPublicKey)
    await removeDeviceVerificationMethod({ did: identity.did, deviceKeyId: targetDeviceKid, signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey })
  }
  // did:webvh pre-rotation (identity/webvh/prerotation.ts) — independent of
  // coreBaseUrl/deviceKid, same reasoning as editName/revokeDevice above:
  // this is a plain did.jsonl operation against the identity's own domain,
  // nothing to do with the mail/DIDComm core. The Spare Key phrase itself
  // (generate/display/prompt) is handled entirely in account-page.ts, which
  // only ever hands this file the already-revealed key bytes to sign with —
  // same "root key stays here" split as editName/revokeDevice.
  const activateKeyRotation = async (nextKeyHash: string): Promise<void> => {
    const rootPrivateKey = fromHex(identity.rootPrivateKey)
    const rootPublicKey = fromHex(identity.rootPublicKey)
    await activatePreRotation({ did: identity.did, signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey, nextKeyHash })
  }
  const rotateKeyRotation = async (revealedPrivateKey: Uint8Array, revealedPublicKey: Uint8Array, nextKeyHash: string): Promise<void> => {
    const rootPublicKey = fromHex(identity.rootPublicKey)
    await rotateToPreRotatedKey({ did: identity.did, revealedPrivateKey, revealedPublicKey, identityPublicKey: rootPublicKey, nextKeyHash })
  }
  const deactivateKeyRotation = async (revealedPrivateKey: Uint8Array, revealedPublicKey: Uint8Array): Promise<void> => {
    const rootPublicKey = fromHex(identity.rootPublicKey)
    await deactivatePreRotation({ did: identity.did, revealedPrivateKey, revealedPublicKey, identityPublicKey: rootPublicKey })
  }
  // did:webvh domain move (identity/webvh/move.ts) — same coreBaseUrl-
  // independence as editName/revokeDevice/pre-rotation above for the
  // did.jsonl half; the MLS self-group credential migration half (only
  // relevant once this device has a deviceKid at all) does need a core to
  // submit the migration commit through, same as revokeDevice's own MLS
  // step.
  const moveIdentity = async (newDomain: string): Promise<string> => {
    const previousDid = identity.did
    const rootPrivateKey = fromHex(identity.rootPrivateKey)
    const rootPublicKey = fromHex(identity.rootPublicKey)
    let mlsTransport: CoordinatorMlsDeliveryTransport | undefined
    let mlsSign: SelfGroupSigner | undefined
    if (identity.deviceKid) {
      if (!coordinatorUrl) throw new Error('coordinatorUrl not configured')
      const stored = await selfGroupStore.load(identity.did)
      if (!stored) throw new Error('No self-group state for this identity')
      mlsSign = bytes => ed25519.sign(bytes, ownSignaturePrivateKey(stored.state))
      mlsTransport = new CoordinatorMlsDeliveryTransport({ baseUrl: coordinatorUrl })
    }
    const moved = await moveWebvhIdentity({
      recordStore, record: identity, vaultStore, selfGroupStore, keyPackageStore: keyStore,
      mlsTransport, mlsSign, newDomain, signingPrivateKey: rootPrivateKey, signingPublicKey: rootPublicKey,
    })
    await loginWalletStore.rekeyIdentity(previousDid, moved.did)
    identity = moved
    // A full re-render, same as logout()'s own re-entry into bootClient()
    // just above -- account-page.ts's own config (did/deviceKid/masterSeed)
    // was captured at configure time below, not read live, so there is no
    // lighter way to get the identity card, devices list, and every other
    // did-scoped closure in this file (editName, revokeDevice, the
    // pre-rotation trio) onto the new did without going through this same
    // boot path again.
    await bootClient()
    return moved.did
  }
  configureAccountPage({
    did: identity.did, deviceKid: identity.deviceKid, masterSeed: identity.masterSeed,
    onLogout: logout, onEditName: editName, onRevokeDevice: revokeDevice,
    onActivateKeyRotation: activateKeyRotation, onRotateKeyRotation: rotateKeyRotation, onDeactivateKeyRotation: deactivateKeyRotation,
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
    const eventVerifier = buildRestoreTransferVerifier(selfGroupStore, identity.did).eventVerifier
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
        verifier: buildRestoreTransferVerifier(selfGroupStore, identity.did).eventVerifier,
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
        verifier: buildRestoreTransferVerifier(selfGroupStore, identity.did).eventVerifier,
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
        verifier: buildRestoreTransferVerifier(selfGroupStore, identity.did).eventVerifier,
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
      const rootPrivateKey = fromHex(identity.rootPrivateKey)
      const rootPublicKey = fromHex(identity.rootPublicKey)
      await enableOpenPgpMail(pgpReader, pgpSink, { updateKey: encodeMultikey(rootPublicKey), privateKey: rootPrivateKey }, { identityId: identity.did, mailAddress: mailFrom })
        .catch(e => console.warn('[enableOpenPgpMail]', e instanceof Error ? e.message : e))
    }

    // Mail Mediator outbound submission (PLAN_biset-mail-mediator.md
    // section 12): opt-in via the first configured mailMediatorUrls entry,
    // only once this identity's front-door DIDComm credential exists.
    // Falls back to buildMailSubmitter's own default (CoreMailSubmissionTransport)
    // otherwise -- switching submission paths must never regress a device
    // that hasn't enabled DIDComm at all.
    const mailMediatorSubmissionUrl = mailMediatorUrls[0]
    const mailMediatorTransport = mailMediatorSubmissionUrl && anchorBaseUrl
      ? new MailMediatorSubmissionTransport({
          mediatorUrl: mailMediatorSubmissionUrl,
          identityDid: identity.did,
          anchorBaseUrl,
          relationshipReader: new MailRelationshipCredentialReader({
            identityId: identity.did, objects: vaultStore, events: vaultStore,
            segmentKeys: boundary.resolver, verifier: buildRestoreTransferVerifier(selfGroupStore, identity.did).eventVerifier,
          }),
          relationshipSink: new MailRelationshipCredentialVaultSink({
            identityId: identity.did, actorDeviceId: deviceKid,
            nextActorSeq: () => sequencer.nextActorSeq(), initialParents: () => sequencer.initialParents(),
            activeSegment: () => boundary.activeSegment(), currentSnapshot: () => readModel.snapshot(),
            signer: boundary.signer, committer: vaultStore,
          }),
        })
      : undefined
    const submitter = buildMailSubmitter(vaultStore, selfGroupStore, identity, mutationSink, apexDomain, coreBaseUrl, mailMediatorTransport)
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
      if (input.toAddrs.length === 1 && input.toAddrs[0]!.startsWith('did:')) {
        await sendDidCommChat(input.toAddrs[0]!, input)
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

    syncMailIngress = async () => {
      const mailProjector = new MailIngressProjector({
        identityId: identity.did,
        actorDeviceId: identity.deviceKid!,
        nextActorSeq: () => sequencer.nextActorSeq(),
        initialParents: () => sequencer.initialParents(),
        activeSegment: () => boundary.activeSegment(),
        currentSnapshot: () => readModel.snapshot(),
        signer: boundary.signer,
      })
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

      // Mail Mediator pickup bridge (PLAN_biset-mail-mediator.md section
      // 4): the raw RFC 5322 bytes a spooled item carries are handed
      // straight to the SAME MailIngressProjector core's own SMTP path
      // uses (mail/ingress-projector.ts), via `protocol: 'mail'` --
      // there is no separate "DIDComm-mail" ingress kind, just a
      // different transport landing on the identical vault-commit shape.
      async function onMailMediatorItem(item: PickupItem, mediatorUrl: string): Promise<void> {
        const mailProjector = new MailIngressProjector({
          identityId: identity.did,
          actorDeviceId: identity.deviceKid!,
          nextActorSeq: () => sequencer.nextActorSeq(),
          initialParents: () => sequencer.initialParents(),
          activeSegment: () => boundary.activeSegment(),
          currentSnapshot: () => readModel.snapshot(),
          signer: boundary.signer,
        })
        const envelope: IngressEnvelopeV1 = {
          version: 1,
          ingressId: canonicalHash('biset/mail-mediator-ingress/v1', { mediatorUrl, spoolId: item.spoolId }),
          protocol: 'mail',
          recipientIdentityId: identity.did,
          recipientDeviceSnapshot: [identity.deviceKid!],
          createdAt: item.createdAt,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
          transportMetadata: {},
          sourceEvidence: new Uint8Array(0),
          protectedPayload: item.encryptedBody,
          protectedPayloadHash: sha256Bytes(item.encryptedBody),
        }
        await ingestTransportIngress(envelope, mailProjector, vaultStore)
        await flushReplicationOutbox()
        await refreshInbox(readModel)
      }

      async function onMessage(msg: DeliveredMessage, recipientKid: string, mediatorUrl: string): Promise<void> {
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
        mediatorPollHandles.push(startMediatorPolling(
          mediatorUrl,
          relationshipOwn,
          resolveAnyDidCommSenderKey,
          msg => onMessage(msg, xKid, mediatorUrl),
        ))
      }

      for (const url of mediatorUrls) {
        mediatorPollHandles.push(startMediatorPolling(url, own, resolveAnyDidCommSenderKey, msg => onMessage(msg, didCommKid, url)))
      }

      // Mail Mediator route bind + pickup poll (PLAN_biset-mail-mediator.md
      // section 4, revised to a VC-based route-bind): route-bind carries
      // a BisetMailAddressOwnershipCredential Anchor issues for a fresh
      // relationship identity -- the mediator never learns this
      // identity's own did:webvh at any point, not even at bind time.
      // Best-effort per mediator, same treatment as enableDidComm: a
      // mediator or Anchor briefly unreachable at boot must not block
      // mail already working through core/SMTP.
      for (const url of anchorBaseUrl ? mailMediatorUrls : []) {
        const mailRelReader = new MailRelationshipCredentialReader({
          identityId: identity.did, objects: vaultStore, events: vaultStore,
          segmentKeys: boundary.resolver, verifier: buildRestoreTransferVerifier(selfGroupStore, identity.did).eventVerifier,
        })
        const mailRelSink = new MailRelationshipCredentialVaultSink({
          identityId: identity.did, actorDeviceId: deviceKid,
          nextActorSeq: () => sequencer.nextActorSeq(), initialParents: () => sequencer.initialParents(),
          activeSegment: () => boundary.activeSegment(), currentSnapshot: () => readModel.snapshot(),
          signer: boundary.signer, committer: vaultStore,
        })
        ensureMailRelationship(mailRelReader, mailRelSink, identity.did, mailFrom, url, anchorBaseUrl)
          .then(credential => {
            const relationshipXKid = decodePeerDid2(credential.relationshipDid).keyAgreement[0]!
            const relationship: DidCommSender = { did: credential.relationshipDid, xKid: relationshipXKid, xPriv: credential.privateKey }
            mediatorPollHandles.push(startMailMediatorPolling(url, relationship, credential.address, item => onMailMediatorItem(item, url)))
          })
          .catch(e => console.warn('[mail-mediator]', e instanceof Error ? e.message : e))
      }
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
    const synchronizeStreamOnce = async (): Promise<{ localSeq: string; latestSeq: string; checkpointSeq?: string } | undefined> => {
      if (!streamTransport || !streamVaultId) return undefined
      const transport = streamTransport
      const vaultId = streamVaultId
      const checkpoint = await transport.pullStreamCheckpoint(vaultId)
      let checkpointSeq = checkpoint?.coveredSeq
      const checkpointNeedsUpgrade = checkpoint ? (() => { try { return (JSON.parse(new TextDecoder().decode(checkpoint.payload)) as { version?: unknown }).version === 1 } catch { return false } })() : false
      const localCursor = await vaultStore.readDeliveryCursor(identity.did, identity.deviceKid!)
      if (checkpoint && BigInt(checkpoint.coveredSeq) > BigInt(localCursor)) {
        if (!identity.masterSeed) throw new Error('Coordinator checkpoint restore requires the identity master seed')
        if (!equalBytes(sha256Bytes(checkpoint.payload), checkpoint.payloadHash)) throw new Error('Coordinator checkpoint payload hash is invalid')
        let snapshot: Awaited<ReturnType<typeof openCoordinatorCheckpoint>> | undefined
        try {
          snapshot = await openPortableCoordinatorCheckpoint(fromHex(identity.masterSeed), checkpoint.payload, { vaultId, coveredSeq: checkpoint.coveredSeq, coordinatorUrl })
          if (snapshot.identityId !== identity.did) throw new Error('Coordinator checkpoint belongs to another identity')
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
      if (coveredSeq === synced.latestSeq && (flushed.appendedEntryIds.length > 0 || checkpointBehind || checkpointNeedsUpgrade)) {
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
        const detail = error instanceof Error ? error.message : String(error)
        setVaultCard({ state: 'error', coordinatorUrl, vaultId: streamVaultId, detail })
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
  }
}

/** Keeps the initial public API explicit while account routing is implemented. */
export function accountKind(session: AccountSession): AccountSession['kind'] {
  return session.kind
}

bootClient()
