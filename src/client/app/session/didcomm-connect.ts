// The network half of a session: this device's DIDComm key registered with its mediator, Vault Sync with its siblings, DID
// Rotation with its counterparties, the durable outbox, and the live watch that brings what arrives.
//
// DIDComm has its own X25519 leaf, never the MLS signing leaf and never a did.md controller key. Wallet published the public
// leaf and mediator route during the explicit consent that enrolled it; registration only proves possession of the local
// X25519 private key to the mediator.
import { DidCommIngressProjector } from '../../didcomm/ingress-projector.ts'
import { preferredMediatorUrl, isTorEnvironment } from '../../didcomm/mediator-endpoints.ts'
import { watchMediatorLive } from '../../didcomm/mediator-live.ts'
import { registerWithMediator, type MediatorPollHandle } from '../../didcomm/mediator-sync.ts'
import { createRotationManager, type RotationManager } from '../../didcomm/rotation-manager.ts'
import { resolveDidCommSenderKey } from '../../../protocol/didcomm/sender-key.ts'
import { sendFrontDoorMessage } from '../../didcomm/front-door-send.ts'
import { VaultSyncClient, vaultSyncChunkBytes, walletVaultSyncTransport } from '../../didcomm/vault-sync.ts'
import { freshFetch } from '../../identity/log-io.ts'
import type { DidMdBisetDidCommDevice } from '../../identity/wallet/did-md-oauth.ts'
import { createWalletDidCommOutbox, type WalletDidCommOutbox } from '../../identity/wallet/didcomm-outbox.ts'
import { bridgeHostOf, mailAddressOfBridgeDid, ownAutocryptFor, shouldEncrypt } from '../../pgp/autocrypt.ts'
import { composeEncryptedMail } from '../../pgp/compose.ts'
import { autocryptKeydata } from '../../pgp/keyring.ts'
import { contactCardForDid, currentAutocryptKey, replyTokenOf } from '../../store/projection/contacts.ts'
import { base64ToBytes } from '../../../protocol/base64.ts'
import { resolveDidDocument, verifiedVhAddress } from '../../../protocol/did-resolve.ts'
import { discoverMaxReceiveBytes } from '../../../protocol/didcomm/discover-features.ts'
import { didCommRouteFromDocument } from '../../../protocol/didcomm/doc-route.ts'
import { fromPriorKeyResolver, verifyFromPrior } from '../../../protocol/didcomm/from-prior.ts'
import { signingKeyResolver } from '../../../protocol/didcomm/jws.ts'
import { mediatorInbox } from '../../../protocol/didcomm/mediator-device.ts'
import { expandEndpoint } from '../../../protocol/didcomm/mediator-endpoint.ts'
import { decodePeerDid2, publicKeyOf } from '../../../protocol/didcomm/peer.ts'
import { SenderKeyNotPublishedError } from '../../../protocol/didcomm/sender-key.ts'
import { errorMessage } from '../../../protocol/error-message.ts'
import { labelForDid } from '../ui/did-display.ts'
import { showSysMsg } from '../ui/shell.ts'
import type { AccountVault } from './account-vault.ts'
import { timed } from './boot-timing.ts'
import { incomingHandler, type MediatorDelivery } from './incoming.ts'
import type { OwnIdentity } from './own-identity.ts'
import { createSecureJoin, type SecureJoin } from './secure-join.ts'
import type { SessionSeeds } from './seeds.ts'

export interface DidCommConnection {
  outbox: WalletDidCommOutbox
  secureJoin: SecureJoin
  /** Set when the identity's rotation key needs a Wallet approval (account page). */
  rotationKeyState?: 'unpublished' | 'lost' | 'stale'
}

/** This identity's own devices: the keyAgreement keys its DID document lists now. Historical event actors are audit history,
 * not devices: using them made every past login remain in the UI. */
export interface OwnDevices {
  refresh(): Promise<void>
  includes(kid: string): boolean
}

/** A did:peer is self-certifying: a kid it does not contain never will. Any other DID is resolved. */
function resolveAnyDidCommSenderKey(kid: string): Promise<Uint8Array> {
  if (kid.startsWith('did:peer:2.')) {
    try { return Promise.resolve(publicKeyOf(decodePeerDid2(kid.split('#', 1)[0]!), kid)) } catch { return Promise.reject(new SenderKeyNotPublishedError(kid)) }
  }
  return resolveDidCommSenderKey(kid)
}

/** URL serialization is canonical at the Wallet boundary (an origin gains its trailing slash), whereas deployment
 * configuration may omit it: canonical URLs are compared, not their source spellings. */
function isConfiguredMediator(url: string, configured: readonly string[]): boolean {
  const authorized = new URL(url).toString()
  return configured.some(candidate => { try { return new URL(candidate).toString() === authorized } catch { return false } })
}

/** Dials the mediator's onion entrance only when this page itself is served over Tor (PLAN-tor.md D-5, D-6): an ordinary
 * browser never attempts a `.onion` fetch. Falls back to the canonical URL when no onion is known or the onion fails. */
async function registerPreferringOnion(device: DidMdBisetDidCommDevice, inbox: ReturnType<typeof mediatorInbox>) {
  const preferred = preferredMediatorUrl({ canonicalUrl: device.mediatorUrl, onionUrl: device.mediatorOnionUrl }, isTorEnvironment())
  try {
    return { url: preferred, mediator: await timed('registerWithMediator', registerWithMediator(preferred, inbox)) }
  } catch (error) {
    if (preferred === device.mediatorUrl) throw error
    console.warn('[did.md Wallet DIDComm register] onion entrance unreachable, falling back to canonical', errorMessage(error))
    return { url: device.mediatorUrl, mediator: await timed('registerWithMediator', registerWithMediator(device.mediatorUrl, inbox)) }
  }
}

/** Connects; undefined when a later boot took over meanwhile (`stale`). Throws when this device cannot use its mediator. */
export async function connectDidComm(options: {
  vault: AccountVault
  /** The identity's DID. */
  did: string
  device: DidMdBisetDidCommDevice
  identity: OwnIdentity
  seeds: SessionSeeds
  devices: OwnDevices
  /** Every mediator this deployment is configured with, canonical and onion. */
  configuredMediators: readonly string[]
  onVaultConnected(): void
  onSiblingSync(): Promise<void>
  stale(): boolean
  keep(handle: MediatorPollHandle): void
}): Promise<DidCommConnection | undefined> {
  const { vault, device, identity, seeds } = options
  const { identityId } = vault
  if (!isConfiguredMediator(device.mediatorUrl, options.configuredMediators)) throw new Error('Wallet-authorized mediator is not configured by this Oui deployment')
  await timed('refreshVaultDevices', options.devices.refresh())
  if (!options.devices.includes(device.xKid)) throw new Error('This device is no longer listed in your DID document; reconnect did.md Wallet')
  const frontDoor = { did: device.did, xKid: device.xKid, xPriv: device.x25519PrivateKey }
  const frontDoorInbox = mediatorInbox(frontDoor, device.mediatorDeviceSecret)
  const { url: mediatorUrl, mediator } = await registerPreferringOnion(device, frontDoorInbox)
  if (mediator.xKid !== device.routingKid) throw new Error('Mediator routing key changed since Wallet authorization; enable messaging again')

  // Restore is "only while an existing sibling is reachable" (no recovery-mailbox fallback): a cold device pulls state from an
  // online sibling via the ordinary request below, and a fresh Vault with no siblings simply starts empty.
  const vaultSync = new VaultSyncClient(identityId, device.xKid, vault.store, walletVaultSyncTransport(frontDoor),
    async result => { if (result.targetIds.length || result.addedEventIds.length) await vault.projector.recomputeEmails(identityId, result.targetIds) },
    // Sized to what this identity's mediator says it takes; a mediator that does not say gets the conservative default.
    vaultSyncChunkBytes(await timed('discoverMaxReceiveBytes', discoverMaxReceiveBytes(mediator, frontDoorInbox).catch(() => undefined))))
  vault.setSiblingPush(events => vaultSync.push(events))
  await timed('refreshInbox', vault.refresh())
  // Registration and the transport are both live: nothing past here leaves the Vault card on 'checking'.
  options.onVaultConnected()

  // The seed's authority is the DID document. A seed a Wallet approval just published is stored in the Vault here, where it
  // reaches every sibling; the account page offers a renewal when the document's key needs one.
  const seedAuthority = await seeds.connect({ did: options.did, ownKid: device.xKid })
  let rotationKeyState: DidCommConnection['rotationKeyState']
  try {
    const status = await timed('seedAuthority.status', seedAuthority.status())
    if (status.state === 'unpublished' || status.state === 'lost' || status.state === 'stale') rotationKeyState = status.state
    else if (status.state === 'pending') console.info('[did.md Wallet] waiting for the generation seed from another device')
  } catch (error) {
    console.warn('[did.md Wallet generation seed status]', errorMessage(error))
  }
  // A fresh browser and a long-idle browser use the same pull route: ask every sibling (one message to this identity's own
  // DID) what this device's state lacks.
  const catchUpFromSiblings = () => {
    void vaultSync.requestState().catch(error => console.warn('[did.md Wallet Vault Sync catch-up]', errorMessage(error)))
  }
  catchUpFromSiblings()

  // DID Rotation: every message to a counterparty goes by the route its contact card gives, and a conversation moves to this
  // identity's own did:peer (Y) once the counterparty says it can. Y names the mediator of this identity's public DID
  // document, by DID -- the same on every device.
  // Set below, before any watch starts. Until then a delivery fails, and so stays unacknowledged at the mediator.
  let handle: (delivery: MediatorDelivery, recipientKid: string, mediatorUrl: string) => Promise<void> = async () => { throw new Error('DIDComm is still connecting') }
  const watch = (url: string, inbox: ReturnType<typeof mediatorInbox>, recipientKid: string, label: string) => {
    const live = watchMediatorLive({
      mediatorUrl: url,
      inbox,
      resolveSenderKey: resolveAnyDidCommSenderKey,
      onMessage: message => handle(message, recipientKid, url),
      onError: error => console.warn(`[did.md Wallet DIDComm ${label}]`, error),
      onMissed: catchUpFromSiblings,
    })
    options.keep({ stop: () => live.close() })
  }
  const rotationManager: RotationManager = createRotationManager({
    identityDid: options.did,
    frontDoor: { fromKid: device.xKid, x25519PrivateKey: device.x25519PrivateKey },
    cards: async () => (await vault.snapshot()).contactCards,
    async rotation() {
      const [{ seed }, mediatorDid] = await Promise.all([seedAuthority.require(), mediatorDidOfDocument()])
      return mediatorDid ? { seed, mediatorDid } : undefined
    },
    commit: writes => vault.commitContactWrites(writes),
    storedSeeds: () => seeds.all(),
    send: (toDid, type, body, sendOptions) => sendFrontDoorMessage(toDid, type, body, sendOptions),
    async watch(peer) {
      const url = (await expandEndpoint({ uri: decodePeerDid2(peer.did).service[0]!.serviceEndpoint.uri }, freshFetch())).url
      const inbox = mediatorInbox({ did: peer.did, xKid: peer.xKid, xPriv: peer.xPriv }, device.mediatorDeviceSecret)
      await registerWithMediator(url, inbox)
      watch(url, inbox, peer.xKid, 'rotation watch')
    },
    onError: error => console.warn('[did.md Wallet DID Rotation]', errorMessage(error)),
  })
  // Only a mediator named by DID: Y cannot embed a URL without the mediator's routing key, or what is sent to Y would not be
  // Forward-wrapped and the mediator could not open it.
  let ownMediatorDid: Promise<string | undefined> | undefined
  const mediatorDidOfDocument = () => ownMediatorDid ??= resolveDidDocument(options.did, { fetch: freshFetch() })
    .then(document => {
      const uri = document ? didCommRouteFromDocument(document).endpoint?.uri : undefined
      return typeof uri === 'string' && uri.startsWith('did:') ? uri : undefined
    })
    .catch(error => { ownMediatorDid = undefined; throw error })

  const secureJoin = createSecureJoin({ vault, mail: identity.mail, seeds, profile: () => identity.profile(), route: did => rotationManager.route(did) })
  const outbox = createOutbox(vault, identity, rotationManager)
  // Every message arrives at one of this device's keys in the DID document; each durable delivery is projected into this
  // browser's encrypted local Vault.
  const projector = new DidCommIngressProjector({
    identityId,
    actorDeviceId: vault.deviceId,
    resolveOwnKey: kid => rotationManager.ownKey(kid),
    resolveSenderKey: resolveAnyDidCommSenderKey,
    // Past the host's CDN: a stale document would accept a replaced key.
    verifyFromPrior: (jwt, from) => verifyFromPrior(jwt, from, fromPriorKeyResolver(freshFetch())),
    resolveSigningKey: kid => signingKeyResolver(freshFetch())(kid),
    resolveAddress: did => verifiedVhAddress(did, { fetch: freshFetch() }),
    async alreadyProcessed() { return false },
    ...vault.authoring,
    currentSnapshot: () => vault.snapshot(),
  })
  handle = incomingHandler({ vault, vaultSync, projector, rotationManager, answerSecureJoin: message => secureJoin.answer(message), onSiblingSync: options.onSiblingSync })
  if (options.stale()) return undefined

  watch(mediatorUrl, frontDoorInbox, device.xKid, 'watch')
  void rotationManager.sync()
  // A durable intent might predate this tab (or the previous send's network attempt). Flushing never delays the first render,
  // and is retried independently of incoming traffic; a failure leaves its row durable for the next pass.
  void outbox.flush()
  const retryTimer = setInterval(() => { void outbox.flush() }, 10_000)
  options.keep({ stop: () => clearInterval(retryTimer) })
  return { outbox, secureJoin, ...(rotationKeyState ? { rotationKeyState } : {}) }
}

function createOutbox(vault: AccountVault, identity: OwnIdentity, rotationManager: RotationManager): WalletDidCommOutbox {
  const { mail } = identity
  const cardOf = async (did: string) => contactCardForDid((await vault.snapshot()).contactCards, did)
  const reported = new Set<string>()
  return createWalletDidCommOutbox({
    identityId: vault.identityId,
    store: vault.store,
    readModel: vault.readModel,
    mutationSink: vault.mutationSink,
    route: publicDid => rotationManager.route(publicDid),
    fromName: async () => (await identity.profile()).name,
    // To a mail address: the token its bridge gave for it (didmail PROTOCOL.md §7.1), kept on the contact's card.
    replyToken: async toDid => replyTokenOf(await cardOf(toDid)),
    onReplyTokens: tokens => vault.keepReplyTokens(tokens),
    // To a mail address: this identity's OpenPGP key, which the bridge puts in an Autocrypt header.
    autocrypt: async toDid => ownAutocryptFor(toDid, mail ? await mail.pgp.current().then(key => key && { address: mail.address, privateKey: key.privateKey }) : undefined),
    // To a mail address whose key we hold and who asked for encryption: the message goes as an OpenPGP-encrypted mail.
    encrypt: async (toDid, content, message) => {
      const own = await mail?.pgp.current()
      const host = bridgeHostOf(toDid), toAddress = mailAddressOfBridgeDid(toDid)
      if (!own || !mail || !host || !toAddress) return undefined
      const card = await cardOf(toDid)
      const held = card && currentAutocryptKey(card)
      if (!held || !shouldEncrypt(held)) return undefined
      const profile = await identity.profile()
      const sendPicture = identity.takePictureFor(toDid, profile)
      return composeEncryptedMail({
        ...(profile.name ? { fromName: profile.name } : {}), ...(sendPicture ? { avatarBase64: profile.avatarBase64! } : {}),
        id: message.id, ...(message.thid ? { thid: message.thid } : {}), bridgeHost: host, ...(message.subject ? { subject: message.subject } : {}),
        content, sentAt: message.sentAt, fromAddress: mail.address, toAddress,
        own: { privateKey: own.privateKey, keydata: await autocryptKeydata(own.privateKey, mail.address) },
        peerKey: base64ToBytes(held.keydata),
      })
    },
    // A counterparty written to may be one the conversation can move with.
    onDelivered: item => { void rotationManager.offer(item.toDid).catch(() => undefined) },
    onError: (error, item) => {
      const reason = errorMessage(error)
      console.warn(`[did.md Wallet DIDComm outbox] ${item.emailId} -> ${item.toDid}:`, reason)
      // Said once per message, recipient and reason: the row is retried every few seconds, and the same failure each time is no news.
      const key = `${item.outboundEventId}\u0000${item.toDid}\u0000${reason}`
      if (reported.has(key)) return
      reported.add(key)
      showSysMsg(`Could not send to ${labelForDid(item.toDid)} yet (it stays queued and will be retried): ${reason}`)
    },
  })
}
