// A did.md Wallet session on this device: what the account page, the compose box and the inbox are given once the identity's
// Vault is open, and the DIDComm connection that follows it.
import { sameMediatorUrl } from '../../didcomm/mediator-endpoints.ts'
import { resolveOwnDeviceKids } from '../../didcomm/vault-sync.ts'
import {
  beginDidMdDocumentEdit, didMdSessionMovedTo, openDidMdWalletBisetDidCommDevice, openDidMdWalletVaultDevice, peekDidMdWalletSession,
  prepareDidMdMovedDidLoginRequest, restoreDidMdWalletSession, type DidMdActiveSession, type DidMdBisetDidCommDevice, type DidMdDocumentChange,
} from '../../identity/wallet/did-md-oauth.ts'
import { ditoEmbedOrigin } from '../../identity/wallet/dito-embed.ts'
import type { MediatorPollHandle } from '../../didcomm/mediator-sync.ts'
import { errorMessage } from '../../../protocol/error-message.ts'
import { requestAliasChange } from '../ui/approve-dialog.tsx'
import { readBisetConfig } from '../ui/config.ts'
import { setOwnDid } from '../ui/did-display.ts'
import { configureAccountPage, configureComposePage, updateVaultCardStatus, type VaultCardStatus } from '../ui/pages/index.ts'
import { configureCompose } from '../ui/reply-box.tsx'
import { showSysMsg } from '../ui/shell.ts'
import { openAccountVault } from './account-vault.ts'
import { timed } from './boot-timing.ts'
import { connectDidComm, type DidCommConnection, type OwnDevices } from './didcomm-connect.ts'
import { installInboxHandlers } from './inbox-handlers.ts'
import { startMarkdownVault } from './markdown-vault.ts'
import { messageArchive, type MessageArchive } from './message-archive.ts'
import { createOutgoing } from './outgoing.ts'
import { createOwnIdentity, type OwnIdentity } from './own-identity.ts'
import { sessionSeeds } from './seeds.ts'

export interface SessionHost {
  /** Boots the client again: after a Wallet approval changed the session, or when the Wallet turned the stored one down. */
  reboot(session?: DidMdActiveSession): Promise<void>
  /** False once a later boot took over: work still running from this one must not touch what that one set up. */
  current(): boolean
  /** Keeps a mediator watch or timer, to be stopped by the next boot. */
  keep(handle: MediatorPollHandle): void
  /** Disconnects and purges what this browser kept. */
  disconnect(): Promise<void>
}

type DidCommCard = { xKid: string; mediatorUrl: string; connecting?: boolean; error?: string }

/** The first configured mediator, kept visible after an intentional logout: its Log in creates and registers a fresh device. */
function configuredMediatorCard(): { mediatorUrl: string; loggedOut: true } | undefined {
  const configured = readBisetConfig().mediatorUrls.find(url => { try { return Boolean(new URL(url).host) } catch { return false } })
  return configured ? { mediatorUrl: new URL(configured).toString(), loggedOut: true } : undefined
}

/** The configured onion paired with a mediator (same index as `mediatorUrls`): it pre-fills the "Enable Tor" prompt (a card
 * already at an onion address offers that one); nothing publishes it until the user confirms. */
function configuredOnionFor(mediatorUrl: string): string | undefined {
  const { mediatorUrls, mediatorOnionUrls } = readBisetConfig()
  return mediatorOnionUrls[mediatorUrls.findIndex(url => sameMediatorUrl(url, mediatorUrl))]
    ?? mediatorOnionUrls.find(url => sameMediatorUrl(url, mediatorUrl))
}

/**
 * Opens the session `callbackSession` names, or the one this browser stored. A stored session is this browser's own, checked
 * when it was saved: what it names is on screen at once, and the Wallet is asked to refresh it in the background. False when
 * there is no session at all.
 */
export async function startWalletSession(host: SessionHost, callbackSession?: DidMdActiveSession): Promise<boolean> {
  let session = callbackSession
  let refreshing: Promise<DidMdActiveSession | undefined> | undefined
  if (!session) {
    session = await peekDidMdWalletSession()
    if (session) {
      refreshing = timed('restoreDidMdWalletSession', restoreDidMdWalletSession())
      refreshing.catch(() => {}) // the outcome is read at the end; this only keeps an early failure from going unhandled
    }
  }
  if (!session) return false

  // An approved edit changes the session (new DIDComm key, rotation key): the page is rebuilt from it. Without an in-page
  // approver the call navigates to the Wallet and never returns here.
  const editDocument = async (change: DidMdDocumentChange): Promise<void> => host.reboot(await beginDidMdDocumentEdit(change, readBisetConfig()))

  // The account page as the state stands: published once what is local is ready, and again as each thing the network
  // confirms (the mediator, the key notice) changes it.
  let active: DidMdActiveSession = session
  let vaultCard: VaultCardStatus | undefined
  let didComm: DidCommCard | undefined
  let connection: DidCommConnection | undefined
  let identity: OwnIdentity | undefined
  let archive: MessageArchive | undefined
  const setVaultCard = (status: VaultCardStatus) => { vaultCard = status; updateVaultCardStatus(status) }
  const publishAccount = (): void => {
    const mediatorCard = didComm ?? configuredMediatorCard()
    const onionUrl = mediatorCard && configuredOnionFor(mediatorCard.mediatorUrl)
    configureAccountPage({
      did: active.did,
      ...(archive ? { onExportMessages: archive.exportMessages, onImportMessages: archive.importMessages } : {}),
      wallet: {
        handle: active.handle,
        deviceJkt: active.deviceJkt,
        capabilityExpiresAt: active.capabilityExpiresAt,
        deviceKid: active.deviceKid,
        ...(mediatorCard ? { didComm: { ...mediatorCard, ...(onionUrl ? { onionUrl } : {}) } } : {}),
        // Publishes the DIDComm mediator device: the one enrollment step that needs a DID document edit (other people's
        // DIDComm senders have to be able to find the route publicly).
        onEnableMessaging: () => editDocument({ kind: 'mediator', mediatorUrls: readBisetConfig().mediatorUrls }),
        // The same, pointed at an explicit mediator (the Mediator card's "Edit server").
        onEditMediator: mediatorUrl => editDocument({ kind: 'mediator', mediatorUrls: [mediatorUrl] }),
        // Tor is the same edit as a new server, with the onion address as its default: the DID document then names that one mediator.
        onEnableTor: onionUrl => editDocument({ kind: 'mediator', mediatorUrls: [onionUrl] }),
        onLogOutMediator: () => editDocument({ kind: 'leaveMediator' }),
        onChangeAlias: async () => {
          // dito moves the DID to the new address in its frame. The tab then goes to dito's save page, as the sign-up does: the
          // password manager offers to update the saved account there, and its last page signs this device in under the new DID
          // (the request prepared here) and returns.
          const moved = await requestAliasChange()
          // The log is at the new address now (the old one is gone): the session follows before anything else can fail.
          await didMdSessionMovedTo(moved.host)
          const login = await prepareDidMdMovedDidLoginRequest(moved.did, moved.host, readBisetConfig())
          const origin = ditoEmbedOrigin()
          if (!origin) throw new Error('Changing the alias needs the embedded wallet.')
          location.assign(`${origin}/authorize${login}`)
        },
        onDisconnect: () => host.disconnect(),
      },
      vault: vaultCard,
      ...(identity?.pgpCard ? { pgp: identity.pgpCard } : {}),
      ...(identity ? { profile: identity.profileCard } : {}),
      onRemoveOtherDevices: () => editDocument({ kind: 'rotation', removeOtherDevices: true }),
      ...(connection?.rotationKeyState ? { rotationKey: { state: connection.rotationKeyState, onRenew: () => editDocument({ kind: 'rotation' }) } } : {}),
      showMessage: showSysMsg,
    })
  }

  let startConnect: (() => Promise<void>) | undefined
  try {
    const device = await timed('openDidMdWalletVaultDevice', openDidMdWalletVaultDevice())
    setOwnDid(device.did)
    const vault = await openAccountVault(device)
    archive = messageArchive(vault)
    const seeds = sessionSeeds(vault)
    identity = createOwnIdentity({ vault, handle: device.handle, seeds, joinInvite: () => connection?.secureJoin.joinInvite })
    const outgoing = createOutgoing({ vault, did: device.did, outbox: () => connection?.outbox })
    await startMarkdownVault(vault, input => outgoing.send(input))
    installInboxHandlers(vault, identity.mail)
    // Restore the existing local inbox before rendering, so a page reload never looks like it discarded the account's history.
    await timed('refreshInbox(restore)', vault.refresh().catch(error => console.warn('[did.md Wallet inbox restore]', error)))

    // This identity's devices, as its DID document lists them now; this device's DIDComm key first.
    let ownKid: string | undefined
    let deviceKids: string[] = []
    const devices: OwnDevices = {
      async refresh() { deviceKids = await timed('resolveOwnDeviceKids', resolveOwnDeviceKids(device.did)) },
      includes: kid => deviceKids.includes(kid),
    }
    const deviceList = () => deviceKids
      .map(deviceId => ({ deviceId, current: deviceId === ownKid }))
      .sort((left, right) => Number(right.current) - Number(left.current) || left.deviceId.localeCompare(right.deviceId))
    vaultCard = { state: 'checking', coordinatorUrl: 'didcomm', vaultId: device.did as never, detail: 'Connecting encrypted Vault sync', devices: deviceList() }

    // DIDComm is the identity's own DID once the mediator is (or is being) connected; a failed one is not.
    const publishCompose = (): void => {
      const selfDid = didComm && !didComm.error ? device.did : undefined
      configureCompose({
        selfAddress: vault.identityId,
        selfDid,
        sendReply: outgoing.send,
        sendNote: outgoing.writeNote,
        onError: message => { showSysMsg(message); console.warn('[did.md Wallet send]', message) },
        didcommGroup: {
          membersOf: async thid => (await outgoing.groupConversation(thid))?.participants ?? [],
          groupName: async thid => (await outgoing.groupConversation(thid))?.name,
        },
      })
      configureComposePage({
        selfAddress: vault.identityId,
        selfDid,
        sendMessage: outgoing.send,
        onError: message => { showSysMsg(message); console.warn('[did.md Wallet compose]', message) },
      })
    }

    // A corrupt or independently revoked DIDComm envelope must not make the otherwise healthy Vault look unavailable: it has
    // its own sealed device material, and its registration is best-effort.
    let didCommDevice: DidMdBisetDidCommDevice | undefined
    try { didCommDevice = await timed('openDidMdWalletBisetDidCommDevice', openDidMdWalletBisetDidCommDevice()) }
    catch (error) { console.warn('[did.md Wallet DIDComm]', error) }
    if (didCommDevice) {
      const dc = didCommDevice
      // What is stored is on screen at once, as "connecting"; the connection confirms it with the mediator.
      didComm = { xKid: dc.xKid, mediatorUrl: dc.mediatorUrl, connecting: true }
      ownKid = dc.xKid
      startConnect = async () => {
        try {
          const { mediatorUrls, mediatorOnionUrls } = readBisetConfig()
          const connected = await connectDidComm({
            vault, did: device.did, device: dc, identity: identity!, seeds, devices,
            configuredMediators: [...mediatorUrls, ...mediatorOnionUrls],
            onVaultConnected: () => setVaultCard({ state: 'connected', coordinatorUrl: 'didcomm', vaultId: device.did as never, devices: deviceList() }),
            // A sibling login may have added its device key to the DID document just before sending a sync message.
            onSiblingSync: async () => {
              if (!vaultCard) return
              await timed('refreshVaultDevices', devices.refresh())
              setVaultCard({ ...vaultCard, devices: deviceList() })
            },
            stale: () => !host.current(),
            keep: host.keep,
          })
          if (!connected) return
          connection = connected
          didComm = { xKid: dc.xKid, mediatorUrl: dc.mediatorUrl }
        } catch (error) {
          didComm = { xKid: dc.xKid, mediatorUrl: dc.mediatorUrl, error: errorMessage(error) }
          console.warn('[did.md Wallet DIDComm]', error)
        }
        publishCompose()
        publishAccount()
      }
    }
    publishCompose()
  } catch (error) {
    vaultCard = { state: 'error', coordinatorUrl: 'didcomm', detail: errorMessage(error) }
    console.warn('[did.md Wallet Vault]', error)
  }
  publishAccount()
  void startConnect?.()

  // The Wallet's answer to the background refresh. A newer capability replaces what the page shows; a session the Wallet turned
  // down was cleared, so boot again for what follows (reconnect or sign-up); a failure that left the session alone (offline)
  // leaves the page be.
  refreshing?.then(refreshed => {
    if (!host.current() || !refreshed) return
    active = refreshed
    publishAccount()
  }, async error => {
    if (!host.current()) return
    console.warn('[did.md Wallet restore]', errorMessage(error))
    if (await peekDidMdWalletSession()) showSysMsg(`Could not refresh the Wallet session yet: ${errorMessage(error)}`)
    else void host.reboot()
  })
  return true
}
