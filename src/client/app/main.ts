// The app's entry point. Its first import stops the app where the browser has no IndexedDB (storage-guard.ts).
import './ui/storage-guard.ts'
import { mountNetworkActivity } from 'lft/net-activity-ui'
import { watchNetwork } from 'lft/net-activity'
import {
  allowHandleDomain, beginDidMdWalletLogin, completeDidMdWalletCallback, DID_MD_JUST_CONNECTED_KEY, didMdWalletReconnectState,
  disconnectDidMdWallet, type DidMdActiveSession,
} from '../identity/wallet/did-md-oauth.ts'
import { ditoEmbedOrigin } from '../identity/wallet/dito-embed.ts'
import { StoredDidLinks } from '../identity/did-links.ts'
import { StoredVersionMemory } from '../identity/version-memory.ts'
import { StoredVhPlaces } from '../identity/vh-places.ts'
import type { MediatorPollHandle } from '../didcomm/mediator-sync.ts'
import { configureDidResolution } from '../../protocol/did-resolve.ts'
import { errorMessage } from '../../protocol/error-message.ts'
import { clearPlainStorage, deleteLocalDatabases } from './local-data.ts'
import { mountApp } from './ui/app.tsx'
import { installDitoApprover } from './ui/approve-dialog.tsx'
import { readBisetConfig } from './ui/config.ts'
import { networkNotes, networkRules } from './ui/network-declaration.ts'
import { sendComposedWhenReady, sendProblem, takePendingSend } from './ui/pages/compose-page.tsx'
import { configureAccountPage, setOnWalletConnected, showAccountPage, showComposePage } from './ui/pages/index.ts'
import { setReplyDraft } from './ui/reply-box.tsx'
import { namesRoute, startRouting } from './ui/route.ts'
import { showApp, showSysMsg } from './ui/shell.ts'
import { preloadSignup } from './ui/signup-preload.ts'
import { savedPage } from './ui/state.ts'
import { startUpdates } from './ui/update.ts'
import { sinceBoot, timed } from './session/boot-timing.ts'
import { startWalletSession } from './session/wallet-session.ts'

// The bar across the top and the host the page is talking to, lit while it is on the network (lft: local first toolkit, ../lft).
mountNetworkActivity({ label: 'top-right', mark: 'dot', rules: networkRules(), notes: networkNotes })
// What the wallet's frame does on the network is reported here, and joins the log.
{ const wallet = ditoEmbedOrigin(); if (wallet) watchNetwork().receiveFrom([wallet]) }
startUpdates()
allowHandleDomain(readBisetConfig().identityDomain)
// Where a did:vh's log is looked for, and the memory that refuses an older or forked copy of any log.
configureDidResolution({ watchers: readBisetConfig().vhWatchers, memory: new StoredVersionMemory(), links: new StoredDidLinks(), places: new StoredVhPlaces() })

// The sign-up lands on the account page, showing the identity just made, not the (still empty) inbox. Registered here rather
// than imported by the new-user page: this file is the bundle's entry point, and an import edge back into it breaks bundling.
setOnWalletConnected(async session => {
  await bootClient(session)
  showAccountPage()
})

/** Disconnects, purges what this browser kept (databases and plain storage), and starts the app over with a page load, so that
 * nothing of the identity is left in memory either (the messages, drafts and the like are state of this page). Destructive
 * cleanup happens only here, on the explicit Disconnect: a missing session is no proof that local data is orphaned. */
async function disconnectWalletAndLocalData(): Promise<void> {
  await disconnectDidMdWallet()
  await deleteLocalDatabases()
  clearPlainStorage()
  location.replace('/')
  // The page is going away: whatever called this has nothing more to do.
  await new Promise<void>(() => {})
}

/** Sends the message that was waiting for the account (compose-page.tsx's savePendingSend) once the account's DIDComm is
 * connected. A failure leaves it in the new message's box for the writer to send by hand. */
async function sendWhenReady(body: string): Promise<void> {
  sendProblem.set(undefined)
  try {
    await sendComposedWhenReady(body)
    setReplyDraft('new', '')
  } catch (error) {
    // Said where the message is (under the island, staying), and in the console in full: a toast was gone before it could be read.
    console.error('[send after sign-up]', error)
    sendProblem.set(errorMessage(error))
    showComposePage()
  }
}

// Bumped by every boot: work still running from an earlier one must not touch what a later one set up, and its mediator
// watches are stopped.
let bootGeneration = 0
let pollHandles: MediatorPollHandle[] = []

async function bootClient(callbackSession?: DidMdActiveSession): Promise<void> {
  const generation = ++bootGeneration
  for (const handle of pollHandles) handle.stop()
  pollHandles = []

  // An OAuth callback is consumed before the stored capability is refreshed: a DID-document edit makes the old capability's
  // document snapshot stale, and refreshing it first cleared an otherwise valid session. Completion saves the replacement
  // session atomically, and it is not refreshed again right away (a transient failure there made a successful rotation look
  // like a logout). A failure here (an invalid or expired code, the network) is logged: the new-user page shows it.
  let completed = callbackSession
  if (!completed) {
    try { completed = await completeDidMdWalletCallback() } catch (error) { console.warn('[did.md Wallet callback]', errorMessage(error)) }
  }

  const host = {
    reboot: bootClient,
    current: () => generation === bootGeneration,
    keep: (handle: MediatorPollHandle) => { pollHandles.push(handle) },
    disconnect: disconnectWalletAndLocalData,
  }
  if (await timed('startWalletSession (total)', startWalletSession(host, completed))) {
    showApp()
    // What was being written when the account had to be made is back in its box, and goes out as soon as the account can
    // send. That is the page to land on: a message that fails to go has to be seen where it is.
    const pendingBody = takePendingSend()
    startRouting()
    console.info(`[boot] app shown at ${sinceBoot()}ms`)
    const justConnected = completed || sessionStorage.getItem(DID_MD_JUST_CONNECTED_KEY) === '1'
    sessionStorage.removeItem(DID_MD_JUST_CONNECTED_KEY)
    if (pendingBody !== undefined) {
      setReplyDraft('new', pendingBody)
      showComposePage()
      void sendWhenReady(pendingBody)
    } else if (justConnected) {
      showAccountPage()
    } else if (savedPage() === 'account' || location.pathname === '/') {
      // A plain reload stays where it was; the root names nothing to open: it is the account's own page.
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
          return beginDidMdWalletLogin(config.mediatorUrls, config)
        },
        onDisconnect: disconnectWalletAndLocalData,
      },
      showMessage: showSysMsg,
    })
    showApp()
    showAccountPage()
    showSysMsg(`The capability for ${reconnect.handle} expired. Reconnect did.md Wallet; local Vault and message databases were preserved.`)
    return
  }

  configureAccountPage({ did: null })
  // With no account the address bar can still name a message to write (/alice@gmail.com): that page is opened before the app
  // is shown, so the sign-up is not seen on the way to it. Otherwise the sign-up is the page.
  const named = namesRoute()
  if (named) startRouting()
  showApp()
  if (!named) showAccountPage()
  // The wallet's frames are loaded now, out of sight, so that whatever the person turns to (a new message, the log-in) has them ready.
  preloadSignup()
  startRouting()
}

mountApp()
installDitoApprover()
void bootClient()
