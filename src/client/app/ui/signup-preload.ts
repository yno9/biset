// The sign-up kept ready: dito's create form is loaded in a frame out of sight as soon as it may be wanted (a new message is being
// written with no account), so that pressing Send can have the account made at once (dito's `wallet.create`) instead of showing a
// form and waiting for it to load. What the person still does is the one thing it cannot do for them: save the Passphrase, on dito's
// own page, which the tab goes to and comes back from.
import { createStore } from '../react/store.ts'
import { ditoEmbedOrigin, mountDito, type DitoEmbed } from '../../identity/wallet/dito-embed.ts'
import { mountSignup } from './pages/signup-frame.ts'
import { addressOfHost, shortDid } from './did-display.ts'

let ready: Promise<DitoEmbed> | undefined

/** The address of the identity this browser's wallet already holds (`485c@did.md`), once the frame has said so: sending then asks to log in
 * as it, and does not make another. */
export const heldIdentity = createStore<string | undefined>(undefined)
/** The host the held identity is published at (`485c.did.md`), once the wallet has said: the handle a sign-in as it is asked for. */
/** Whether the wallet has said if it holds an identity (or could not): until then the page does not guess between a create and a log-in. */
export const walletKnown = createStore(false)
export const heldHost = createStore<string | undefined>(undefined)
/** How the wallet's identity is told to the person: its address (`485c@did.md`, from the host the wallet names), else the DID cut short. */
const addressOfIdentity = ({ did, host }: { did: string; host?: string }): string => host ? addressOfHost(host) : shortDid(did)

// The Passphrase field of the wallet, kept loaded too: its frame is on the page from the start (off to the side) and is laid over the
// log-in form's box when that is shown (moving a frame in the page would load it again).
let passphrase: { frame: HTMLIFrameElement; embed: Promise<DitoEmbed> } | undefined
/** Whether the Passphrase frame has laid its field out (it can be shown without a blank moment). */
export const passphraseReady = createStore(false)
let passphraseHandlers: { submit?: () => void; error?: (message: string) => void } = {}
/** Who answers the Passphrase frame's Enter and errors (the log-in form that is on screen). */
export function setPassphraseHandlers(handlers: typeof passphraseHandlers): void { passphraseHandlers = handlers }
const PASSPHRASE_AWAY = 'position:fixed;left:-10000px;top:0;width:440px;height:56px;border:0;opacity:0;pointer-events:none'

function preloadPassphrase(origin: string): void {
  if (passphrase) return
  const frame = document.createElement('iframe')
  frame.title = 'Passphrase'
  frame.tabIndex = -1
  frame.allow = 'clipboard-write; publickey-credentials-get'
  frame.style.cssText = PASSPHRASE_AWAY
  document.body.append(frame)
  const embed = mountDito(frame, origin, 'passphrase', { resized: () => passphraseReady.set(true), submit: () => passphraseHandlers.submit?.(), error: message => passphraseHandlers.error?.(message) })
  passphrase = { frame, embed }
  embed.catch(() => { passphrase = undefined; passphraseReady.set(false); frame.remove() })
}

/** The loaded Passphrase frame, if the wallet is here. */
export const passphraseEmbed = (): Promise<DitoEmbed> | undefined => passphrase?.embed

/** Lays the Passphrase frame over `box` (a placeholder in the page) for as long as the page is shown; returns what takes it away again. */
export function showPassphraseOver(box: HTMLElement): () => void {
  const target = passphrase
  if (!target) return () => {}
  let frameId = 0
  const follow = () => {
    const rect = box.getBoundingClientRect()
    target.frame.style.cssText = `position:fixed;left:${rect.left}px;top:${rect.top}px;width:${rect.width}px;height:${rect.height}px;border:0;z-index:1;color-scheme:light dark;background:transparent;opacity:${passphraseReady.get() ? 1 : 0}`
    frameId = requestAnimationFrame(follow)
  }
  follow()
  return () => { cancelAnimationFrame(frameId); target.frame.style.cssText = PASSPHRASE_AWAY }
}

/** Loads the sign-up out of sight (once). Without a same-site wallet (an embed cannot be made) there is nothing to load. */
export function preloadSignup(): void {
  const origin = ditoEmbedOrigin()
  if (ready || !origin) return
  preloadPassphrase(origin)
  const frame = document.createElement('iframe')
  frame.title = 'Account'
  frame.setAttribute('aria-hidden', 'true')
  frame.tabIndex = -1
  frame.allow = 'clipboard-write; publickey-credentials-create; publickey-credentials-get'
  // Out of sight but laid out (a frame with no box does not report, and its form reads sizes): off to the side, not display:none.
  frame.style.cssText = 'position:fixed;left:-10000px;top:0;width:440px;height:260px;border:0;opacity:0;pointer-events:none'
  document.body.append(frame)
  ready = mountSignup(frame, origin, error => { console.warn('[signup]', error) }, message => { console.warn('[signup frame]', message) }, did => heldIdentity.set(addressOfIdentity({ did })))
  ready.catch(() => { ready = undefined; frame.remove(); walletKnown.set(true) })
  // Whether this browser's wallet already holds an identity is asked, not waited for: the frame's own one-time note of it can come before
  // this page has connected.
  ready.then(embed => embed.describe()).then(described => { if (described.host) heldHost.set(described.host); if (described.did) heldIdentity.set(addressOfIdentity({ did: described.did, ...(described.host ? { host: described.host } : {}) })) }).catch(() => {}).finally(() => walletKnown.set(true))
}

/** Whether the sign-up can be made without being shown: a same-site wallet is there to ask. */
export const canSignUpInBackground = (): boolean => ditoEmbedOrigin() !== undefined

/** Has the wallet make the account (at `alias`, or the random one it offers). Resolves when it is made; the tab is then taken to the
 * wallet's save page by the frame's `savePage` handler. Rejects with the reason (a taken alias, an identity this browser already holds). */
export async function createAccountInBackground(alias?: string, host?: string): Promise<void> {
  preloadSignup()
  if (!ready) throw new Error('The wallet is not available here.')
  const embed = await ready
  await embed.create(alias, host)
}

/** Whether the wallet has `alias` free; without one, the random name its form offers (and whether that is free). */
export async function checkAlias(alias?: string, host?: string): Promise<{ alias: string; available: boolean }> {
  preloadSignup()
  if (!ready) throw new Error('The wallet is not available here.')
  return (await ready).checkAlias(alias, host)
}

/** A name of six digits (`048213`). */
export const randomAlias = (): string => String(crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000).padStart(6, '0')

/** The name the account will be made with while there is none: the sign-up page shows it in its field, a message written with no account makes the
 * account with it, and the tab's icon is its face (the person's avatar is not settled until the account is; this stands in for it). */
export const provisionalAlias = createStore(randomAlias())
