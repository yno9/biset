// The address bar: every inbox, and the pages, have a path, and a path opens what it names.
//
//   /alice@gmail.com     the inbox with that address (always in full: a name alone, /alice, is no address and no route)
//   /did:vh:SCID         the inbox with a DID that has no address
//   /alice@gmail.com,bob a message to several (the inboxes of a group are by their `didcomm-group:` id)
//   /{my_address}        the account page (the address of this account itself)
//   /somebody            an address nobody has talked to yet: the new-message page, with it in the To field
//   /                    nothing named: the screen the app opens on, and the new-message page while no one is addressed
//
// What has a mark (a leading underscore: no account name begins with one) is the app's; what has none is a person. `@` and `:` stay as
// they are in the path: an address reads as itself in the URL bar.
import { vhScidOf } from '../../../protocol/vh/identifier.ts'
import { addressOfHost, labelForDid } from './did-display.ts'
import { accountConfig, getAccountConfig } from './account/state.ts'
import { composeConfigured, composeDraft } from './pages/compose-page.tsx'
import { showAccountPage, showComposePage } from './pages/index.ts'
import { composeConfig } from './reply-box.tsx'
import { setPage, uiPage } from './state.ts'
import { setInboxOpener } from './helper.ts'
import { mail, patchShell, shell } from './stores.ts'
import { NEW_INBOX_KEY, SELF_INBOX_KEY, selfAddressesOf, threadsOf, type InboxRow } from './thread-model.ts'

/** An address is written in full in the path (`alice@002053.xyz`): a bare name is no address. */
const addressOfToken = (token: string): string => token
const tokenOfAddress = (address: string): string => address

/** Between the addresses of a message to several people: a comma. It is legal in a path as it is, reads as a list, and is in no address
 * or DID (a mail address may hold one only inside quotes). */
const RECIPIENT_SEPARATOR = ','

const segment = (text: string): string => encodeURIComponent(text).replace(/%40/g, '@').replace(/%3A/gi, ':').replace(/%2C/gi, RECIPIENT_SEPARATOR).replace(/%2B/gi, '+')
const unsegment = (text: string): string => { try { return decodeURIComponent(text) } catch { return text } }

/** The path (without the slash) of an inbox: its address, else the SCID of its DID; the special inboxes have reserved words. */
function pathOfInbox(row: InboxRow): string {
  if (row.key === NEW_INBOX_KEY) return ''
  if (row.key === SELF_INBOX_KEY) return ownToken() ?? ''
  const counterpart = row.key.split(', ')[0] ?? row.key
  if (!counterpart.startsWith('did:')) return counterpart
  const address = labelForDid(counterpart)
  if (address.includes('@')) return address
  const scid = vhScidOf(counterpart)
  return scid ? `did:vh:${scid}` : counterpart
}

/** This account's own address as a path token, or undefined when there is no account address (then its DID: the address is preferred whenever there is one, and the path follows an alias change). */
const ownToken = (): string | undefined => {
  const handle = accountConfig.get()?.wallet?.handle
  return handle ? addressOfHost(handle) : composeConfig.get()?.selfAddress
}
/** The account's address, or (older links, an account with no alias) its DID: both open the account page. */
const isOwnToken = (text: string): boolean => {
  const wanted = text.toLowerCase()
  return [ownToken(), composeConfig.get()?.selfAddress].some(own => !!own && own.toLowerCase() === wanted)
}

/** The inbox a path names, among the existing ones. */
function inboxOfPath(rows: readonly InboxRow[], token: string): InboxRow | undefined {
  const wanted = tokenOfAddress(addressOfToken(token)).toLowerCase()
  return rows.find(row => pathOfInbox(row).toLowerCase() === wanted || row.key.toLowerCase() === token.toLowerCase())
}

/** What the address bar's path says to open, if it says anything (a path that names no address is no route). */
function routeOf(pathname: string): string | undefined {
  const parts = pathname.split('/').filter(Boolean)
  if (parts.length !== 1) return undefined
  const text = unsegment(parts[0]!)
  const isPerson = (token: string): boolean => token.includes('@') || token.startsWith('did:') || token.startsWith('didcomm-group:')
  const tokens = text.split(RECIPIENT_SEPARATOR).filter(Boolean)
  return tokens.length > 0 && tokens.every(isPerson) ? text : undefined
}

const currentThreads = () => {
  const config = composeConfig.get()
  return threadsOf(mail.get().messages, shell.get().focusedThreadKey, selfAddressesOf(config?.selfAddress, config?.selfDid))
}

/** The path the screen is on now. */
function pathOfScreen(): string {
  const page = uiPage.get()
  // With no account the account page is the sign-up: it is the front door, at the root.
  if (page === 'account') return getAccountConfig()?.did === null ? '' : ownToken() ?? ''
  // The addresses settled so far (not the one still being typed), in one path.
  if (page === 'compose') return composeDraft.get().to.split(/[\s,]+/).slice(0, -1).filter(Boolean).map(tokenOfAddress).join(RECIPIENT_SEPARATOR)
  const { focused, rows } = currentThreads()
  const row = focused && rows.find(r => r.groups.some(g => g.key === focused.key))
  return row ? pathOfInbox(row) : ''
}

let writing = false
function writePath(): void {
  if (!writing) return
  const wanted = `/${segment(pathOfScreen())}`
  document.documentElement.dataset.path = wanted
  // Not on a file (mock.html, index.html opened as one, file://): there the path is the file's own.
  if (location.protocol === 'file:' || location.pathname.endsWith('.html')) return
  try { if (location.pathname !== wanted) history.replaceState(null, '', wanted) } catch { /* no history to write */ }
}

function open(text: string): void {
  if (isOwnToken(text)) { showAccountPage(); return }
  // Several people: a new message to all of them.
  if (text.includes(RECIPIENT_SEPARATOR)) {
    composeDraft.set({ to: `${text.split(RECIPIENT_SEPARATOR).filter(Boolean).map(addressOfToken).join(' ')} `, subject: '' })
    showComposePage()
    return
  }
  const row = inboxOfPath(currentThreads().rows, text)
  if (row) {
    patchShell({ focusedThreadKey: row.groups[0]!.key, lpFocusedKey: `inbox:${row.key}`, showLeft: false })
    setPage('thread')
    return
  }
  // Nobody has written to that address yet: a new message to it, settled (the space) so that it shows as a chip and the cursor is ready
  // for the next address.
  composeDraft.set({ to: `${addressOfToken(text)} `, subject: '' })
  showComposePage()
}

/** Opens what the address bar names once the page it needs is ready (the messages have arrived, the pages are set up), then keeps
 * the address bar following the screen. `pathname` is the address bar's, unless a caller stands in for it. */
let started = false
export function startRouting(pathname: string = location.pathname): void {
  if (started) return
  started = true
  const text = routeOf(pathname)
  const follow = (): void => {
    writing = true
    uiPage.subscribe(writePath)
    accountConfig.subscribe(writePath)
    shell.subscribe(writePath)
    mail.subscribe(writePath)
    composeDraft.subscribe(writePath)
    writePath()
  }
  if (!text) { follow(); return }
  const startedAt = Date.now()
  let lastCount = -1
  let steady = 0
  const timer = window.setInterval(() => {
    const waited = Date.now() - startedAt
    // With no account (its page is the sign-up) there is nothing to wait for: no messages will come, and the compose page is open to all.
    const accountless = getAccountConfig()?.did === null
    const pageReady = accountless || (isOwnToken(text) ? getAccountConfig() !== undefined : composeConfigured())
    // An existing inbox is known once the messages have stopped arriving; an unknown address is only believed after that, or at the end of the wait.
    const count = mail.get().messages.length
    steady = count === lastCount && count > 0 ? steady + 1 : 0
    lastCount = count
    const settled = accountless || isOwnToken(text) || steady >= 3
    if ((pageReady && settled) || waited > 6000) {
      window.clearInterval(timer)
      open(text)
      follow()
    }
  }, 150)
}

// The helper's conversation is opened once it exists: a message just sent shows up in the messages a moment later.
setInboxOpener(address => {
  let tries = 0
  const timer = window.setInterval(() => {
    tries++
    if (inboxOfPath(currentThreads().rows, address) || tries >= 12) {
      window.clearInterval(timer)
      open(address)
    }
  }, 250)
})
