// The address bar: every inbox, and the pages, have a path, and a path opens what it names.
//
//   /alice@gmail.com     the inbox with that address (the DID's SCID where there is no address)
//   /new                 the page for a new message
//   /me@did.md           the account page
//   /somebody@else.org   an address nobody has talked to yet: the new-message page, with it in the To field
//
// `@` and `:` stay as they are in the path: an address reads as itself in the URL bar.
import { vhScidOf } from '../../../protocol/vh/identifier.ts'
import { labelForDid } from './did-display.ts'
import { getAccountConfig } from './account/state.ts'
import { composeConfigured, composeDraft, resetComposeDraft } from './pages/compose-page.tsx'
import { showAccountPage, showComposePage } from './pages/index.ts'
import { composeConfig } from './reply-box.tsx'
import { setPage, uiPage } from './state.ts'
import { setInboxOpener } from './helper.ts'
import { mail, patchShell, shell } from './stores.ts'
import { NEW_INBOX_KEY, SELF_INBOX_KEY, selfAddressesOf, threadsOf, type InboxRow } from './thread-model.ts'

const NEW_PATH = 'new'
const SELF_PATH = 'me@did.md'

/** Between the addresses of a message to several people: a comma. It is legal in a path as it is, reads as a list, and is in no address
 * or DID (a mail address may hold one only inside quotes). */
const RECIPIENT_SEPARATOR = ','

const segment = (text: string): string => encodeURIComponent(text).replace(/%40/g, '@').replace(/%3A/gi, ':').replace(/%2C/gi, RECIPIENT_SEPARATOR).replace(/%2B/gi, '+')
const unsegment = (text: string): string => { try { return decodeURIComponent(text) } catch { return text } }

/** The path (without the slash) of an inbox: its address, else the SCID of its DID; the special inboxes have reserved words. */
function pathOfInbox(row: InboxRow): string {
  if (row.key === NEW_INBOX_KEY) return NEW_PATH
  if (row.key === SELF_INBOX_KEY) return SELF_PATH
  const counterpart = row.key.split(', ')[0] ?? row.key
  if (!counterpart.startsWith('did:')) return counterpart
  const address = labelForDid(counterpart)
  return address.includes('@') ? address : vhScidOf(counterpart) ?? counterpart
}

/** The inbox a path names, among the existing ones. */
function inboxOfPath(rows: readonly InboxRow[], path: string): InboxRow | undefined {
  const wanted = path.toLowerCase()
  return rows.find(row => pathOfInbox(row).toLowerCase() === wanted || row.key.toLowerCase() === wanted)
}

/** What the address bar's path says to open, if it says anything (a path that names no address is no route). */
function routeOf(pathname: string): string | undefined {
  const parts = pathname.split('/').filter(Boolean)
  if (parts.length !== 1) return undefined
  const text = unsegment(parts[0]!)
  const looksLikeRoute = text === NEW_PATH || text.includes('@') || text.startsWith('did:') || text.startsWith('didcomm-group:') || /^[A-Za-z0-9_-]{20,}$/.test(text)
  return looksLikeRoute ? text : undefined
}

const currentThreads = () => {
  const config = composeConfig.get()
  return threadsOf(mail.get().messages, shell.get().focusedThreadKey, selfAddressesOf(config?.selfAddress, config?.selfDid))
}

/** The path the screen is on now. */
function pathOfScreen(): string {
  const page = uiPage.get()
  if (page === 'account') return SELF_PATH
  // The addresses settled so far (not the one still being typed), in one path.
  if (page === 'compose') return composeDraft.get().to.split(/[\s,]+/).slice(0, -1).filter(Boolean).join(RECIPIENT_SEPARATOR) || NEW_PATH
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
  if (text === NEW_PATH) { resetComposeDraft(); showComposePage(); return }
  // Several addresses: a new message to all of them.
  if (text.includes(RECIPIENT_SEPARATOR)) {
    composeDraft.set({ to: `${text.split(RECIPIENT_SEPARATOR).filter(Boolean).join(' ')} `, subject: '' })
    showComposePage()
    return
  }
  if (text.toLowerCase() === SELF_PATH) { showAccountPage(); return }
  const row = inboxOfPath(currentThreads().rows, text)
  if (row) {
    patchShell({ focusedThreadKey: row.groups[0]!.key, lpFocusedKey: `inbox:${row.key}`, showLeft: false })
    setPage('thread')
    return
  }
  // Nobody has written to that address yet: a new message to it.
  // Settled (the space), so that it shows as a chip and the cursor is ready for the next address.
  composeDraft.set({ to: `${text} `, subject: '' })
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
    const pageReady = accountless || (text === NEW_PATH ? composeConfigured() : text.toLowerCase() === SELF_PATH ? getAccountConfig() !== undefined : composeConfigured())
    // An existing inbox is known once the messages have stopped arriving; an unknown address is only believed after that, or at the end of the wait.
    const count = mail.get().messages.length
    steady = count === lastCount && count > 0 ? steady + 1 : 0
    lastCount = count
    const settled = accountless || text === NEW_PATH || text.toLowerCase() === SELF_PATH || steady >= 3
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
