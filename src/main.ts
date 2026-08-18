import {
  sessions, addSession, setCurrentInbox, currentInbox, loadStoredAccounts, accountsForActiveIdentity,
} from './context.ts'
import { initSession, loadInboxSummaries, backfillContactNames } from './app.ts'
import type { InboxSummary } from './types.ts'
import { inboxToHash, parseInboxHash } from './utils.ts'
import { contactIdentityKey, representativeAddressForDid } from './did/contacts.ts'
import { setMlsAuthService } from './mls/group.ts'
import { didAuthenticationService } from './mls/authservice.ts'
import { showApp, startPolling, fetchMessages } from './ui/shell.ts'
import { loadLeftInboxes, showMenuPage, setupLeftPane, refreshAccountsList, menuTargetInbox, openComposeTo, syncNotifToggle, inMenuMode } from './ui/left-pane.ts'
import { primeAvatarCache } from './deltachat/avatar.ts'
import { advertiseAllOwnAvatars } from './ap/avatar.ts'
import { loadFromCache } from './store/cache.ts'
import { loadFromIDB as loadQuerystateFromIDB } from './jmap/querystate.ts'
import { listenForServiceWorkerMessages } from './push/client.ts'

// ── Hash routing helpers ───────────────────────────────────────────────────────
// Inbox hash build/parse lives in utils (inboxToHash / parseInboxHash) so the
// left pane's switchInbox and this router encode permalinks identically.

// The complete, fixed set of menu-page names (LP_COMMANDS in left-pane.ts).
// A conversation permalink is now also a single, shapeless segment (just the
// contact — see utils.ts's inboxToHash), so "no slash = menu page" no longer
// disambiguates anything; an explicit allowlist does instead.
const MENU_PAGE_NAMES = new Set(['account', 'config', 'compose', 'debug'])

function menuHashFromHash(hash: string): string | null {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash
  const name = raw.startsWith('/') ? raw.slice(1) : raw
  return MENU_PAGE_NAMES.has(name) ? '/' + name : null
}

// Resolves a permalink hash (just a contact — see utils.ts's inboxToHash)
// against currently-loaded inboxes, regardless of which of the user's own
// identities/mailboxes it lives under (a real but rare edge case — the same
// contact appearing under two different logged-in identities — just picks
// the first match). Matching goes through contactIdentityKey rather than
// plain string equality: InboxSummary.contact is whichever literal address
// most recently had traffic (see app.ts's loadInboxSummaries), which can
// drift to a DIFFERENT address than what's in an old hash even for the exact
// same DID-grouped conversation — comparing raw strings would wrongly call
// that "not found".
//
// If the contact segment is a DID with no locally-known Card yet (a fresh
// device, or a shared link opened cold), one extra live DHT resolve is
// attempted before giving up — the same self-healing property compose's
// DID input already has, applied to permalinks.
async function matchInboxForHash(hash: string, inboxes: InboxSummary[]): Promise<InboxSummary | null> {
  const parts = parseInboxHash(hash)
  if (!parts) return null
  const matches = (i: InboxSummary) =>
    parts.contact.startsWith('group:')
      ? i.contact === parts.contact
      : contactIdentityKey(i.contact) === contactIdentityKey(parts.contact)
  let found = inboxes.find(matches) ?? null
  if (!found && parts.contact.startsWith('did:') && !representativeAddressForDid(parts.contact)) {
    try { await (await import('./did/discovery.ts')).resolveDidDirect(parts.contact) } catch { /* best-effort */ }
    found = inboxes.find(matches) ?? null
  }
  return found
}

// ── Per-user landing (/<localpart>[/]) ──────────────────────────────────────────
// The apex serves the biset app at /<localpart> too (see jmapap content
// negotiation), so a browser hitting https://<host>/y lands here. Detect the
// localpart from the path (dots excluded → asset paths like /index.html don't
// match; the app root "/" doesn't match either).
function userPathLocalpart(): string | null {
  const m = location.pathname.match(/^\/([a-z0-9][a-z0-9_-]*)\/?$/)
  return m ? m[1]! : null
}

// A typed/linked address or DID → the value the To field should actually
// carry. did: already means DIDComm, used as-is. An address gets one shot at
// resolving to its DID anchor first (discoverDidForAddress) so a link to
// someone with a published DID opens compose already on DIDComm rather than
// defaulting to Mail (resolveRecipientProtocols's own default for a bare
// email-shaped To) — falls back to the address itself when no DID anchor
// exists yet.
async function resolveComposeTarget(addrOrDid: string): Promise<string> {
  if (addrOrDid.startsWith('did:')) return addrOrDid
  try {
    const { discoverDidForAddress } = await import('./did/discovery.ts')
    return (await discoverDidForAddress(addrOrDid)) || addrOrDid
  } catch { return addrOrDid }
}

// One visitor's journey, whether they already have an account here or not
// (2026-08-16 — collapsed the old two-step "Chat with X?" landing → #new →
// compose handoff into one screen): compose opens straight away with the
// target pre-filled as To (via DIDComm whenever the target has a DID
// anchor), and account creation itself now happens INSIDE compose (a
// "create account" affordance in the From field — left-pane.ts's onShowNew)
// rather than as a separate page first. Existing sessions just additionally
// get polling/inbox loading; a first-time visitor gets the exact same
// compose page, just without anything to poll yet.
async function handleUserLanding(localpart: string, accounts: ReturnType<typeof loadStoredAccounts>) {
  const cfg = (window as any).__BISET_CONFIG__
  const host: string = cfg?.hostname || location.hostname
  const target = `${localpart}@${host}`

  if (accounts.length) {
    const results = await Promise.all(accounts.map(initSession))
    const valid = results.filter(Boolean) as NonNullable<Awaited<ReturnType<typeof initSession>>>[]
    valid.forEach(s => addSession(s))
  }
  showApp()
  await setupLeftPane()
  if (sessions.length) {
    advertiseAllOwnAvatars()
    startPolling()
    loadLeftInboxes()
  }
  openComposeTo(await resolveComposeTarget(target))
}

// ── Session bootstrap ────────────────────────────────────────────────────────
// DID⊥relay (PLAN.md): an identity's DIDComm channel is orthogonal to whether
// it has any relay (JMAP) accounts at all — every identity may have one, on
// top of however many relay accounts it also has. This is the ONE place
// sessions[] gets populated, for either shape, so nothing downstream can ever
// implement it for one and forget the other again. Found live: this pairing
// used to be reimplemented separately at every boot entry point (one per
// hash-route × relay/standalone combination) — the "menu-hash × relay-backed"
// copy never got the DIDComm half at all, so a relay-backed identity's iOS
// PWA that always relaunches into #account (its start_url, captured at
// "Add to Home Screen" time) silently never polled for DIDComm mail, ever,
// with zero trace anywhere — no network request, no console line, nothing.
//
// Returns `configured`: whether SOME identity exists on this device at all (a
// relay account, or a DID ever created with zero relays) — distinct from
// whether sessions[] ends up non-empty, which also depends on whether that
// identity's relays/channel are reachable right now. Callers use this to
// tell "nothing set up yet" (new-user page) apart from "set up, but nothing
// came up this time" (account page).
//
// No automatic DHT publish here (or anywhere at boot): publishing is opt-in,
// never a keep-alive side effect of opening the app — see
// didcomm-devices.ts's file header and
// [[project_biset_did_relay_orthogonality]]'s published/unpublished design.
// setupDidCommChannel's reassertKeylistRegistration (channel.ts), below,
// already republishes the full document on its own whenever a mediator is
// registered — for any DID, relay-backed or not — and does nothing when one
// isn't, which is the only "keep alive" this identity needs.
// Memoized: route() (below) re-runs this whole file's routing logic on every
// hashchange/popstate, not just the initial load (the fix for "typing #foo
// into the address bar and pressing Enter does nothing until you reload" —
// hashchange has no listener otherwise). Re-running the ACTUAL session
// bootstrap on every navigation would double-addSession every stored
// account and re-run DIDComm channel setup on top of an already-live one —
// so only the first call does real work; every later call (regardless of
// its own onNew) gets back the same settled promise.
let bootSessionsPromise: Promise<{ configured: boolean }> | null = null

async function bootSessions(accounts: ReturnType<typeof loadStoredAccounts>, onNew: () => void): Promise<{ configured: boolean }> {
  if (bootSessionsPromise) return bootSessionsPromise
  bootSessionsPromise = (async () => {
    if (accounts.length) {
      const results = await Promise.all(accounts.map(initSession))
      const validSessions = results.filter(Boolean) as NonNullable<Awaited<ReturnType<typeof initSession>>>[]
      validSessions.forEach(s => addSession(s))
    }

    const { ownDid: ownIdentityDid } = await import('./did/didcomm-devices.ts')
    const ownDid = sessions.find(s => s.account.did)?.account.did ?? ownIdentityDid()
    const configured = accounts.length > 0 || ownDid !== null
    if (!accounts.length && !ownDid) return { configured } // no accounts, no local identity — genuinely new
    advertiseAllOwnAvatars()

    if (ownDid) {
      const { setupDidCommChannel } = await import('./did/didcomm/channel.ts')
      await setupDidCommChannel(ownDid, onNew)
        .then(started => { if (!started) console.warn('[didcomm] channel setup skipped — hasDidCommChannel() returned false for', ownDid) })
        .catch(e => console.warn('[didcomm] channel setup failed:', e instanceof Error ? e.message : e))
    }

    if (sessions.length) {
      import('./did/discovery.ts').then(m => m.pullOwnContacts()).catch(() => {})
      // Learn contact display names from history already in the store. Lives
      // here rather than beside loadFromCache() in initInner: it needs
      // sessions[] populated — both to tell our own addresses apart from
      // contacts', and to know which private key decrypts a given message
      // (a DeltaChat name is only in the encrypted part, see app.ts).
      backfillContactNames()
    }
    return { configured }
  })()
  return bootSessionsPromise
}

// ── Init ───────────────────────────────────────────────────────────────────────

// A stale/broken stored account (e.g. pointing at a relay that no longer
// resolves, or one left over from a domain migration) can throw partway through
// initInner and leave the app stuck on the pre-app overlay — unresponsive menu,
// no left pane, no way back in without devtools. This safety net guarantees the
// UI becomes interactive no matter what: it drops onto the account page, where
// the broken account can be removed via the existing per-account "Remove"
// action (left-pane.ts openAccountMenu) — a self-service recovery path that
// doesn't require clearing localStorage by hand.
async function init() {
  // The MLS Authentication Service, installed before anything can process a
  // group message. Until it is, ts-mls's own validator accepts every
  // credential, so a leaf's claim to be `did#kN` is structurally well-formed
  // and completely unverified (mls/authservice.ts). Installed here rather than
  // lazily at first use because "unverified until someone remembers to switch
  // it on" is exactly the shape of a security control that silently never
  // runs.
  setMlsAuthService(didAuthenticationService)
  try {
    await initInner()
  } catch (e) {
    console.error('[init] failed, falling back to account page', e)
    showApp()
    if (!document.getElementById('app')?.classList.contains('lp-enabled')) {
      await setupLeftPane().catch(() => {})
    }
    showMenuPage('/account')
  }
}

// The hash-dependent half of initInner, split out so a hashchange/popstate
// after the initial load (e.g. typing #restore into the address bar and
// pressing Enter — previously a no-op until a manual reload, since nothing
// listened for it) can re-run just this, not the one-time cache priming
// initInner also does. Safe to call repeatedly: bootSessions is memoized
// (its own note), and every branch here either reads state or replaces DOM/
// hash state idempotently — nothing here accumulates on a second call the
// way a naive full initInner() rerun would (double addSession, etc).
async function route(rawHash: string, accounts: ReturnType<typeof loadStoredAccounts>): Promise<void> {
  // #new/#restore are gone (2026-08-16): account creation is no longer a
  // separate page, it's a "create account" affordance inside compose's From
  // field (left-pane.ts's onShowNew). Both hashes are still accepted so an
  // old bookmark lands somewhere sensible (the account page, which already
  // covers both creating a new identity and restoring one from its
  // recovery phrase) rather than nowhere.
  if (rawHash === '#new' || rawHash === '#restore') {
    showApp()
    await setupLeftPane()
    showMenuPage('/account')
    return
  }

  // Menu-only hash (e.g. #account, #config): load sessions in background
  const menuPage = menuHashFromHash(rawHash)
  if (menuPage) {
    showApp()
    await setupLeftPane()
    showMenuPage(menuPage)
    // showMenuPage above renders (and, for /compose, onShow-initializes) the
    // page immediately, BEFORE sessions[] is populated below — deliberate,
    // so a menu page never blocks on the network. But /compose's From
    // selector reads sessions[] at that exact moment and finds it empty
    // (see did/didcomm/channel.ts's channel-detection notes for the same
    // race). Once sessions[] is actually populated, redraw it — but only if
    // the user hasn't started typing a draft in the meantime, so a slow
    // network never clobbers real input.
    const refreshComposeIfPristine = () => {
      if (menuPage !== '/compose') return
      const body = document.getElementById('new-body') as HTMLTextAreaElement | null
      const firstTo = document.querySelector<HTMLInputElement>('#new-recipients .new-field-input')
      if (body?.value.trim() || firstTo?.value.trim()) return
      showMenuPage(menuPage)
    }
    // One shared bootstrap regardless of relay/standalone shape (bootSessions'
    // own note) — this used to be reimplemented separately per shape here,
    // and the relay-backed copy never started the DIDComm channel at all.
    await bootSessions(accounts, () => { fetchMessages(); loadLeftInboxes() })
    syncNotifToggle()
    refreshAccountsList()
    startPolling()
    loadLeftInboxes()
    refreshComposeIfPristine()
    return
  }

  // Everything else is a conversation permalink (#<contact>, the exact shape
  // utils.ts's inboxToHash emits): an existing conversation opens it; a hash
  // naming someone with no conversation yet opens compose prefilled with
  // them instead — logged in or not (2026-08-16: folded the old separate
  // `#compose/<addr>` shareable-link shape into this one, since a link to
  // start chatting with someone IS a permalink, just to a conversation that
  // doesn't exist). One shared bootstrap regardless of relay/standalone
  // shape (bootSessions' own note): a relay-less identity's zero
  // StoredAccounts republishes its DID doc + renews mediation and registers
  // its DIDComm channel (if any) as a synthetic session.
  await bootSessions(accounts, () => { fetchMessages(); loadLeftInboxes() })
  showApp()
  await setupLeftPane()

  const parts = rawHash ? parseInboxHash(rawHash) : null
  // group: permalinks are never a compose target — no "start a message to
  // this group" flow exists, so a stale/broken one falls back like an empty
  // hash always has (inboxes[0]) rather than trying to compose to it.
  const composable = !!parts && !parts.contact.startsWith('group:')

  if (sessions.length) {
    refreshAccountsList()
    startPolling()
    loadLeftInboxes()

    const inboxes = await loadInboxSummaries()
    let target: InboxSummary | null = await matchInboxForHash(rawHash, inboxes)
    if (!target && !composable) target = inboxes[0] ?? null
    if (target) {
      setCurrentInbox(target)
      if (!rawHash || parseInboxHash(rawHash)) {
        try { history.replaceState(null, '', inboxToHash(target)) } catch {}
      }
      await fetchMessages()
      return
    }
  }

  if (composable) {
    openComposeTo(await resolveComposeTarget(parts!.contact))
    return
  }
  // Not logged in and the hash names nothing composable (empty, or a
  // group: permalink): #new is gone, so this is where a genuinely new
  // visitor (and a stale group link) both land.
  if (!sessions.length) showMenuPage('/account')
}

async function initInner() {
  // The Service Worker talks to this page for two things (push/client.ts): a
  // tapped notification's target conversation, and "the mediator has DIDComm
  // messages queued, collect them now". Wired before any routing so a cold
  // start opened from a notification can't miss either.
  listenForServiceWorkerMessages()

  // One client session = one identity (2026-07-14) — narrow to whichever
  // identity is currently active before anything gets initSession'd, so
  // sessions[] (and everything merged from it) only ever spans one DID.
  const accounts = accountsForActiveIdentity(loadStoredAccounts())

  // Prime the DeltaChat avatar cache so synchronous UI lookups have data, and
  // load the browser-local cache (IndexedDB) into the in-memory stores before
  // the first sync — this is what lets a plain page refresh do a delta sync
  // (via querystate) instead of re-fetching + re-decrypting full history.
  // IndexedDB can wedge (e.g. a delete racing an open right after logout) —
  // race it against a timeout so a stuck cache load can never block the app
  // from ever syncing at all; a missed cache just costs one full re-fetch.
  // One-time only — a later route() call (hashchange/popstate) reuses
  // whatever this already loaded into the in-memory stores.
  const withTimeout = <T>(p: Promise<T>, ms: number): Promise<T | void> =>
    Promise.race([p, new Promise<void>(resolve => setTimeout(resolve, ms))])
  await Promise.all([
    primeAvatarCache(),
    withTimeout(loadFromCache(), 3000),
    withTimeout(loadQuerystateFromIDB(), 3000),
  ])

  // Per-user landing page (https://<host>/<localpart>[/]) takes precedence over
  // hash routing — it's how a shared user URL opens a conversation. This reads
  // location.pathname, not the hash, so it only ever applies to the initial
  // load (an SPA hash change can't produce a new pathname).
  const landingLp = userPathLocalpart()
  if (landingLp) { await handleUserLanding(landingLp, accounts); return }

  await route(location.hash, accounts)
}

// ── UI wiring ──────────────────────────────────────────────────────────────────

function togglePane() {
  const $app = document.getElementById('app')
  if (!$app) return
  if ($app.classList.contains('show-left')) {
    $app.classList.remove('show-left')
  } else if ($app.classList.contains('single-col')) {
    $app.classList.remove('single-col')
    try { localStorage.setItem('lp-open', '1') } catch {}
    requestAnimationFrame(() => {
      import('./ui/thread.ts').then(t => { t.syncDockPosition(); t.scrollToFocused() })
    })
    setTimeout(() => import('./ui/thread.ts').then(t => t.syncDockPosition()), 300)
  } else if (window.innerWidth <= 574) {
    $app.classList.add('show-left')
  } else {
    $app.classList.add('single-col')
    try { localStorage.setItem('lp-open', '0') } catch {}
    requestAnimationFrame(() => {
      import('./ui/thread.ts').then(t => { t.syncDockPosition(); t.scrollToFocused() })
    })
    setTimeout(() => import('./ui/thread.ts').then(t => t.syncDockPosition()), 300)
  }
}

document.getElementById('main-toggle')?.addEventListener('click', togglePane)
document.getElementById('main-toggle-right')?.addEventListener('click', togglePane)
document.getElementById('main-toggle-cmd')?.addEventListener('click', togglePane)

document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'b') {
    e.preventDefault()
    togglePane()
  }
})

const $menu = document.getElementById('menu')
document.querySelectorAll('.lp-hmenu-item').forEach(btn => {
  btn.addEventListener('click', e => {
    e.stopPropagation()
    const page = (btn as HTMLElement).dataset.page
    if (page) showMenuPage(page)
    document.getElementById('lp-hamburger-menu')?.classList.remove('open')
    document.getElementById('app')?.classList.remove('show-left')
  })
})

// Logout moved off this menu entirely (2026-08-12, user-requested): it now
// lives on the identity card's own hamburger (left-pane.ts's
// renderAccountsList), next to the other whole-identity actions — this menu
// is page navigation, and logging out was the one item on it that wasn't.
{
  const menu = document.getElementById('lp-hamburger-menu')!
  let hideTimer: ReturnType<typeof setTimeout> | null = null

  const showNear = (trigger: HTMLElement) => {
    if (!menu) return
    const r = trigger.getBoundingClientRect()
    menu.style.top = (r.bottom + 4) + 'px'
    menu.style.right = (window.innerWidth - r.right) + 'px'
    menu.style.left = 'auto'
    menu.classList.add('open')
  }
  const scheduleHide = () => {
    hideTimer = setTimeout(() => menu?.classList.remove('open'), 200)
  }
  const cancelHide = () => {
    if (hideTimer) { clearTimeout(hideTimer); hideTimer = null }
  }

  menu?.addEventListener('mouseenter', cancelHide)
  menu?.addEventListener('mouseleave', scheduleHide)

  for (const id of ['lp-hamburger', 'lp-hamburger-left']) {
    const btn = document.getElementById(id)
    btn?.addEventListener('mouseenter', () => { cancelHide(); showNear(btn) })
    btn?.addEventListener('mouseleave', scheduleHide)
    btn?.addEventListener('click', e => {
      e.stopPropagation()
      if (menu?.classList.contains('open')) { menu.classList.remove('open') } else { showNear(btn) }
    })
  }
}
document.getElementById('cmd-page-avatar-btn')?.addEventListener('click', e => {
  e.stopPropagation()
  showMenuPage('/account')
})
document.addEventListener('click', () => $menu?.classList.remove('open'))

document.getElementById('lp-export-inbox-btn')?.addEventListener('click', async e => {
  e.stopPropagation()
  const menu = document.getElementById('lp-inbox-menu')
  if (!menu) return
  menu.style.display = 'none'
  const ci = menuTargetInbox
  if (!ci) return
  const { showSysMsg } = await import('./ui/shell.ts')
  showSysMsg('Exporting…')
  try {
    const { activeSession, identityKey } = await import('./context.ts')
    const { getInboxEmails, emailToMsg } = await import('./app.ts')
    const sess = activeSession()
    if (!sess) return
    const selfAddr = sess.jmapAccountId || sess.account.email
    const emails = getInboxEmails(ci.mailbox, ci.contact, selfAddr, identityKey(sess))
    const output = {
      generated_at: Math.floor(Date.now() / 1000),
      inbox: ci,
      messages: emails.map(e => emailToMsg(e, selfAddr)),
    }
    const blob = new Blob([JSON.stringify(output, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${ci.user}_${ci.mailbox}_${ci.contact}.json`.replace(/[^a-z0-9._-]/gi, '_')
    a.click()
    showSysMsg('Export complete')
  } catch { (await import('./ui/shell.ts')).showSysMsg('Export failed') }
})

document.getElementById('lp-archive-inbox-btn')?.addEventListener('click', async e => {
  e.stopPropagation()
  const menu = document.getElementById('lp-inbox-menu')
  if (!menu) return
  menu.style.display = 'none'
  const ci = menuTargetInbox
  if (!ci) return
  const { archiveInbox } = await import('./ui/left-pane.ts')
  await archiveInbox(ci, !ci.archived)
})

document.getElementById('lp-delete-inbox-btn')?.addEventListener('click', async e => {
  e.stopPropagation()
  const menu = document.getElementById('lp-inbox-menu')
  if (!menu) return
  menu.style.display = 'none'
  const ci = menuTargetInbox
  if (!ci) return
  const { doDeleteInbox } = await import('./ui/left-pane.ts')
  await doDeleteInbox(ci)
})

document.addEventListener('click', () => {
  const m = document.getElementById('lp-inbox-menu')
  if (m) m.style.display = 'none'
})

// Re-route on any hash navigation route() itself didn't drive (URL bar edits,
// bookmarks, back/forward) — without this, typing e.g. #restore into the
// address bar and pressing Enter changed the URL but left the page showing
// whatever it showed before, since nothing was listening for hashchange at
// all (main.ts previously routed only once, at initInner()). Both events are
// wired to the same handler: hashchange covers direct URL-bar edits (the
// case above), popstate covers back/forward — since every in-app hash write
// here uses replaceState (never pushState — grep confirms it), back/forward
// through a biset hash essentially never happens today, but there's no
// reason for it to silently do nothing if it ever does.
function onHashNav() {
  route(location.hash, accountsForActiveIdentity(loadStoredAccounts()))
    .catch(e => console.error('[route] navigation failed', e))
}
window.addEventListener('hashchange', onHashNav)
window.addEventListener('popstate', onHashNav)

// scroll-to-top/bottom buttons. The reply dock used to also auto-hide while
// scrolling up (for reading room) and re-show scrolling down — removed
// (2026-07-14) after it caused a whole day of intermittent "reply box
// missing" reports: it needed a stale-prone lastScrollTop baseline plus a
// markProgrammaticScroll/isProgrammaticScroll window (utils.ts, since
// removed) sprinkled across every app-driven scroll to avoid mistaking our
// own scrolls for the user's, and kept finding new timing gaps (native
// scroll-anchoring on thread-open, slow devices missing the window, a
// completely separate show-left/CSS interaction) no matter how many self-
// heals got added. The dock is just always visible while a thread is open
// now — simpler and it can't get stuck hidden again by construction.
{
  const outer = document.getElementById('outer')
  const btn = document.getElementById('scroll-to-bottom')
  const btnTop = document.getElementById('scroll-to-top')
  outer?.addEventListener('scroll', () => {
    // Menu pages (#account, #config, #compose, …) share #outer with the
    // conversation view, but these buttons only make sense for a thread's
    // own message strip — not a settings form (2026-08-17, user-reported:
    // they showed up while scrolling #account).
    if (inMenuMode()) {
      btn?.classList.remove('visible')
      btnTop?.classList.remove('visible')
      return
    }
    const distFromBottom = outer.scrollHeight - outer.scrollTop - outer.clientHeight
    const bottomVisible = distFromBottom > 120
    btn?.classList.toggle('visible', bottomVisible)
    const past = document.getElementById('past-threads')
    const pastH = past && outer.contains(past) ? past.offsetHeight : 0
    btnTop?.classList.toggle('visible', outer.scrollTop > pastH + 40)
    btnTop?.classList.toggle('above-bottom', bottomVisible)
    // Hidden only while actually mid-scroll away from both ends — not at the
    // top, and not at the bottom either, since opening a thread auto-scrolls
    // there and the title shouldn't vanish on arrival.
    //
    // "At the top" is pastH, NOT 0: scrollTop 0 is the top of the past-threads
    // drawer, which sits above the title row, so a conversation with several
    // threads kept the title hidden at exactly the position the ↑ button
    // scrolls to (it targets pastH — the title row pinned at the top of the
    // viewport, which is precisely when the title should be readable). Only
    // with a single thread does the drawer collapse to 0 and the two agree,
    // which is why it looked right there and nowhere else.
    //
    // "At the bottom" can't just be distFromBottom <= 120: scrollToFocused
    // pins a last message taller than the viewport to the top of the strip
    // instead of chasing its tail (thread.ts), which leaves plenty of
    // scrollable distance below even though the last message is exactly what's
    // on screen. Checking whether that message has scrolled into view catches
    // this case too.
    const lastMsg = outer.querySelector('.t-messages')?.lastElementChild as HTMLElement | null
    const lastMsgVisible = !lastMsg || lastMsg.getBoundingClientRect().top < outer.getBoundingClientRect().bottom
    const titleHidden = outer.scrollTop > pastH && bottomVisible && !lastMsgVisible
    document.getElementById('header-left')?.classList.toggle('title-hidden', titleHidden)
    document.getElementById('main-toggle-right')?.classList.toggle('title-hidden', titleHidden)
    document.getElementById('lp-hamburger')?.classList.toggle('title-hidden', titleHidden)
  }, { passive: true })
  btn?.addEventListener('click', () => {
    outer?.scrollTo({ top: outer.scrollHeight, behavior: 'smooth' })
  })
  btnTop?.addEventListener('click', () => {
    const past = document.getElementById('past-threads')
    const pastH = past && outer?.contains(past) ? past.offsetHeight : 0
    outer?.scrollTo({ top: pastH, behavior: 'smooth' })
  })
}

// Mobile: swipe right anywhere in the conversation to reveal the inbox list.
// Mirrors the swipe-to-delete gesture on inbox rows (left-pane.ts) but opens
// the left pane instead. Only fires below the mobile breakpoint and while a
// conversation (not already the list) is showing.
//
// Direction is decided early (once the touch has moved a few px) rather than
// only at touchend: a diagonal touch would otherwise scroll the message list
// vertically for the whole gesture (native scroll isn't blocked until we
// preventDefault) while also being judged as a swipe at the end, which felt
// like the screen wobbling up and down. Once locked horizontal, further
// vertical movement is suppressed for the rest of the gesture; once locked
// vertical, we back off entirely and let normal scrolling happen.
{
  const rightCol = document.getElementById('right-col')
  let startX = 0, startY = 0, tracking = false
  let lockedAxis: 'x' | 'y' | null = null
  rightCol?.addEventListener('touchstart', e => {
    if (window.innerWidth > 574) { tracking = false; return }
    const $app = document.getElementById('app')
    tracking = !!$app && !$app.classList.contains('show-left')
    lockedAxis = null
    startX = e.touches[0].clientX
    startY = e.touches[0].clientY
  }, { passive: true })
  rightCol?.addEventListener('touchmove', e => {
    if (!tracking) return
    const dx = e.touches[0].clientX - startX
    const dy = e.touches[0].clientY - startY
    if (!lockedAxis) {
      if (Math.abs(dx) < 10 && Math.abs(dy) < 10) return
      lockedAxis = Math.abs(dx) > Math.abs(dy) * 1.5 ? 'x' : 'y'
    }
    if (lockedAxis === 'x') e.preventDefault()
  }, { passive: false })
  rightCol?.addEventListener('touchend', e => {
    if (!tracking) return
    tracking = false
    const dx = e.changedTouches[0].clientX - startX
    if (lockedAxis === 'x' && dx > 70) {
      document.getElementById('app')?.classList.add('show-left')
    }
  }, { passive: true })
}

window.addEventListener('resize', async () => {
  const { syncDockPosition, scrollToFocused } = await import('./ui/thread.ts')
  syncDockPosition()
  scrollToFocused()
})

// Keep #outer's padding in step as the dock's own height changes (textarea
// growing, compose mode expanding). syncDockPosition writes the padding
// synchronously first, so the scroll compensation below reads the updated
// scrollHeight and the conversation doesn't jump when the dock resizes.
{
  const dock = document.getElementById('reply-dock')
  if (dock && typeof ResizeObserver !== 'undefined') {
    let prevDockH = dock.offsetHeight
    new ResizeObserver(async () => {
      const { syncDockPosition } = await import('./ui/thread.ts')
      const newH = dock.offsetHeight
      const delta = newH - prevDockH
      prevDockH = newH
      syncDockPosition()
      if (delta !== 0) {
        const outer = document.getElementById('outer')
        const past = document.getElementById('past-threads')
        const pastH = past && outer?.contains(past) ? past.offsetHeight : 0
        if (outer && outer.scrollTop > pastH) outer.scrollTop += delta
      }
    }).observe(dock)
  }
}

init()

// TEMPORARY (2026-08-11, remove once y@biset.md's mediator registration is
// confirmed complete on every device): console-only, one-shot. The did:dht →
// did:webvh migration (earlier __migrateY, since removed) deliberately left
// mediator fields unset on the new record — first-time registration only
// happens automatically at #new signup, never at boot for an existing
// identity (main.ts's own note on bootSessions) — so nothing ever completed
// it for the migrated identity. Run once per device/browser, logged in as
// y@biset.md: `await window.__registerMediator()`.
;(window as any).__registerMediator = async () => {
  const { registerWithMediator, mediatorUrl, ownDid } = await import('./did/didcomm-devices.ts')
  const { sessions } = await import('./context.ts')
  const did = sessions.find(s => s.account.did)?.account.did ?? ownDid()
  if (!did) throw new Error('no identity in this session')
  console.log('[register] registering', did, 'with', mediatorUrl())
  const reg = await registerWithMediator(mediatorUrl())
  console.log('[register] done, own kid:', reg.own.xKid)
  const { setupDidCommChannel } = await import('./did/didcomm/channel.ts')
  await setupDidCommChannel(reg.own.did, () => {
    import('./ui/shell.ts').then(s => s.fetchMessages())
    import('./ui/left-pane.ts').then(m => m.loadLeftInboxes())
  })
  console.log('[register] channel set up — reload the page next')
  return reg.own.did
}

// TEMPORARY (2026-08-12, remove once y@biset.md's did:webvh path-shape
// migration — dropping the `dids/` segment — is confirmed live): console-
// only, one-shot, gated to the exact known (already-migrated-once) DID.
// Run once, logged into t.biset.md as y@biset.md: `await window.__migrateWebvhShape()`.
;(window as any).__migrateWebvhShape = async () => {
  const OLD_DID = 'did:webvh:Qmcz9xXcVcToPw5w4cgUv9SonybrmNpjnUDjtw1Zsqtua3:biset.md:dids:y'
  const { migrateWebvhPathShape } = await import('./did/index.ts')
  const { setOwnDid, publishBareOrCurrent } = await import('./did/didcomm-devices.ts')
  const { loadStoredAccounts, saveStoredAccounts } = await import('./context.ts')

  const rec = await migrateWebvhPathShape(OLD_DID, { domain: 'biset.md', username: 'y' })
  console.log('[migrate] new did:', rec.did)

  const accounts = loadStoredAccounts()
  const updated = accounts.map(a => a.did === OLD_DID ? { ...a, did: rec.did } : a)
  saveStoredAccounts(updated)
  console.log('[migrate] StoredAccount.did rewritten for', updated.filter(a => a.did === rec.did).map(a => a.email))

  setOwnDid(rec.did)
  const published = await publishBareOrCurrent(rec)
  console.log('[migrate] published to', published, 'gateway(s) — reload the page next, then run window.__registerMediator()')

  return rec.did
}
