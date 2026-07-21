import {
  sessions, addSession, setCurrentInbox, currentInbox, loadStoredAccounts, accountsForActiveIdentity,
} from './context.ts'
import { initSession, loadInboxSummaries, logout } from './app.ts'
import type { InboxSummary } from './types.ts'
import { inboxToHash, parseInboxHash } from './utils.ts'
import { contactIdentityKey, representativeAddressForDid } from './did/contacts.ts'
import { useSeqStore } from './did/freshness.ts'
import { showApp, startPolling, fetchMessages } from './ui/shell.ts'
import { loadLeftInboxes, switchInbox, showMenuPage, setupLeftPane, refreshAccountsList, menuTargetInbox, openComposeTo, syncNotifToggle } from './ui/left-pane.ts'
import { setupNewUserPage, showNewUserPage } from './ui/account-create.ts'
import { showUserLanding } from './ui/user-landing.ts'
import { primeAvatarCache } from './deltachat/avatar.ts'
import { advertiseAllOwnAvatars } from './ap/avatar.ts'
import { loadFromCache } from './store/cache.ts'
import { loadFromIDB as loadQuerystateFromIDB } from './jmap/querystate.ts'

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

// `#compose/<addr>` opens the compose page with To pre-filled — a shareable link
// to start a message to someone.
function composeArgFromHash(hash: string): string | null {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash
  if (!raw.startsWith('compose/')) return null
  const addr = raw.slice('compose/'.length)
  try { return addr ? decodeURIComponent(addr) : null } catch { return addr || null }
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

async function handleUserLanding(localpart: string, accounts: ReturnType<typeof loadStoredAccounts>) {
  const cfg = (window as any).__BISET_CONFIG__
  const host: string = cfg?.hostname || location.hostname
  const target = `${localpart}@${host}`
  const apUrl: string = cfg?.ap_url || (host ? `https://ap.${host}` : '')

  // Existing biset users get the compose page with the target pre-filled as To.
  if (accounts.length) {
    const results = await Promise.all(accounts.map(initSession))
    const valid = results.filter(Boolean) as NonNullable<Awaited<ReturnType<typeof initSession>>>[]
    valid.forEach(s => addSession(s))
    if (sessions.length) {
      advertiseAllOwnAvatars()
      showApp()
      await setupLeftPane()
      startPolling()
      loadLeftInboxes()
      openComposeTo(target)
      return
    }
  }
  // New visitors see the profile + a CTA that routes through account creation and
  // then opens the conversation (pending-DM handoff).
  await showUserLanding(target, apUrl)
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
// relay account, or a standalone DID ever created) — distinct from whether
// sessions[] ends up non-empty, which also depends on whether that identity's
// relays/channel are reachable right now. Callers use this to tell "nothing
// set up yet" (new-user page) apart from "set up, but nothing came up this
// time" (account page).
async function bootSessions(accounts: ReturnType<typeof loadStoredAccounts>, onNew: () => void): Promise<{ configured: boolean }> {
  const createStandalone = await import('./did/create-standalone.ts')
  let configured = accounts.length > 0
  if (accounts.length) {
    const results = await Promise.all(accounts.map(initSession))
    const validSessions = results.filter(Boolean) as NonNullable<Awaited<ReturnType<typeof initSession>>>[]
    validSessions.forEach(s => addSession(s))
  } else {
    // Relay-less: republish this identity's bare DID doc + renew mediation.
    // refreshStandalone reads its own localStorage marker and returns null
    // immediately if this device was never set up as standalone, so this is
    // exactly the relay-less branch — never reached when accounts.length > 0.
    const sDid = await createStandalone.refreshStandalone()
    configured = createStandalone.standaloneDid() !== null
    if (!sDid) return { configured } // no accounts, no standalone identity — genuinely new
  }
  advertiseAllOwnAvatars()

  const ownDid = sessions.find(s => s.account.did)?.account.did ?? createStandalone.standaloneDid()
  if (ownDid) {
    const { setupDidCommChannel } = await import('./did/didcomm/channel.ts')
    await setupDidCommChannel(ownDid, onNew)
      .then(started => { if (!started) console.warn('[didcomm] channel setup skipped — hasDidCommChannel() returned false for', ownDid) })
      .catch(e => console.warn('[didcomm] channel setup failed:', e instanceof Error ? e.message : e))
  }

  if (sessions.length) {
    // Keep our DID records alive on the DHT (best-effort — see did/publish.ts).
    import('./did/publish.ts').then(m => m.publishOwnDids()).catch(() => {})
    import('./did/discovery.ts').then(m => m.pullOwnContacts()).catch(() => {})
  }
  return { configured }
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

async function initInner() {
  // One client session = one identity (2026-07-14) — narrow to whichever
  // identity is currently active before anything gets initSession'd, so
  // sessions[] (and everything merged from it) only ever spans one DID.
  const accounts = accountsForActiveIdentity(loadStoredAccounts())
  const rawHash = location.hash

  // Prime the DeltaChat avatar cache so synchronous UI lookups have data, and
  // load the browser-local cache (IndexedDB) into the in-memory stores before
  // the first sync — this is what lets a plain page refresh do a delta sync
  // (via querystate) instead of re-fetching + re-decrypting full history.
  // IndexedDB can wedge (e.g. a delete racing an open right after logout) —
  // race it against a timeout so a stuck cache load can never block the app
  // from ever syncing at all; a missed cache just costs one full re-fetch.
  const withTimeout = <T>(p: Promise<T>, ms: number): Promise<T | void> =>
    Promise.race([p, new Promise<void>(resolve => setTimeout(resolve, ms))])
  await Promise.all([
    primeAvatarCache(),
    withTimeout(loadFromCache(), 3000),
    withTimeout(loadQuerystateFromIDB(), 3000),
  ])

  // Per-user landing page (https://<host>/<localpart>[/]) takes precedence over
  // hash routing — it's how a shared user URL opens a conversation.
  const landingLp = userPathLocalpart()
  if (landingLp) { await handleUserLanding(landingLp, accounts); return }

  // #compose/<addr>: open compose with To pre-filled (shareable message link; the
  // app-host handoff target from a /<user>/ profile page). Logged in → compose;
  // new visitor → account creation (with the target as a chat header) then compose.
  const composeTo = composeArgFromHash(rawHash)
  if (composeTo) {
    // DID⊥relay: a relay-less identity can compose too (bootSessions.
    // configured also becomes true here for anyone with an existing
    // standalone identity, not just relay accounts).
    await bootSessions(accounts, () => { fetchMessages(); loadLeftInboxes() })
    if (sessions.length) {
      showApp()
      await setupLeftPane()
      refreshAccountsList()
      startPolling()
      loadLeftInboxes()
      openComposeTo(composeTo)
      return
    }
    const cfg = (window as any).__BISET_CONFIG__
    const apUrl: string = cfg?.ap_url || (cfg?.hostname ? `https://ap.${cfg.hostname}` : '')
    await showUserLanding(composeTo, apUrl)
    return
  }

  if (rawHash === '#new' || rawHash === '#newdid') {
    setupNewUserPage()
    showNewUserPage()
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

  // One shared bootstrap for whichever shape this identity is (bootSessions'
  // own note): a relay-less identity's zero StoredAccounts republishes its
  // DID doc + renews mediation and registers its DIDComm channel (if any) as
  // a synthetic session — sessions[] being non-empty from here on is what
  // lets the SAME "pick an inbox, show it" flow below handle it, exactly like
  // a JMAP identity's sessions. No DIDComm channel yet (mediator unreachable,
  // or never configured) falls through to the account page, where "+ New
  // Relay" can register one. A genuinely new visitor (no accounts, no
  // standalone identity ever created) routes to the new-user page instead.
  const { configured } = await bootSessions(accounts, () => { fetchMessages(); loadLeftInboxes() })
  if (!sessions.length) {
    if (!configured) {
      setupNewUserPage()
      showNewUserPage()
      return
    }
    showApp()
    await setupLeftPane()
    showMenuPage('/account')
    return
  }

  // Fire-and-forget PGP init (kek only available on fresh envelope login, not here)
  // sessions.forEach(s => initPGPForSession(s))

  // Determine initial inbox from hash or first available
  const inboxes = await loadInboxSummaries()

  let target: InboxSummary | null = await matchInboxForHash(rawHash, inboxes)

  if (!target) {
    target = inboxes[0] ?? null
  }

  if (!target) {
    showApp()
    await setupLeftPane()
    startPolling()
    return
  }

  setCurrentInbox(target)
  if (!rawHash || parseInboxHash(rawHash)) {
    try { history.replaceState(null, '', inboxToHash(target)) } catch {}
  }

  showApp()
  await setupLeftPane()
  startPolling()
  loadLeftInboxes()
  await fetchMessages()
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
  } else if (window.innerWidth <= 520) {
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

// Full local wipe — every account's cached credentials, messages, keys, DID
// records. Server-side data is untouched (this only clears what the browser
// holds); a stale password/token surviving a server-side reset (see the
// 401-after-relay-reset incident) is exactly what this is for.
document.getElementById('lp-hmenu-logout')?.addEventListener('click', async () => {
  if (!confirm('Log out and erase ALL local data (accounts, messages, keys)? This cannot be undone.')) return
  // The single teardown chokepoint (app.ts) — deregisters this device from
  // every mediator, then wipes. This handler used to inline its OWN wipe that
  // skipped the deregister entirely; that divergence is the whole "logout
  // doesn't remove the key" saga. Do NOT reintroduce a second wipe here.
  await logout()
})
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

window.addEventListener('popstate', async () => {
  const hash = location.hash
  const menuPage = menuHashFromHash(hash)
  if (menuPage) { showMenuPage(menuPage); return }
  if (!parseInboxHash(hash)) return
  const inboxes = await loadInboxSummaries()
  const found = await matchInboxForHash(hash, inboxes)
  if (found) switchInbox(found)
})

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
    const distFromBottom = outer.scrollHeight - outer.scrollTop - outer.clientHeight
    const bottomVisible = distFromBottom > 120
    btn?.classList.toggle('visible', bottomVisible)
    const past = document.getElementById('past-threads')
    const pastH = past && outer.contains(past) ? past.offsetHeight : 0
    btnTop?.classList.toggle('visible', outer.scrollTop > pastH + 40)
    btnTop?.classList.toggle('above-bottom', bottomVisible)
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
    if (window.innerWidth > 520) { tracking = false; return }
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

// Wire the browser's storage into the DID freshness floor before anything can
// resolve. did/freshness.ts takes this by injection rather than reaching for
// localStorage itself, so the did:dht wire layer stays runnable outside a
// browser (see ANCHOR.md) — and it throws rather than defaulting, since a
// silent fallback would quietly disable rollback defense.
useSeqStore(localStorage)

init()
