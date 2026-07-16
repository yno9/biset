import {
  sessions, addSession, setCurrentInbox, currentInbox, loadStoredAccounts, accountsForActiveIdentity,
} from './context.ts'
import { initSession, initPGPForSession, loadInboxSummaries } from './app.ts'
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
const MENU_PAGE_NAMES = new Set(['account', 'config', 'compose', 'debug', 'didcomm'])

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
    if (accounts.length) {
      const results = await Promise.all(accounts.map(initSession))
      const valid = results.filter(Boolean) as NonNullable<Awaited<ReturnType<typeof initSession>>>[]
      valid.forEach(s => addSession(s!))
      valid.forEach(s => initPGPForSession(s!))
      advertiseAllOwnAvatars()
      if (sessions.length) {
        showApp()
        await setupLeftPane()
        refreshAccountsList()
        startPolling()
        loadLeftInboxes()
        openComposeTo(composeTo)
        return
      }
    }
    const cfg = (window as any).__BISET_CONFIG__
    const apUrl: string = cfg?.ap_url || (cfg?.hostname ? `https://ap.${cfg.hostname}` : '')
    await showUserLanding(composeTo, apUrl)
    return
  }

  if (rawHash === '#new') {
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
    if (accounts.length) {
      const results = await Promise.all(accounts.map(initSession))
      const validSessions = results.filter(Boolean) as NonNullable<Awaited<ReturnType<typeof initSession>>>[]
      validSessions.forEach(s => addSession(s!))
      validSessions.forEach(s => initPGPForSession(s!))
      advertiseAllOwnAvatars()
      import('./did/publish.ts').then(m => m.publishOwnDids()).catch(() => {})
      import('./did/discovery.ts').then(m => m.pullOwnContacts()).catch(() => {})
      syncNotifToggle()
      refreshAccountsList()
      startPolling()
      loadLeftInboxes()
    }
    return
  }

  if (!accounts.length) {
    setupNewUserPage()
    showNewUserPage()
    return
  }

  const results = await Promise.all(accounts.map(initSession))
  const validSessions = results.filter(Boolean) as NonNullable<Awaited<ReturnType<typeof initSession>>>[]
  validSessions.forEach(s => addSession(s))
  advertiseAllOwnAvatars()

  if (!sessions.length) {
    showApp()
    showMenuPage('/account')
    return
  }

  // Keep our DID records alive on the DHT (best-effort — see did/publish.ts).
  import('./did/publish.ts').then(m => m.publishOwnDids()).catch(() => {})
  import('./did/discovery.ts').then(m => m.pullOwnContacts()).catch(() => {})

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
  localStorage.clear()
  try { sessionStorage.clear() } catch { /* ignore */ }
  const dbNames = ['biset-cache', 'biset-pgp', 'biset-did', 'biset-deltachat']
  await Promise.all(dbNames.map(name => new Promise<void>(resolve => {
    const req = indexedDB.deleteDatabase(name)
    req.onsuccess = () => resolve()
    req.onerror = () => resolve()
    // onblocked (another open connection) resolves too — the reload below
    // closes every connection, so a blocked delete finishes on next load.
    req.onblocked = () => resolve()
  })))
  if ('caches' in window) {
    try { const keys = await caches.keys(); await Promise.all(keys.map(k => caches.delete(k))) } catch { /* ignore */ }
  }
  if ('serviceWorker' in navigator) {
    try { const regs = await navigator.serviceWorker.getRegistrations(); await Promise.all(regs.map(r => r.unregister())) } catch { /* ignore */ }
  }
  location.href = location.pathname // drop the hash too, land on a clean boot
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
