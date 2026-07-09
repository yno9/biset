import {
  sessions, addSession, setCurrentInbox, currentInbox, loadStoredAccounts,
} from './context.ts'
import { initSession, initPGPForSession, loadInboxSummaries } from './app.ts'
import type { InboxSummary } from './types.ts'
import { inboxToHash, parseInboxHash, isProgrammaticScroll, markProgrammaticScroll } from './utils.ts'
import { showApp, startPolling, fetchMessages } from './ui/shell.ts'
import { loadLeftInboxes, switchInbox, showMenuPage, setupLeftPane, refreshAccountsList, menuTargetInbox, openComposeTo } from './ui/left-pane.ts'
import { setupNewUserPage, showNewUserPage } from './ui/account-create.ts'
import { showUserLanding } from './ui/user-landing.ts'
import { primeAvatarCache } from './deltachat/avatar.ts'
import { advertiseAllOwnAvatars } from './ap/avatar.ts'
import { loadFromCache } from './store/cache.ts'
import { loadFromIDB as loadQuerystateFromIDB } from './jmap/querystate.ts'

// ── Hash routing helpers ───────────────────────────────────────────────────────
// Inbox hash build/parse lives in utils (inboxToHash / parseInboxHash) so the
// left pane's switchInbox and this router encode permalinks identically.

function menuHashFromHash(hash: string): string | null {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash
  if (!raw || raw.includes('/')) return null
  return raw.startsWith('/') ? raw : '/' + raw
}

// `#compose/<addr>` opens the compose page with To pre-filled — a shareable link
// to start a message to someone.
function composeArgFromHash(hash: string): string | null {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash
  if (!raw.startsWith('compose/')) return null
  const addr = raw.slice('compose/'.length)
  try { return addr ? decodeURIComponent(addr) : null } catch { return addr || null }
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
  const accounts = loadStoredAccounts()
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

  // Fire-and-forget PGP init (kek only available on fresh envelope login, not here)
  // sessions.forEach(s => initPGPForSession(s))

  // Determine initial inbox from hash or first available
  const inboxes = await loadInboxSummaries()

  let target: InboxSummary | null = null

  const hashParts = parseInboxHash(rawHash)
  if (hashParts) {
    target = inboxes.find(i =>
      i.user === hashParts.user &&
      i.mailbox === hashParts.mailbox &&
      i.contact === hashParts.contact,
    ) ?? null
  }

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
  if (!rawHash || hashParts) {
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
    const { activeSession } = await import('./context.ts')
    const { getInboxEmails, emailToMsg } = await import('./app.ts')
    const sess = activeSession()
    if (!sess) return
    const selfAddr = sess.jmapAccountId || sess.account.email
    const emails = getInboxEmails(ci.mailbox, ci.contact, selfAddr, sess.account.email)
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
  const parts = parseInboxHash(hash)
  if (!parts) return
  const inboxes = await loadInboxSummaries()
  const found = inboxes.find(i =>
    i.user === parts.user && i.mailbox === parts.mailbox && i.contact === parts.contact,
  )
  if (found) switchInbox(found)
})

// scroll buttons + reply-dock auto hide/show
{
  const outer = document.getElementById('outer')
  const btn = document.getElementById('scroll-to-bottom')
  const btnTop = document.getElementById('scroll-to-top')
  let lastScrollTop = outer?.scrollTop ?? 0
  outer?.addEventListener('scroll', () => {
    const distFromBottom = outer.scrollHeight - outer.scrollTop - outer.clientHeight
    const bottomVisible = distFromBottom > 120
    btn?.classList.toggle('visible', bottomVisible)
    const past = document.getElementById('past-threads')
    const pastH = past && outer.contains(past) ? past.offsetHeight : 0
    btnTop?.classList.toggle('visible', outer.scrollTop > pastH + 40)
    btnTop?.classList.toggle('above-bottom', bottomVisible)

    // Safety net: however dock-hidden got set, being at the bottom of the
    // conversation should always show the reply box — self-heals a stuck
    // state instead of requiring a thread switch to reset it.
    if (!bottomVisible) document.getElementById('reply-dock')?.classList.remove('dock-hidden')

    // Scrolling up (toward older messages) stows the reply box for more
    // reading room; scrolling down (toward the newest message) brings it
    // back. Only for scrolls we didn't trigger ourselves (scrollToFocused,
    // these buttons, sendReply's auto-scroll all call markProgrammaticScroll
    // first) — mobile momentum keeps firing 'scroll' events for an
    // unpredictable stretch after the finger lifts, so there's no reliable
    // fixed "recent touch" window to key off instead. A small delta
    // threshold avoids flicker from tiny trackpad jitter.
    const delta = outer.scrollTop - lastScrollTop
    const dock = document.getElementById('reply-dock')
    if (dock && !isProgrammaticScroll() && !dock.classList.contains('group-expanded') && Math.abs(delta) > 4) {
      dock.classList.toggle('dock-hidden', delta < 0)
    }
    lastScrollTop = outer.scrollTop
  }, { passive: true })
  btn?.addEventListener('click', () => {
    markProgrammaticScroll()
    outer?.scrollTo({ top: outer.scrollHeight, behavior: 'smooth' })
  })
  btnTop?.addEventListener('click', () => {
    const past = document.getElementById('past-threads')
    const pastH = past && outer?.contains(past) ? past.offsetHeight : 0
    markProgrammaticScroll()
    outer?.scrollTo({ top: pastH, behavior: 'smooth' })
  })
}

// Left-pane header auto hide/show — disabled for now (turned out not to be
// wanted), kept here commented so it's easy to bring back. Same mechanism as
// the reply-dock above (translateY + markProgrammaticScroll-gated direction),
// mirrored for the top edge.
// {
//   const leftPane = document.getElementById('left-pane')
//   const header = document.getElementById('left-pane-header')
//   let lastLpScrollTop = leftPane?.scrollTop ?? 0
//   leftPane?.addEventListener('scroll', () => {
//     if (leftPane.scrollTop < 24) header?.classList.remove('lph-hidden')
//     const delta = leftPane.scrollTop - lastLpScrollTop
//     if (header && !isProgrammaticScroll() && Math.abs(delta) > 4) {
//       header.classList.toggle('lph-hidden', delta > 0)
//     }
//     lastLpScrollTop = leftPane.scrollTop
//   }, { passive: true })
// }

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
  const dock = document.getElementById('reply-dock')
  if (dock?.children.length) {
    const outer = document.getElementById('outer')
    if (outer) outer.style.paddingBottom = dock.offsetHeight + 'px'
  }
  scrollToFocused()
})

{
  const dock = document.getElementById('reply-dock')
  if (dock && typeof ResizeObserver !== 'undefined') {
    let _prevDockH = dock.offsetHeight
    new ResizeObserver(async () => {
      const outer = document.getElementById('outer')
      const newH = dock.offsetHeight
      if (outer && newH) {
        const delta = newH - _prevDockH
        outer.style.paddingBottom = newH + 'px'
        if (delta !== 0) {
          const past = document.getElementById('past-threads')
          const pastH = past && outer.contains(past) ? past.offsetHeight : 0
          if (outer.scrollTop > pastH) outer.scrollTop += delta
        }
      }
      _prevDockH = newH
      const { syncDockPosition } = await import('./ui/thread.ts')
      syncDockPosition()
    }).observe(dock)
  }
}

init()
