import {
  sessions, addSession, setCurrentInbox, currentInbox, loadStoredAccounts,
} from './context.ts'
import { initSession, initPGPForSession, loadInboxSummaries } from './app.ts'
import type { InboxSummary } from './types.ts'
import { inboxToHash, parseInboxHash } from './utils.ts'
import { showApp, startPolling, fetchMessages } from './ui/shell.ts'
import { loadLeftInboxes, switchInbox, showMenuPage, setupLeftPane, refreshAccountsList, menuTargetInbox, openComposeTo } from './ui/left-pane.ts'
import { setupNewUserPage, showNewUserPage } from './ui/account-create.ts'
import { showUserLanding } from './ui/user-landing.ts'
import { primeAvatarCache } from './deltachat/avatar.ts'
import { advertiseAllOwnAvatars } from './ap/avatar.ts'

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

async function init() {
  const accounts = loadStoredAccounts()
  const rawHash = location.hash

  // Prime the DeltaChat avatar cache so synchronous UI lookups have data.
  await primeAvatarCache()

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

// scroll buttons
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
    const pastH = past && outer.contains(past) ? past.offsetHeight : 0
    outer?.scrollTo({ top: pastH, behavior: 'smooth' })
  })
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
