// Ported at the DOM-shape level from src.bak/ui/left-pane.ts (5417 lines,
// makeLpItem/renderLeftInboxes) -- cut to only #left-list rendering and
// click-to-open, per PLAN.md §7's plan. Not a literal port: the old rows were
// keyed on InboxSummary, a per-contact summary across possibly many
// relays/sessions (multi-relay JamClient concept this rewrite doesn't have).
// This rewrite has one identity's one local vault, already thread-grouped by
// mail/message-view.ts's groupMessages() -- so rows are keyed on ThreadGroup
// instead, reusing the same `.lp-item`/`.lp-avatar`/`.lp-info` DOM shape (and
// CSS) the old rows used.
//
// setupLeftPane/applyLpSearch below (2026-08-24, restoring src.bak's real
// index.html/style.css as-is per user direction -- see PLAN.md §7's
// progress log) port the parts of the old setupLeftPane (a single ~4300-
// line function) that are pure DOM/localStorage state with no backend
// dependency: pane collapse/resize, the scroll-hide search bar, and a
// plain substring filter over the rendered rows. The other ~95% of that
// function -- account/device management, DID document viewer, custom
// domain, prerotation, PGP, ActivityPub, Web Push, multi-relay account
// switching, the full compose/command-palette page set -- has no
// corresponding backend here at all (this rewrite has one identity, one
// local vault, no relay/DID-document/PGP/AP/push layer), so none of it can
// actually be wired up; those DOM elements stay present (HTML/CSS
// untouched) but inert, no event listeners attached.
import { groupMessages } from '../mail/message-view.ts'
import type { ThreadGroup } from '../mail/message-view.ts'
import { avatarStyle, esc, previewText } from './format.ts'
import { getFocusedThreadKey, render, setFocusedThreadKey } from './thread.ts'

function latestOf(group: ThreadGroup) {
  return group.messages[group.messages.length - 1]!.msg
}

function makeLpItem(group: ThreadGroup, active: boolean): HTMLElement {
  const latest = latestOf(group)
  const label = group.subject || latest.from_name || latest.from || 'no title'
  const avatarSubject = latest.from_name || latest.from || label
  const unread = group.messages.some(p => p.msg.seen !== true)
  const a = document.createElement('a')
  a.className = 'lp-item' + (active ? ' current' : '')
  a.href = '#'
  a.dataset.threadKey = group.key
  a.innerHTML = `
    <div class="lp-inner">
      <div class="lp-avatar" style="${avatarStyle(avatarSubject)}">${avatarSubject.charAt(0).toUpperCase()}${unread ? '<div class="unread-dot"></div>' : ''}</div>
      <div class="lp-info">
        <div class="lp-name">${esc(label)}</div>
        <div class="lp-preview">${esc(previewText(latest.body))}</div>
      </div>
    </div>
  `
  a.addEventListener('click', e => {
    e.preventDefault()
    setFocusedThreadKey(group.key)
    render()
    renderLeftList()
  })
  return a
}

export function renderLeftList(): void {
  const list = document.getElementById('left-list')
  if (!list) return
  list.innerHTML = ''
  const groups = [...groupMessages()].sort((a, b) => latestOf(b).ts - latestOf(a).ts)
  const active = getFocusedThreadKey()
  for (const group of groups) list.appendChild(makeLpItem(group, group.key === active))
  applyLpSearch()
}

/** Plain substring filter over the rendered rows (src.bak's own version
 * also handled `/`-prefixed command-palette input; that half is dropped,
 * this rewrite has no #lp-commands page set to open). */
export function applyLpSearch(): void {
  const query = ((document.getElementById('lp-search') as HTMLInputElement | null)?.value ?? '').toLowerCase().trim()
  const items = [...document.querySelectorAll<HTMLElement>('#left-list .lp-item')]
  let visible = 0
  for (const el of items) {
    const name = el.querySelector('.lp-name')?.textContent?.toLowerCase() ?? ''
    const show = !query || name.includes(query)
    el.style.display = show ? '' : 'none'
    if (show) visible++
  }
  const empty = document.getElementById('lp-empty')
  if (empty) empty.style.display = (!query && items.length > 0 && visible === 0) ? 'block' : 'none'
}

function togglePane(): void {
  const app = document.getElementById('app')
  if (!app) return
  if (app.classList.contains('show-left')) {
    app.classList.remove('show-left')
  } else if (app.classList.contains('single-col')) {
    app.classList.remove('single-col')
    try { localStorage.setItem('lp-open', '1') } catch { /* private browsing */ }
  } else if (window.innerWidth <= 574) {
    app.classList.add('show-left')
  } else {
    app.classList.add('single-col')
    try { localStorage.setItem('lp-open', '0') } catch { /* private browsing */ }
  }
}

let _setup = false

/** Pane collapse/resize + scroll-hide search bar + the plain search filter
 * -- the pure-DOM/localStorage slice of src.bak's setupLeftPane, see this
 * file's header for what's deliberately left unwired. */
export function setupLeftPane(): void {
  if (_setup) return
  _setup = true
  const app = document.getElementById('app')
  // Load-bearing, not decoration: #left-pane/#header/#main-toggle's CSS is
  // all scoped under #app.lp-enabled (style.css) -- without this class none
  // of that renders at all, no matter what state single-col/show-left are
  // in. Missed porting this the first time (2026-08-24), which is why the
  // left column and its toggle button were both invisible.
  app?.classList.add('lp-enabled')

  for (const id of ['main-toggle', 'main-toggle-right', 'main-toggle-cmd']) {
    document.getElementById(id)?.addEventListener('click', togglePane)
  }
  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'b') { e.preventDefault(); togglePane() }
  })

  // Mobile: swipe right anywhere in the conversation column to reveal the
  // inbox list. Direction is locked early (a few px of movement) rather
  // than only at touchend, same as src.bak's own reasoning -- a diagonal
  // touch judged only at the end both scrolls the message list vertically
  // AND is judged a swipe, which reads as the screen wobbling.
  {
    const rightCol = document.getElementById('right-col')
    let startX = 0, startY = 0, tracking = false, lockedAxis: 'x' | 'y' | null = null
    rightCol?.addEventListener('touchstart', e => {
      if (window.innerWidth > 574) { tracking = false; return }
      tracking = !!app && !app.classList.contains('show-left')
      lockedAxis = null
      startX = e.touches[0]!.clientX
      startY = e.touches[0]!.clientY
    }, { passive: true })
    rightCol?.addEventListener('touchmove', e => {
      if (!tracking) return
      const dx = e.touches[0]!.clientX - startX
      const dy = e.touches[0]!.clientY - startY
      if (!lockedAxis) {
        if (Math.abs(dx) < 10 && Math.abs(dy) < 10) return
        lockedAxis = Math.abs(dx) > Math.abs(dy) * 1.5 ? 'x' : 'y'
      }
      if (lockedAxis === 'x') e.preventDefault()
    }, { passive: false })
    rightCol?.addEventListener('touchend', e => {
      if (!tracking) return
      tracking = false
      const dx = e.changedTouches[0]!.clientX - startX
      if (lockedAxis === 'x' && dx > 70) app?.classList.add('show-left')
    }, { passive: true })
  }

  if (window.innerWidth > 574) {
    if (localStorage.getItem('lp-open') === '1') app?.classList.remove('single-col')
    else app?.classList.add('single-col')
  }
  const savedLpWidth = localStorage.getItem('lp-width')
  if (savedLpWidth) document.documentElement.style.setProperty('--lp-width', savedLpWidth + 'px')

  const resizeHandle = document.getElementById('lp-resize-handle')
  if (resizeHandle) {
    let startX = 0, startWidth = 0
    const onMouseMove = (e: MouseEvent) => {
      const w = Math.max(200, Math.min(600, startWidth + e.clientX - startX))
      document.documentElement.style.setProperty('--lp-width', w + 'px')
      localStorage.setItem('lp-width', String(w))
    }
    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    resizeHandle.addEventListener('mousedown', e => {
      startX = e.clientX
      startWidth = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--lp-width')) || 300
      document.addEventListener('mousemove', onMouseMove)
      document.addEventListener('mouseup', onMouseUp)
      document.body.style.cursor = 'col-resize'
      document.body.style.userSelect = 'none'
      e.preventDefault()
    })
  }

  const leftPane = document.getElementById('left-pane')
  const searchWrap = document.getElementById('lp-search-wrap')
  const mainToggle = document.getElementById('main-toggle')
  const hamburgerLeft = document.getElementById('lp-hamburger-left')
  let lastScrollTop = 0
  leftPane?.addEventListener('scroll', () => {
    const top = leftPane.scrollTop
    const hidden = top > 0 && top > lastScrollTop
    lastScrollTop = top
    searchWrap?.classList.toggle('lp-search-hidden', hidden)
    mainToggle?.classList.toggle('lp-search-hidden', hidden)
    hamburgerLeft?.classList.toggle('lp-search-hidden', hidden)
  }, { passive: true })

  document.getElementById('lp-search')?.addEventListener('input', applyLpSearch)

  setupHamburgerMenu()
}

/** #lp-hamburger-menu's hover/click open-near-trigger behaviour -- pure DOM
 * positioning, no backend involved, so it stays even though every item
 * inside it (#lp-hmenu-item -> showMenuPage('/account'|'/config')) has
 * nowhere to navigate to yet: this rewrite has neither page. Clicking one
 * just closes the menu instead of silently doing nothing, so hovering
 * doesn't look broken even though the destinations aren't there. */
function setupHamburgerMenu(): void {
  const menu = document.getElementById('lp-hamburger-menu')
  if (!menu) return
  let hideTimer: ReturnType<typeof setTimeout> | null = null

  const showNear = (trigger: HTMLElement) => {
    const rect = trigger.getBoundingClientRect()
    menu.style.top = (rect.bottom + 4) + 'px'
    menu.style.right = (window.innerWidth - rect.right) + 'px'
    menu.style.left = 'auto'
    menu.classList.add('open')
  }
  const scheduleHide = () => { hideTimer = setTimeout(() => menu.classList.remove('open'), 200) }
  const cancelHide = () => { if (hideTimer) { clearTimeout(hideTimer); hideTimer = null } }

  menu.addEventListener('mouseenter', cancelHide)
  menu.addEventListener('mouseleave', scheduleHide)

  for (const id of ['lp-hamburger', 'lp-hamburger-left']) {
    const btn = document.getElementById(id)
    if (!btn) continue
    btn.addEventListener('mouseenter', () => { cancelHide(); showNear(btn) })
    btn.addEventListener('mouseleave', scheduleHide)
    btn.addEventListener('click', e => {
      e.stopPropagation()
      if (menu.classList.contains('open')) menu.classList.remove('open')
      else showNear(btn)
    })
  }
  for (const item of document.querySelectorAll<HTMLElement>('.lp-hmenu-item')) {
    item.addEventListener('click', e => {
      e.stopPropagation()
      menu.classList.remove('open')
      document.getElementById('app')?.classList.remove('show-left')
    })
  }
  document.addEventListener('click', () => menu.classList.remove('open'))
}
