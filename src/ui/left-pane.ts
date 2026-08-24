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

  for (const id of ['main-toggle', 'main-toggle-right', 'main-toggle-cmd']) {
    document.getElementById(id)?.addEventListener('click', togglePane)
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
}
