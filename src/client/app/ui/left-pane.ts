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
import { groupMessages } from './message/message-view.ts'
import type { ThreadGroup } from './message/message-view.ts'
import { avatarStyle, esc, previewText } from './format.ts'
import { getFocusedThreadKey, inboxKeyOf, render, setFocusedThreadKey } from './thread.ts'
import { hideAccountPage, hideConfigPage, inAccountMode, inConfigMode, showAccountPage, showConfigPage } from './account-page.ts'
import { hideComposePage, inComposeMode, showComposePage } from './compose-page.ts'
import { labelForDid } from './did-display.ts'

function latestOf(group: ThreadGroup) {
  return group.messages[group.messages.length - 1]!.msg
}

/** src.bak's own left-pane row (makeLpItem) was one per InboxSummary (a
 * server-side per-contact summary), with a `.lp-thread-toggle` accordion
 * underneath it listing every JMAP thread that contact had -- multiple
 * subject-lines with the same person, not multiple people. This rewrite has
 * no InboxSummary (no relay/multi-account layer to summarize), so rows were
 * ported 1:1 off ThreadGroup instead (this file's own header comment) and
 * the accordion was dropped outright along with it. Restoring it needs the
 * same grouping key back -- thread.ts's inboxKeyOf (participantsOf) is
 * exactly isk()'s `contact` field, so grouping ThreadGroups by it here
 * reconstructs the same row shape src.bak had, one row per counterparty with
 * every thread that shares it underneath (found live, 2026-09-09: the
 * toggle button was simply missing, along with any way to reach a second
 * thread with someone once one existed). */
interface InboxRow {
  key: string
  /** Newest thread first -- same ordering src.bak's renderThreadAccordion used. */
  groups: ThreadGroup[]
}

function inboxRows(): InboxRow[] {
  const byKey = new Map<string, ThreadGroup[]>()
  for (const g of groupMessages()) {
    const key = inboxKeyOf(g)
    const list = byKey.get(key)
    if (list) list.push(g)
    else byKey.set(key, [g])
  }
  return [...byKey.entries()].map(([key, groups]) => ({
    key,
    groups: groups.sort((a, b) => latestOf(b).ts - latestOf(a).ts),
  }))
}

// src.bak's fmtThreadTs (ui/left-pane.ts), ported verbatim -- the
// .lp-thread-row-ts label, distinct from thread.ts's fmtRelDate (past-row,
// a different row shape) and left-pane's own relative-time preview.
function fmtThreadTs(ts: number): string {
  if (!ts) return ''
  const d = new Date(ts)
  return String(d.getMonth() + 1).padStart(2, '0') + '/'
    + String(d.getDate()).padStart(2, '0') + ' '
    + String(d.getHours()).padStart(2, '0') + ':'
    + String(d.getMinutes()).padStart(2, '0')
}

// Persists across renderLeftList rebuilds, same lifetime as src.bak's own
// module-level _expandedInboxKeys.
const expandedInboxKeys = new Set<string>()

// ── Keyboard nav ──────────────────────────────────────────────────────────
//
// Ported from src.bak's own lpNavIdx/_lpFocusedKey/lpNavItems/focusedNavEl/
// syncNavFocus/lpFocusEl/lpNavClear (ui/left-pane.ts) -- pure DOM/state, no
// backend dependency, so this half of the old file ports as-is. Left out:
// the `/`-prefixed command-palette branch inside the old search-box keydown
// handler (applyLpSearch's own header comment already drops that half, this
// rewrite has no #lp-commands page set to open).

let lpNavIdx = -1
/** 'inbox:<InboxRow.key>' | 'thread:<ThreadGroup.key>' | null. */
let lpFocusedKey: string | null = null

// .focused doubles as the keyboard-nav cursor, applied from every render
// path below (toggleAccordion, lpFocusEl, applyLpSearch indirectly via
// renderLeftList) -- there's no keyboard to navigate with on a touchscreen,
// and re-applying it on every re-render flashed an unrelated row/inbox
// background after taps in src.bak (2026-07-something, same reasoning its
// own navFocusEnabled comment gives). Guarding every call site is
// whack-a-mole; guard the class application here instead.
function navFocusEnabled(): boolean {
  return window.innerWidth > 574
}

// Flat ordered list. Expanded accordions contribute thread rows (header
// visually grouped with thread1 via CSS :has); collapsed/empty contribute
// the header row.
function lpNavItems(): HTMLElement[] {
  const result: HTMLElement[] = []
  for (const inbox of document.querySelectorAll<HTMLElement>('#left-list .lp-item')) {
    if (inbox.style.display === 'none') continue
    const tl = inbox.querySelector<HTMLElement>('.lp-thread-list')
    const rows = tl && tl.style.display !== 'none'
      ? [...tl.querySelectorAll<HTMLElement>('.lp-thread-row')]
      : []
    if (rows.length) for (const row of rows) result.push(row)
    else result.push(inbox)
  }
  return result
}

// Resolve lpFocusedKey to the current DOM element (recomputed fresh each
// call). With no explicit key yet, falls back to whichever inbox the
// currently-open thread belongs to (src.bak's own `currentInbox` fallback --
// this rewrite has no separate currentInbox, so it's derived from
// getFocusedThreadKey() instead).
function focusedNavEl(items: HTMLElement[]): HTMLElement | undefined {
  if (lpFocusedKey?.startsWith('thread:')) {
    const tk = lpFocusedKey.slice('thread:'.length)
    return items.find(el => el.dataset.threadKey === tk)
  }
  const activeThreadKey = getFocusedThreadKey()
  const key = lpFocusedKey?.startsWith('inbox:')
    ? lpFocusedKey.slice('inbox:'.length)
    : (activeThreadKey ? inboxRows().find(r => r.groups.some(g => g.key === activeThreadKey))?.key : undefined)
  if (!key) return undefined
  return items.find(el => el.dataset.inboxKey === key)
    ?? items.find(el =>
      el.closest<HTMLElement>('.lp-item')?.dataset.inboxKey === key
      && el === el.closest<HTMLElement>('.lp-item')?.querySelector('.lp-thread-list .lp-thread-row'))
}

function syncNavFocus(): void {
  document.querySelectorAll<HTMLElement>('#left-list .lp-item, #left-list .lp-thread-row')
    .forEach(el => el.classList.remove('focused'))
  const items = lpNavItems()
  const target = focusedNavEl(items)
  if (target) {
    if (navFocusEnabled()) target.classList.add('focused')
    lpNavIdx = items.indexOf(target)
  } else {
    lpNavIdx = -1
  }
}

// Set focus on el: update key, apply CSS, trigger the corresponding
// navigation. Single entry point for "user hover/click/keyboard intent to
// view a thread" (src.bak's own header comment on this function).
function lpFocusEl(el: HTMLElement): void {
  document.querySelectorAll<HTMLElement>('#left-list .lp-item, #left-list .lp-thread-row')
    .forEach(item => item.classList.remove('focused'))
  if (navFocusEnabled()) el.classList.add('focused')
  el.scrollIntoView({ block: 'nearest' })
  if (el.classList.contains('lp-thread-row')) {
    const threadKey = el.dataset.threadKey!
    lpFocusedKey = 'thread:' + threadKey
    openThread(threadKey)
  } else {
    const key = el.dataset.inboxKey!
    lpFocusedKey = 'inbox:' + key
    const row = inboxRows().find(r => r.key === key)
    if (row) openThread(row.groups[0]!.key)
  }
  syncNavFocus()
}

function lpNavClear(): void {
  lpNavItems().forEach(el => el.classList.remove('focused'))
  lpFocusedKey = null
  lpNavIdx = -1
}

// Same DID-vs-display-name reasoning as thread.ts's createMsgEl: a DIDComm
// message's from/from_name is always the raw DID string, and a bare
// username (labelForDid: "d157") is the right length for a name repeated
// once per row in a list, the same as a message bubble's sender name --
// the fuller did:webvh:d157.biset.md form is for the one-per-thread header
// pill only (thread.ts's displayParticipantsOf).
function shortSenderLabel(name: string): string {
  return name.startsWith('did:') ? labelForDid(name) : name
}

/** Opens the given thread and leaves the left pane, same three steps every
 * navigation path below needs (mobile row tap, desktop thread-row click,
 * hamburger menu entries elsewhere in this file). */
function openThread(threadKey: string): void {
  if (inAccountMode()) hideAccountPage()
  if (inConfigMode()) hideConfigPage()
  if (inComposeMode()) hideComposePage()
  setFocusedThreadKey(threadKey)
  render()
  renderLeftList()
  // src.bak's switchInbox (ui/left-pane.ts:363,387) unconditionally drops
  // show-left on every navigation through here, including re-opening the
  // already-open row -- on mobile's single-col nav-stack (section 26,
  // style.css) that class is what keeps the left pane the on-screen column;
  // without clearing it, opening a thread left the left pane in front and
  // the thread that just loaded behind it, unreachable (found live,
  // 2026-09-09: opening an inbox in single-column mode never navigated to
  // the right column).
  document.getElementById('app')?.classList.remove('show-left')
}

/** src.bak's toggleAccordionForItem (ui/left-pane.ts), adapted: the old
 * version's else-branch (`currentInbox` mismatch) called switchInbox first
 * because an unopened inbox's threads lived on a server this rewrite has no
 * client for -- every inbox's messages are already in the one local vault
 * here, so opening one is just picking which ThreadGroup is focused. */
function toggleAccordion(key: string, focusThread = true): void {
  if (expandedInboxKeys.has(key)) {
    expandedInboxKeys.delete(key)
    lpFocusedKey = 'inbox:' + key
    renderLeftList()
    syncNavFocus()
    return
  }
  expandedInboxKeys.add(key)
  const row = inboxRows().find(r => r.key === key)
  if (focusThread && row) {
    lpFocusedKey = 'thread:' + row.groups[0]!.key
    openThread(row.groups[0]!.key)
  } else {
    renderLeftList()
  }
  syncNavFocus()
}

/** The `.lp-thread-toggle`/`.lp-thread-list` accordion, ported from
 * src.bak's own makeLpItem/renderThreadAccordion (ui/left-pane.ts) --
 * one row per counterparty (InboxRow), expandable to the individual threads
 * shared with them. Left out of this port vs. the original: swipe-to-delete
 * and the avatar's inbox context menu (both need a delete/archive backend
 * this rewrite's local vault doesn't have yet). */
function makeLpItem(row: InboxRow, active: boolean, activeThreadKey: string | null): HTMLElement {
  const latestGroup = row.groups[0]!
  const latest = latestOf(latestGroup)
  const label = latestGroup.subject || shortSenderLabel(latest.from_name || latest.from || 'no title')
  const avatarSubject = shortSenderLabel(latest.from_name || latest.from || label)
  const unread = row.groups.some(g => g.messages.some(p => p.msg.seen !== true))
  const expanded = expandedInboxKeys.has(row.key)
  const a = document.createElement('a')
  a.className = 'lp-item' + (active ? ' current' : '')
  a.href = '#'
  a.dataset.inboxKey = row.key
  a.innerHTML = `
    <div class="lp-inner">
      <div class="lp-avatar" style="${avatarStyle(avatarSubject)}">${avatarSubject.charAt(0).toUpperCase()}${unread ? '<div class="unread-dot"></div>' : ''}</div>
      <div class="lp-info">
        <div class="lp-name">${esc(label)}</div>
        <div class="lp-preview">${esc(previewText(latest.body))}</div>
      </div>
      <button class="lp-thread-toggle" tabindex="-1">${expanded ? '▾' : '◂'}</button>
    </div>
    <div class="lp-thread-list" style="display:${expanded ? 'block' : 'none'}"></div>
  `

  const threadList = a.querySelector<HTMLElement>('.lp-thread-list')!
  if (expanded) {
    for (const g of row.groups) {
      const threadRow = document.createElement('div')
      threadRow.className = 'lp-thread-row' + (g.key === activeThreadKey ? ' focused' : '')
      threadRow.dataset.threadKey = g.key
      const title = document.createElement('span')
      title.className = 'lp-thread-row-title'
      title.textContent = g.subject || '(no title)'
      const ts = document.createElement('span')
      ts.className = 'lp-thread-row-ts'
      ts.textContent = fmtThreadTs(latestOf(g).ts)
      threadRow.append(title, ts)
      threadRow.addEventListener('click', e => {
        e.preventDefault()
        e.stopPropagation()
        lpFocusEl(threadRow)
      })
      // src.bak's own hover-to-focus on a thread row, desktop only (mouseenter
      // never fires from a touch tap, so this is a no-op on mobile already).
      threadRow.addEventListener('mouseenter', () => { if (navFocusEnabled()) lpFocusEl(threadRow) })
      threadList.appendChild(threadRow)
    }
  }

  a.querySelector<HTMLButtonElement>('.lp-thread-toggle')?.addEventListener('click', e => {
    e.preventDefault()
    e.stopPropagation()
    toggleAccordion(row.key, false)
  })

  // Two-column desktop: moving the mouse over a row switches to it, same as
  // src.bak's own `.lp-inner` mousemove handler -- the rightmost 10% (the
  // toggle button) is excluded so reaching for ▾/◂ doesn't also navigate
  // out from under the pointer. `_hoverFired` re-arms on mouseleave so
  // re-entering the row (not just moving within it) can trigger again, and
  // lpFocusEl itself (called for both the header and any already-expanded
  // thread row) is what actually opens the thread -- no separate "first
  // row" lookup needed here since it always resolves the newest one.
  const innerEl = a.querySelector<HTMLElement>('.lp-inner')
  if (innerEl) {
    let hoverFired = false
    innerEl.addEventListener('mouseenter', () => { hoverFired = false })
    innerEl.addEventListener('mouseleave', () => { hoverFired = false })
    innerEl.addEventListener('mousemove', e => {
      if (hoverFired || !navFocusEnabled()) return
      const rect = innerEl.getBoundingClientRect()
      if (e.clientX > rect.right - rect.width * 0.1) return
      hoverFired = true
      lpFocusEl(a)
    })
  }

  a.addEventListener('click', e => {
    e.preventDefault()
    // Mobile: tapping the row always opens its newest thread, regardless of
    // accordion state -- there's no room for an inline thread list on a
    // single-column screen (src.bak's own `window.innerWidth <= 574` branch).
    if (window.innerWidth <= 574) {
      lpFocusedKey = 'inbox:' + row.key
      openThread(latestGroup.key)
      return
    }
    // Desktop: the row itself is purely the accordion toggle -- expanding it
    // also opens the newest thread underneath (one click does both, same as
    // src.bak's toggleAccordionForItem(a) with its default focusThread=true);
    // collapsing an already-open row leaves whatever's on screen alone.
    toggleAccordion(row.key)
  })
  return a
}

export function renderLeftList(): void {
  const list = document.getElementById('left-list')
  if (!list) return
  list.innerHTML = ''
  const rows = inboxRows().sort((a, b) => latestOf(b.groups[0]!).ts - latestOf(a.groups[0]!).ts)
  const activeThreadKey = getFocusedThreadKey()
  for (const row of rows) list.appendChild(makeLpItem(row, row.groups.some(g => g.key === activeThreadKey), activeThreadKey))
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
  document.getElementById('lp-compose-fab')?.addEventListener('click', () => showComposePage())

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

  const lpSearch = document.getElementById('lp-search') as HTMLInputElement | null
  lpSearch?.addEventListener('input', () => { lpNavIdx = -1; applyLpSearch() })

  // Search box: Escape only (src.bak's own `/`-command-palette branch is
  // dropped, per this function's header comment).
  lpSearch?.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      lpNavClear()
      lpSearch.value = ''
      applyLpSearch()
    }
  })

  // Document-level nav: Arrow/Space work regardless of search focus, ported
  // verbatim from src.bak's own document-level keydown handler.
  document.addEventListener('keydown', e => {
    // Ignore when typing in a real input (but allow when lp-search is
    // focused and empty).
    const active = document.activeElement
    const isTextInput = active instanceof HTMLTextAreaElement
      || (active instanceof HTMLInputElement && active !== lpSearch)
    if (isTextInput) return

    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      const items = lpNavItems()
      if (!items.length) return
      const focused = focusedNavEl(items)
      const cur = focused ? items.indexOf(focused) : -1
      const next = e.key === 'ArrowDown'
        ? (cur < items.length - 1 ? cur + 1 : cur)
        : Math.max(cur - 1, 0)
      const target = items[next]
      if (target && target !== focused) {
        lpSearch?.blur()
        lpFocusEl(target)
      }
    } else if (e.key === ' ') {
      const items = lpNavItems()
      const el = focusedNavEl(items)
      if (el?.classList.contains('lp-item')) {
        e.preventDefault()
        toggleAccordion(el.dataset.inboxKey!)
      } else if (el?.classList.contains('lp-thread-row')) {
        // thread1 (first row) acts as "thread0+1" unit -- Space closes the accordion.
        const inboxEl = el.closest<HTMLElement>('.lp-item')
        if (inboxEl && el === inboxEl.querySelector('.lp-thread-list .lp-thread-row')) {
          e.preventDefault()
          toggleAccordion(inboxEl.dataset.inboxKey!)
        }
      }
    } else if (e.key === 'ArrowRight') {
      e.preventDefault()
      const ta = document.querySelector<HTMLTextAreaElement>('#focused-thread-card textarea, .reply-box textarea')
      if (ta) { ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length) }
    }
  })

  setupHamburgerMenu()
}

/** #lp-hamburger-menu's hover/click open-near-trigger behaviour -- pure DOM
 * positioning, no backend involved. `/account` now opens the minimal
 * identity page (account-page.ts); `/config` still has nowhere to go (no
 * corresponding settings backend), so that item just closes the menu. */
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
      if (item.dataset.page === '/account') showAccountPage()
      else if (item.dataset.page === '/config') showConfigPage()
    })
  }
  document.addEventListener('click', () => menu.classList.remove('open'))
}
