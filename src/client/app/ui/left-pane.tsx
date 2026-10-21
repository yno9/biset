// The left pane: one row per counterparty (a group chat is its own), newest first, each opening to
// the threads shared with them; a filter; the pane's collapse and width; keyboard navigation.
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useStore } from '../react/store.ts'
import { DIDCOMM_GROUP_THREAD_PREFIX } from './message/message-view.ts'
import { displayName } from './did-display.ts'
import { avatarColor, previewText } from './format.ts'
import { hamburgerTrigger } from './hamburger-menu.tsx'
import { showComposePage, hideAccountPage, hideComposePage, hideConfigPage } from './pages/index.ts'
import { HamburgerDots, PaneToggleIcons, togglePane } from './right-col.tsx'
import { isNarrow, patchShell, shell } from './stores.ts'
import { counterpartLabel, groupMembersLabel, latestOf, type InboxRow } from './thread-model.ts'
import { useSelf, useThreads } from './use-threads.ts'

// The keyboard cursor and hover focus only mean something where there is a pointer and a keyboard.
const navFocusEnabled = (): boolean => window.innerWidth > 574

function fmtThreadTs(ts: number): string {
  if (!ts) return ''
  const d = new Date(ts)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

// A DIDComm message's from/from_name is always the raw DID: a bare username is the right length for
// a name repeated once per row.
const shortSenderLabel = (name: string): string => name.startsWith('did:') ? displayName(name) : name

type NavItem = { kind: 'inbox'; key: string } | { kind: 'thread'; key: string; rowKey: string }

/** Opens a thread and leaves the left pane (on a narrow screen the pane is a column in front). */
function openThread(threadKey: string): void {
  hideAccountPage(); hideConfigPage(); hideComposePage()
  patchShell({ focusedThreadKey: threadKey, showLeft: false })
}

/** Opens a row: its threads listed under it, and the newest one open (unless `focusThread` is off). */
function toggleAccordion(row: InboxRow | undefined, key: string, focusThread = true): void {
  const { expandedInboxKeys } = shell.get()
  if (expandedInboxKeys.has(key)) {
    patchShell({ expandedInboxKeys: new Set([...expandedInboxKeys].filter(k => k !== key)), lpFocusedKey: `inbox:${key}` })
    return
  }
  const expanded = new Set(expandedInboxKeys).add(key)
  if (focusThread && row) {
    patchShell({ expandedInboxKeys: expanded, lpFocusedKey: `thread:${row.groups[0]!.key}` })
    openThread(row.groups[0]!.key)
  } else patchShell({ expandedInboxKeys: expanded })
}

function Row({ row, label, avatarSubject, unread, current, focusedItem, activeThreadKey, expanded, visible, onNavigate }: {
  row: InboxRow; label: string; avatarSubject: string; unread: boolean; current: boolean; focusedItem: NavItem | undefined
  activeThreadKey: string | undefined; expanded: boolean; visible: boolean; onNavigate: (item: NavItem) => void
}) {
  const latest = latestOf(row.groups[0]!)
  const hoverFired = useRef(false)
  // With a keyboard/pointer cursor (wide screens) a thread row is lit where the cursor is; without
  // one, it is the open thread's row that is lit.
  const keyboard = shell.get().lpFocusedKey !== null && navFocusEnabled()
  const focusThread = (key: string) => keyboard
    ? focusedItem?.kind === 'thread' && focusedItem.key === key
    : key === activeThreadKey
  const rowFocused = keyboard && focusedItem?.kind === 'inbox' && focusedItem.key === row.key
  const classes = ['lp-item', current ? 'current' : '', rowFocused ? 'focused' : ''].filter(Boolean).join(' ')
  return (
    <a className={classes} href="#" data-inbox-key={row.key} style={visible ? undefined : { display: 'none' }}
      onClick={event => {
        event.preventDefault()
        // Narrow: a tap always opens the row's newest thread, whatever the accordion says: there's no
        // room for an inline thread list on a single-column screen. Wide: the row is the accordion
        // toggle, and expanding it also opens the newest thread underneath.
        if (isNarrow()) { patchShell({ lpFocusedKey: `inbox:${row.key}` }); openThread(row.groups[0]!.key); return }
        toggleAccordion(row, row.key)
      }}>
      <div className="lp-inner"
        onMouseEnter={() => { hoverFired.current = false }}
        onMouseLeave={() => { hoverFired.current = false }}
        // Wide screen: moving the pointer over a row switches to it. The rightmost 10% (the toggle
        // button) is left out so reaching for ▾/◂ doesn't navigate out from under the pointer.
        onMouseMove={event => {
          if (hoverFired.current || !navFocusEnabled()) return
          const rect = event.currentTarget.getBoundingClientRect()
          if (event.clientX > rect.right - rect.width * 0.1) return
          hoverFired.current = true
          onNavigate({ kind: 'inbox', key: row.key })
        }}>
        <div className="lp-avatar" style={{ background: avatarColor(avatarSubject) }}>{avatarSubject.charAt(0).toUpperCase()}{unread ? <div className="unread-dot" /> : null}</div>
        <div className="lp-info">
          <div className="lp-name">{label}</div>
          <div className="lp-preview">{previewText(latest.body)}</div>
        </div>
        <button className="lp-thread-toggle" tabIndex={-1}
          onClick={event => { event.preventDefault(); event.stopPropagation(); toggleAccordion(row, row.key, false) }}>{expanded ? '▾' : '◂'}</button>
      </div>
      <div className="lp-thread-list" style={{ display: expanded ? 'block' : 'none' }}>
        {expanded ? row.groups.map(group => (
          <div key={group.key} className={focusThread(group.key) ? 'lp-thread-row focused' : 'lp-thread-row'} data-thread-key={group.key}
            onClick={event => { event.preventDefault(); event.stopPropagation(); onNavigate({ kind: 'thread', key: group.key, rowKey: row.key }) }}
            onMouseEnter={() => { if (navFocusEnabled()) onNavigate({ kind: 'thread', key: group.key, rowKey: row.key }) }}>
            <span className="lp-thread-row-title">{group.subject || '(no title)'}</span>
            <span className="lp-thread-row-ts">{fmtThreadTs(latestOf(group).ts)}</span>
          </div>
        )) : null}
      </div>
    </a>
  )
}

export function LeftPane() {
  const { rows, focused } = useThreads()
  const self = useSelf()
  const { search, expandedInboxKeys, lpFocusedKey } = useStore(shell)
  const [searchHidden, setSearchHidden] = useState(false)
  const pane = useRef<HTMLElement>(null)
  const lastScrollTop = useRef(0)
  const searchBox = useRef<HTMLInputElement>(null)
  const activeThreadKey = focused?.key
  const query = search.toLowerCase().trim()

  const described = rows.map(row => {
    const latestGroup = row.groups[0]!
    const latest = latestOf(latestGroup)
    // A group chat is its own row, named by its title or, with none, by who is in it: "who the
    // latest message came from" would give it the same label as the 1:1 row with that sender.
    const isGroup = row.key.startsWith(DIDCOMM_GROUP_THREAD_PREFIX)
    // A row is who it is with (the threads, with their subjects, are under it): a group by its title, else its members; a person by name.
    const label = isGroup ? latestGroup.subject || groupMembersLabel(row.groups, self) || 'no title' : counterpartLabel(row.groups, self) || shortSenderLabel(latest.from_name || latest.from || 'no title')
    return {
      row, label,
      avatarSubject: isGroup ? label : shortSenderLabel(latest.from_name || latest.from || label),
      unread: row.groups.some(g => g.messages.some(p => p.msg.seen !== true)),
      visible: !query || label.toLowerCase().includes(query) || row.groups.some(g => (g.subject ?? '').toLowerCase().includes(query)),
    }
  })

  // The rows the keyboard walks, top to bottom: an open row contributes its threads, else itself.
  const navItems: NavItem[] = described.filter(d => d.visible).flatMap(({ row }): NavItem[] =>
    expandedInboxKeys.has(row.key) && row.groups.length ? row.groups.map(g => ({ kind: 'thread', key: g.key, rowKey: row.key })) : [{ kind: 'inbox', key: row.key }])
  const focusedItem = ((): NavItem | undefined => {
    if (lpFocusedKey?.startsWith('thread:')) return navItems.find(item => item.kind === 'thread' && item.key === lpFocusedKey.slice(7))
    const rowKey = lpFocusedKey?.startsWith('inbox:') ? lpFocusedKey.slice(6) : (activeThreadKey ? rows.find(r => r.groups.some(g => g.key === activeThreadKey))?.key : undefined)
    if (!rowKey) return undefined
    return navItems.find(item => item.kind === 'inbox' && item.key === rowKey) ?? navItems.find(item => item.kind === 'thread' && item.rowKey === rowKey)
  })()

  const latest = useRef({ rows, navItems, focusedItem })
  latest.current = { rows, navItems, focusedItem }

  /** A pointer or key lands on an item: it takes the cursor and its thread opens. */
  const navigate = (item: NavItem) => {
    const { rows: current } = latest.current
    if (item.kind === 'thread') { patchShell({ lpFocusedKey: `thread:${item.key}` }); openThread(item.key) }
    else {
      patchShell({ lpFocusedKey: `inbox:${item.key}` })
      const row = current.find(r => r.key === item.key)
      if (row) openThread(row.groups[0]!.key)
    }
  }

  // The cursor stays in view.
  useLayoutEffect(() => {
    if (lpFocusedKey) pane.current?.querySelector('.lp-item.focused, .lp-thread-row.focused')?.scrollIntoView({ block: 'nearest' })
  }, [lpFocusedKey])

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key === 'b') { event.preventDefault(); togglePane(); return }
      // Arrow/Space/→ work wherever the cursor is, except in a real input (the filter box counts when it is empty).
      const active = document.activeElement
      if (active instanceof HTMLTextAreaElement || (active instanceof HTMLInputElement && active !== searchBox.current)) return
      const { rows: currentRows, navItems: items, focusedItem: focusedNow } = latest.current
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault()
        if (!items.length) return
        const cur = focusedNow ? items.findIndex(i => i.kind === focusedNow.kind && i.key === focusedNow.key) : -1
        const next = event.key === 'ArrowDown' ? (cur < items.length - 1 ? cur + 1 : cur) : Math.max(cur - 1, 0)
        const target = items[next]
        if (target && !(focusedNow && target.kind === focusedNow.kind && target.key === focusedNow.key)) { searchBox.current?.blur(); navigate(target) }
      } else if (event.key === ' ') {
        if (focusedNow?.kind === 'inbox') { event.preventDefault(); toggleAccordion(currentRows.find(r => r.key === focusedNow.key), focusedNow.key) }
        else if (focusedNow?.kind === 'thread') {
          // The first thread acts as "the row plus its newest thread": Space closes the accordion.
          const row = currentRows.find(r => r.key === focusedNow.rowKey)
          if (row && row.groups[0]!.key === focusedNow.key) { event.preventDefault(); toggleAccordion(row, row.key) }
        }
      } else if (event.key === 'ArrowRight') {
        event.preventDefault()
        const area = document.querySelector<HTMLTextAreaElement>('.reply-box textarea')
        if (area) { area.focus(); area.setSelectionRange(area.value.length, area.value.length) }
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [])

  // The pane's width is the user's: dragged on the handle, remembered.
  useEffect(() => {
    try { const saved = localStorage.getItem('lp-width'); if (saved) document.documentElement.style.setProperty('--lp-width', `${saved}px`) } catch { /* private browsing */ }
  }, [])
  const startResize = (event: React.MouseEvent) => {
    const startX = event.clientX
    const startWidth = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--lp-width')) || 300
    const move = (e: MouseEvent) => {
      const width = Math.max(200, Math.min(600, startWidth + e.clientX - startX))
      document.documentElement.style.setProperty('--lp-width', `${width}px`)
      try { localStorage.setItem('lp-width', String(width)) } catch { /* private browsing */ }
    }
    const up = () => {
      document.removeEventListener('mousemove', move)
      document.removeEventListener('mouseup', up)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.addEventListener('mousemove', move)
    document.addEventListener('mouseup', up)
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    event.preventDefault()
  }

  const hiddenClass = searchHidden ? 'lp-search-hidden' : undefined
  return (
    <>
      <aside id="left-pane" ref={pane} onScroll={event => {
        // The filter bar slides away while the list is scrolled down, and back when it scrolls up.
        const top = event.currentTarget.scrollTop
        setSearchHidden(top > 0 && top > lastScrollTop.current)
        lastScrollTop.current = top
      }}>
        <div id="left-pane-header">
          <button id="main-toggle" aria-label="Toggle pane" className={hiddenClass} onClick={togglePane}><PaneToggleIcons /></button>
          <div id="lp-search-wrap" className={hiddenClass}>
            <input id="lp-search" ref={searchBox} type="search" placeholder="/ for commands" autoComplete="off" value={search}
              onChange={event => patchShell({ search: event.target.value })}
              onKeyDown={event => { if (event.key === 'Escape') patchShell({ lpFocusedKey: null, search: '' }) }} />
          </div>
          <button id="lp-hamburger-left" aria-label="menu" className={hiddenClass} {...hamburgerTrigger}><HamburgerDots id="lp-hamburger-left-icon" /></button>
        </div>
        <div id="left-list-wrap">
          <div id="left-list">
            {described.map(d => (
              <Row key={d.row.key} {...d} current={d.row.groups.some(g => g.key === activeThreadKey)} focusedItem={focusedItem}
                activeThreadKey={activeThreadKey} expanded={expandedInboxKeys.has(d.row.key)} onNavigate={navigate} />
            ))}
          </div>
        </div>
        <div id="lp-resize-handle" onMouseDown={startResize} />
      </aside>
      <button id="lp-compose-fab" className="compose-fab" type="button" aria-label="Compose" title="Compose" onClick={showComposePage}>
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 20h9" /><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z" /></svg>
      </button>
    </>
  )
}
