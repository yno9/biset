// The menu behind the avatar/⋮ buttons (left pane and thread header): opens near the button on hover
// or click, closes a moment after the pointer leaves, or on any click elsewhere.
import { useEffect } from 'react'
import { createStore, useStore } from '../react/store.ts'
import { showAccountPage } from './pages/index.ts'
import { patchShell } from './stores.ts'

const menu = createStore({ open: false, top: 0, right: 0 })
let hideTimer: ReturnType<typeof setTimeout> | undefined

const cancelHide = (): void => { clearTimeout(hideTimer) }
const scheduleHide = (): void => { hideTimer = setTimeout(() => menu.set(current => ({ ...current, open: false })), 200) }
const close = (): void => menu.set(current => ({ ...current, open: false }))
const showNear = (trigger: HTMLElement): void => {
  const rect = trigger.getBoundingClientRect()
  menu.set({ open: true, top: rect.bottom + 4, right: window.innerWidth - rect.right })
}

/** The handlers a button needs to open the menu. */
export const hamburgerTrigger = {
  onMouseEnter: (event: { currentTarget: HTMLElement }): void => { cancelHide(); showNear(event.currentTarget) },
  onMouseLeave: scheduleHide,
  onClick: (event: { stopPropagation(): void; currentTarget: HTMLElement }): void => {
    event.stopPropagation()
    if (menu.get().open) close()
    else showNear(event.currentTarget)
  },
}

const PAGES = [{ page: '/account', label: 'account', show: showAccountPage }]

export function HamburgerMenu() {
  const { open, top, right } = useStore(menu)
  useEffect(() => {
    document.addEventListener('click', close)
    return () => document.removeEventListener('click', close)
  }, [])
  return (
    <div id="lp-hamburger-menu" className={open ? 'open' : undefined} style={{ top, right, left: 'auto' }} onMouseEnter={cancelHide} onMouseLeave={scheduleHide}>
      {PAGES.map(({ page, label, show }) => (
        <button key={page} className="lp-hmenu-item" data-page={page}
          onClick={event => { event.stopPropagation(); close(); patchShell({ showLeft: false }); show() }}>{label}</button>
      ))}
    </div>
  )
}
