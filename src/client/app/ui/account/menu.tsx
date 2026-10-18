// A dropdown anchored below-right of the button that opened it; closes on a click elsewhere or Escape.
import { useEffect, useRef } from 'react'
import { createStore, useStore } from '../../react/store.ts'

export interface MenuItem { label: string; danger?: boolean; onClick: () => void }

const menu = createStore<{ top: number; left: number; items: MenuItem[] } | undefined>(undefined)
const close = (): void => menu.set(undefined)

export function openDropdownMenu(anchor: HTMLElement, items: MenuItem[]): void {
  const rect = anchor.getBoundingClientRect()
  menu.set({ top: rect.bottom + 4, left: Math.max(8, rect.right - 180), items })
}

export function DropdownMenu() {
  const open = useStore(menu)
  const root = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onClick = (event: MouseEvent) => { if (!root.current?.contains(event.target as Node)) close() }
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') close() }
    // After this click: the one that opened the menu must not close it at once.
    const armed = setTimeout(() => document.addEventListener('click', onClick), 0)
    document.addEventListener('keydown', onKey)
    return () => { clearTimeout(armed); document.removeEventListener('click', onClick); document.removeEventListener('keydown', onKey) }
  }, [open])
  if (!open) return null
  return (
    <div ref={root} className="dropdown-menu" style={{ top: open.top, left: open.left }}>
      {open.items.map(item => (
        <button key={item.label} type="button" className={item.danger ? 'dropdown-item danger' : 'dropdown-item'} onClick={() => { close(); item.onClick() }}>{item.label}</button>
      ))}
    </div>
  )
}
