// ── identity menu (dropdown) ────────────────────────────────────────────────
// Ported from src.bak/ui/left-pane.ts's openDropdownMenu/closeAccountMenu --
// anchored below-right of the button, closes on outside click/Escape.
export interface MenuItem { label: string; danger?: boolean; onClick: () => void }

let openMenuCleanup: (() => void) | null = null

function closeIdentityMenu(): void {
  openMenuCleanup?.()
  openMenuCleanup = null
}

export function openDropdownMenu(anchor: HTMLElement, items: MenuItem[]): void {
  closeIdentityMenu()
  const rect = anchor.getBoundingClientRect()
  const menu = document.createElement('div')
  menu.style.cssText = `position:fixed;top:${rect.bottom + 4}px;left:${Math.max(8, rect.right - 180)}px;width:180px;background:var(--bg);border:1px solid var(--border, rgba(128,128,128,0.25));border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,0.18);z-index:10000;padding:4px;font-size:14px`
  for (const item of items) {
    const b = document.createElement('button')
    b.type = 'button'
    b.style.cssText = `display:block;width:100%;text-align:left;padding:8px 12px;background:none;border:none;border-radius:6px;cursor:pointer;color:${item.danger ? '#ff3b30' : 'var(--text)'};font-size:14px`
    b.textContent = item.label
    b.addEventListener('mouseover', () => { b.style.background = 'rgba(128,128,128,0.12)' })
    b.addEventListener('mouseout', () => { b.style.background = 'none' })
    b.addEventListener('click', () => { closeIdentityMenu(); item.onClick() })
    menu.appendChild(b)
  }
  document.body.appendChild(menu)
  const onDocClick = (ev: MouseEvent) => {
    if (!menu.contains(ev.target as Node)) closeIdentityMenu()
  }
  const onKey = (ev: KeyboardEvent) => { if (ev.key === 'Escape') closeIdentityMenu() }
  setTimeout(() => document.addEventListener('click', onDocClick), 0)
  document.addEventListener('keydown', onKey)
  openMenuCleanup = () => {
    document.removeEventListener('click', onDocClick)
    document.removeEventListener('keydown', onKey)
    menu.remove()
  }
}
