// What the islands at the top of the right column share: the up / down chevrons that move between the threads of an inbox (or the
// tabs of the account), and the scroll over the island that does the same.
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { RefObject } from 'react'

/** Moving between the threads of one inbox: up to the older one, down to the newer one. */
export interface ThreadNav { position: number; count: number; go(step: -1 | 1): void }

const NavChevron = ({ up }: { up: boolean }) => (
  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={up ? 'M3.5 10l4.5-4.5L12.5 10' : 'M3.5 6l4.5 4.5L12.5 6'} /></svg>
)

/** The pair of chevrons (#conv-nav), when there is more than one thread to move between. */
export function IslandNav({ nav }: { nav: ThreadNav | undefined }) {
  if (!nav || nav.count < 2) return null
  return (
    <div id="conv-nav" title={`${nav.position + 1} / ${nav.count}`}>
      <button type="button" aria-label="Older thread" disabled={nav.position === 0} onClick={() => nav.go(-1)}><NavChevron up /></button>
      <button type="button" aria-label="Newer thread" disabled={nav.position === nav.count - 1} onClick={() => nav.go(1)}><NavChevron up={false} /></button>
    </div>
  )
}

/** Scrolling over the island moves between the threads too: one step per scroll gesture (its inertia included). */
export function useIslandWheel(fields: RefObject<HTMLDivElement | null>, nav: ThreadNav | undefined): void {
  const navNow = useRef(nav)
  navNow.current = nav
  useEffect(() => {
    const el = fields.current
    if (!el) return
    let sum = 0
    let spent = false
    let quiet: number | undefined
    // Whose scroll this is: decided by where the gesture began. A scroll that began elsewhere (the page under the pointer moving
    // until the island arrives beneath it) is not the island's, however long it goes on.
    let lastWheelAt = 0
    let beganHere = false
    const watch = (event: WheelEvent): void => {
      if (event.timeStamp - lastWheelAt > 250) beganHere = el.contains(event.target as Node)
      lastWheelAt = event.timeStamp
    }
    const onWheel = (event: WheelEvent): void => {
      const current = navNow.current
      if (!current || current.count < 2 || !beganHere) return
      event.preventDefault()
      window.clearTimeout(quiet)
      quiet = window.setTimeout(() => { sum = 0; spent = false }, 250)
      if (spent) return
      sum += event.deltaY
      if (Math.abs(sum) < 30) return
      spent = true
      current.go(sum > 0 ? 1 : -1)
    }
    window.addEventListener('wheel', watch, { capture: true, passive: true })
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => { window.removeEventListener('wheel', watch, { capture: true }); el.removeEventListener('wheel', onWheel); window.clearTimeout(quiet) }
  }, [fields])
}

/** The other form of the island's navigation, for the account: its threads side by side as tabs, the open one underlined (the
 * underline is one element that slides to the chosen tab; it first appears already in place). The pointer over a tab picks it, as a
 * click does. */
export function IslandTabs<T extends string>({ tabs, current, onPick }: { tabs: readonly T[]; current: T; onPick: (tab: T) => void }) {
  const [bar, setBar] = useState<{ left: number; width: number }>()
  const buttons = useRef<Partial<Record<T, HTMLButtonElement | null>>>({})
  useLayoutEffect(() => {
    const measure = () => { const button = buttons.current[current]; if (button) setBar({ left: button.offsetLeft, width: button.offsetWidth }) }
    measure()
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [current])
  return (
    <nav className="island-tabs" role="tablist">
      {tabs.map(name => (
        <button key={name} ref={element => { buttons.current[name] = element }} type="button" role="tab" className="island-tab" aria-selected={current === name}
          onPointerEnter={event => { if (event.pointerType === 'mouse') onPick(name) }} onClick={() => onPick(name)}>{name}</button>
      ))}
      {bar ? <span className="island-tab-underline" style={{ left: bar.left, width: bar.width }} /> : null}
    </nav>
  )
}
