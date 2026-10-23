// A tooltip for elements that carry `data-tip` (in place of `title`, whose bubble the browser draws and CSS cannot
// style). One bubble for the whole page, fixed-positioned under the element, so no ancestor's overflow clips it.
// It is centred under the element, then moved just far enough to stay on the screen: measured at its own width, so an
// element at the edge of the screen (the icons on the right of a card) keeps its bubble beside it.
import { useEffect, useLayoutEffect, useRef, useState } from 'react'

const DELAY_MS = 350
const MAX_WIDTH = 280
const MARGIN = 8

/** The left edge of a bubble `width` wide, centred on `centre`, kept `MARGIN` inside a screen `screen` wide. */
export function bubbleLeft(centre: number, width: number, screen: number): number {
  return Math.max(MARGIN, Math.min(centre - width / 2, screen - width - MARGIN))
}

export function Tooltip() {
  const [tip, setTip] = useState<{ text: string; top: number; centre: number } | undefined>()
  const [left, setLeft] = useState<number | undefined>()
  const bubble = useRef<HTMLDivElement>(null)
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined
    let target: Element | null = null
    const hide = () => { clearTimeout(timer); target = null; setLeft(undefined); setTip(undefined) }
    const over = (event: PointerEvent) => {
      const element = (event.target as Element | null)?.closest?.('[data-tip]') ?? null
      if (element === target) return
      hide()
      const text = element?.getAttribute('data-tip')
      if (!element || !text) return
      target = element
      timer = setTimeout(() => {
        const rect = element.getBoundingClientRect()
        setTip({ text, top: rect.bottom + 6, centre: rect.left + rect.width / 2 })
      }, DELAY_MS)
    }
    document.addEventListener('pointerover', over)
    document.addEventListener('pointerdown', hide)
    document.addEventListener('scroll', hide, true)
    return () => { clearTimeout(timer); document.removeEventListener('pointerover', over); document.removeEventListener('pointerdown', hide); document.removeEventListener('scroll', hide, true) }
  }, [])
  // Drawn unseen first, to know its width; then put where it belongs, before it is painted.
  useLayoutEffect(() => {
    if (tip && bubble.current) setLeft(bubbleLeft(tip.centre, bubble.current.offsetWidth, window.innerWidth))
  }, [tip])
  if (!tip) return null
  return <div ref={bubble} className="tip" role="tooltip" style={{ top: tip.top, left: left ?? 0, maxWidth: MAX_WIDTH, visibility: left === undefined ? 'hidden' : 'visible' }}>{tip.text}</div>
}
