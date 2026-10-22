// A tooltip for elements that carry `data-tip` (in place of `title`, whose bubble the browser draws and CSS cannot
// style). One bubble for the whole page, fixed-positioned under the element, so no ancestor's overflow clips it.
import { useEffect, useState } from 'react'

const DELAY_MS = 350
const MAX_WIDTH = 280

export function Tooltip() {
  const [tip, setTip] = useState<{ text: string; top: number; left: number } | undefined>()
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined
    let target: Element | null = null
    const hide = () => { clearTimeout(timer); target = null; setTip(undefined) }
    const over = (event: PointerEvent) => {
      const element = (event.target as Element | null)?.closest?.('[data-tip]') ?? null
      if (element === target) return
      hide()
      const text = element?.getAttribute('data-tip')
      if (!element || !text) return
      target = element
      timer = setTimeout(() => {
        const rect = element.getBoundingClientRect()
        setTip({ text, top: rect.bottom + 6, left: Math.max(8, Math.min(rect.left, window.innerWidth - MAX_WIDTH - 8)) })
      }, DELAY_MS)
    }
    document.addEventListener('pointerover', over)
    document.addEventListener('pointerdown', hide)
    document.addEventListener('scroll', hide, true)
    return () => { clearTimeout(timer); document.removeEventListener('pointerover', over); document.removeEventListener('pointerdown', hide); document.removeEventListener('scroll', hide, true) }
  }, [])
  if (!tip) return null
  return <div className="tip" role="tooltip" style={{ top: tip.top, left: tip.left, maxWidth: MAX_WIDTH }}>{tip.text}</div>
}
