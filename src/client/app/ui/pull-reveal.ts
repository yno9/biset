// The strip of the inbox's other threads above the open one (#past-threads) is closed; pulling the conversation down past its top
// edge, against resistance, opens it. Let go early and it springs back; pull far enough and it stays open until scrolled away.

const OPEN_AT = 0.5 // of the strip's height
const RESISTANCE = 0.45
const QUIET_MS = 160 // a wheel gesture ends when no more wheel events arrive for this long
const COOLDOWN_MS = 450 // trackpad inertia after a release must not start a new pull
const ARM_MS = 250 // wheel events must pause this long at the top before a pull may begin: the scroll that reached the top is spent

export interface PullReveal {
  /** Closes the strip at once (another thread was opened). */
  reset(): void
  detach(): void
}

export function attachPullReveal(outer: HTMLElement): PullReveal {
  const strip = (): HTMLElement | null => document.getElementById('past-threads')
  const natural = (): number => strip()?.querySelector<HTMLElement>('.past-inner')?.offsetHeight ?? 0
  let raw = 0
  let open = false
  let quiet: number | undefined
  let cooldownUntil = 0
  let touchStartY: number | undefined
  // A pull may begin only from rest at the top. The wheel gesture that scrolled the conversation up to its top (its inertia
  // included) does not count: it stops there, and the next, separate scroll is the one that opens the strip.
  let armed = true
  let armTimer: number | undefined
  const disarm = (): void => {
    armed = false
    window.clearTimeout(armTimer)
    armTimer = window.setTimeout(() => { armed = outer.scrollTop <= 0 }, ARM_MS)
  }

  const show = (height: number, animate: boolean): void => {
    const el = strip()
    if (!el) return
    el.classList.toggle('snapping', animate)
    el.style.height = `${height}px`
  }
  const pulled = (): number => Math.min(natural(), raw * RESISTANCE)
  const release = (): void => {
    window.clearTimeout(quiet)
    const height = natural()
    open = height > 0 && pulled() >= height * OPEN_AT
    raw = 0
    cooldownUntil = Date.now() + COOLDOWN_MS
    show(open ? height : 0, true)
  }

  const onWheel = (event: WheelEvent): void => {
    // Something nearer the pointer took this scroll (the island moving between threads): it is not a pull on the conversation.
    if (event.defaultPrevented) { disarm(); return }
    if (open || Date.now() < cooldownUntil || natural() === 0) return
    if (raw === 0) {
      if (!armed || outer.scrollTop > 0 || event.deltaY >= 0) { disarm(); return }
    }
    event.preventDefault()
    raw = Math.max(0, raw - event.deltaY)
    show(pulled(), false)
    window.clearTimeout(quiet)
    quiet = window.setTimeout(release, QUIET_MS)
  }
  const onTouchStart = (event: TouchEvent): void => { touchStartY = !open && outer.scrollTop <= 0 ? event.touches[0]!.clientY : undefined }
  const onTouchMove = (event: TouchEvent): void => {
    if (touchStartY === undefined || natural() === 0) return
    const dy = event.touches[0]!.clientY - touchStartY
    if (dy <= 0 && raw === 0) return
    event.preventDefault()
    raw = Math.max(0, dy)
    show(pulled(), false)
  }
  const onTouchEnd = (): void => { if (touchStartY !== undefined && raw > 0) release(); touchStartY = undefined }
  // Scrolled down until the open strip is out of sight: it closes, and the view keeps its place.
  const onScroll = (): void => {
    if (!open) return
    const height = natural()
    if (outer.scrollTop < height) return
    open = false
    show(0, false)
    outer.scrollTop -= height
  }

  outer.addEventListener('wheel', onWheel, { passive: false })
  outer.addEventListener('touchstart', onTouchStart, { passive: true })
  outer.addEventListener('touchmove', onTouchMove, { passive: false })
  outer.addEventListener('touchend', onTouchEnd, { passive: true })
  outer.addEventListener('scroll', onScroll, { passive: true })
  return {
    reset() { window.clearTimeout(quiet); raw = 0; open = false; show(0, false) },
    detach() {
      window.clearTimeout(quiet)
      window.clearTimeout(armTimer)
      outer.removeEventListener('wheel', onWheel)
      outer.removeEventListener('touchstart', onTouchStart)
      outer.removeEventListener('touchmove', onTouchMove)
      outer.removeEventListener('touchend', onTouchEnd)
      outer.removeEventListener('scroll', onScroll)
    },
  }
}
