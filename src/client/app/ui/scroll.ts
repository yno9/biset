// The thread column's scroll geometry: #outer scrolls, #reply-dock floats over its bottom, and the
// thread's last message is left at the top of the view when it is taller than the view. Plain DOM
// measuring, called by the right column (ui/right-col.tsx) after it renders.

const THREAD_BOTTOM_GAP = 14

const $ = (id: string): HTMLElement | null => document.getElementById(id)

/** The height of the past-threads strip: scrolling up stops there, not at 0. */
export function topFloor(outer: HTMLElement): number {
  const past = $('past-threads')
  return past && outer.contains(past) ? past.offsetHeight : 0
}

/** The reply dock is position:fixed, so it doesn't shrink #outer: #outer's bottom padding has to be
 * kept equal to the dock's height by hand, or the last message ends up under it. Synchronous:
 * reading offsetHeight forces layout, so callers that adjust scroll right after see the padding. */
export function syncDockPosition(): void {
  const outer = $('outer')
  const h = $('reply-dock')?.offsetHeight ?? 0
  if (outer) outer.style.paddingBottom = h ? `${h}px` : '0'
  document.documentElement.style.setProperty('--dock-h', h ? `${h}px` : '0px')
  const titleRow = $('thread-title-row')
  if (titleRow) document.documentElement.style.setProperty('--thread-title-h', `${titleRow.offsetHeight}px`)
}

/** #scroll-spacer pads the end of the thread so a short thread still scrolls up to the strip. */
function updateScrollSpacer(): void {
  const outer = $('outer')
  const spacer = $('scroll-spacer')
  if (!outer || !spacer) return
  spacer.style.height = '0'
  const floor = topFloor(outer)
  const overflow = outer.scrollHeight - outer.clientHeight
  spacer.style.height = `${overflow <= floor ? floor - overflow : THREAD_BOTTOM_GAP}px`
}

/** Scrolls to the end of the open thread, or to the top of its last message when that message is
 * taller than the view. Two frames later: the thread's layout has to settle first. */
export function scrollToFocused(): void {
  requestAnimationFrame(() => requestAnimationFrame(() => {
    updateScrollSpacer()
    const outer = $('outer')
    if (!outer) return
    let target = outer.scrollHeight - outer.clientHeight
    const messages = outer.querySelectorAll('.t-msg')
    const last = messages[messages.length - 1] as HTMLElement | undefined
    if (last) {
      const titleRow = $('thread-title-row')
      const titleH = titleRow && outer.contains(titleRow) ? titleRow.offsetHeight : 0
      const stickyTop = titleRow ? parseFloat(getComputedStyle(titleRow).top) || 0 : 0
      const viewTop = titleH + stickyTop
      if (last.offsetHeight > outer.clientHeight - viewTop) {
        const lastTopInOuter = last.getBoundingClientRect().top - outer.getBoundingClientRect().top + outer.scrollTop
        target = Math.max(topFloor(outer), lastTopInOuter - viewTop)
      }
    }
    outer.scrollTop = target
  }))
}
