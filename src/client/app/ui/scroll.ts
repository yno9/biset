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
  // Everything above the page in the flow: the island row (#conv-top) and, on the pages that have one, the title row.
  const headerH = ($('conv-top')?.offsetHeight ?? 0) + ($('thread-title-row')?.offsetHeight ?? 0)
  document.documentElement.style.setProperty('--thread-title-h', `${headerH}px`)
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

/** Puts the view where a freshly opened thread rests: at its end, or at the top of its last message when that message is
 * taller than the view. Returns where it put it. */
function snapToRest(): number | undefined {
  const outer = $('outer')
  if (!outer) return undefined
  // A new message has nothing to rest at the end of: the page is empty, and the view stays at the top (a snap left over from the page
  // before, the Notepad's say, must not carry it down by the few pixels the empty page overflows by).
  if ($('app')?.dataset.menuPage === '/compose') { outer.scrollTop = 0; return 0 }
  updateScrollSpacer()
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
  return outer.scrollTop
}

// Where the last snap left the view, and the timers that look again: the layout is not final when a thread opens (web fonts
// arrive, the header's lines settle), and a spacer worked out from the early layout would leave a short thread resting a few
// pixels down. Each look re-snaps only while the view is still where the snap put it, so a reader who has moved is left alone.
let restedAt: number | undefined
let lookAgain: number[] = []
function resnapIfUntouched(): void {
  const outer = $('outer')
  if (!outer || restedAt === undefined || Math.abs(outer.scrollTop - restedAt) > 2) return
  restedAt = snapToRest()
}
if (typeof document !== 'undefined') document.fonts?.addEventListener('loadingdone', resnapIfUntouched)

/** Scrolls to the end of the open thread, or to the top of its last message when that message is
 * taller than the view. Two frames later: the thread's layout has to settle first. */
export function scrollToFocused(): void {
  for (const timer of lookAgain) window.clearTimeout(timer)
  requestAnimationFrame(() => requestAnimationFrame(() => {
    restedAt = snapToRest()
    lookAgain = [250, 800].map(ms => window.setTimeout(resnapIfUntouched, ms))
  }))
}
