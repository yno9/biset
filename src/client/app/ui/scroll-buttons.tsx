// "Scroll to bottom": shown when the thread has been scrolled well away from its end, with how many messages lie below.
import { createStore, useStore } from '../react/store.ts'
import { topFloor } from './scroll.ts'

export interface ScrollUi {
  /** Far enough from the end of the thread to offer a jump to it. */
  bottomVisible: boolean
  /** Messages that start below the visible part of the thread. */
  below: number
  /** The thread's title has scrolled out and the header's controls make room for the page. */
  titleHidden: boolean
}

export const scrollUi = createStore<ScrollUi>({ bottomVisible: false, below: 0, titleHidden: false })

/** Reads where #outer is scrolled to, into scrollUi. */
export function readScroll(outer: HTMLElement): void {
  const distFromBottom = outer.scrollHeight - outer.scrollTop - outer.clientHeight
  const bottomVisible = distFromBottom > 120
  const floor = topFloor(outer)
  const lastMsg = outer.querySelector('.t-messages')?.lastElementChild as HTMLElement | null
  const lastMsgVisible = !lastMsg || lastMsg.getBoundingClientRect().top < outer.getBoundingClientRect().bottom
  // The reply box covers the foot of #outer: what is below its top edge is not yet in view.
  const viewBottom = document.getElementById('reply-dock')?.getBoundingClientRect().top ?? outer.getBoundingClientRect().bottom
  const below = [...outer.querySelectorAll('.t-msg')].filter(el => el.getBoundingClientRect().top >= viewBottom).length
  scrollUi.set({
    bottomVisible,
    below,
    titleHidden: outer.scrollTop > floor && bottomVisible && !lastMsgVisible,
  })
}

export function ScrollButtons() {
  const { bottomVisible, below } = useStore(scrollUi)
  return (
    <div id="scroll-island" className={bottomVisible ? 'visible' : undefined}>
      <button id="scroll-to-bottom" aria-label="Scroll to bottom"
        onClick={() => { const el = document.getElementById('outer'); if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' }) }}>
        {below > 0 ? <span>{below === 1 ? '1 message' : `${below} messages`}</span> : null}
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M3.5 6l4.5 4.5L12.5 6" /></svg>
      </button>
    </div>
  )
}
