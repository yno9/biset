// "Scroll to top" / "Scroll to bottom": shown by how far the thread has been scrolled.
import { createStore, useStore } from '../react/store.ts'
import { topFloor } from './scroll.ts'

export interface ScrollUi {
  /** Far enough from the end of the thread to offer a jump to it. */
  bottomVisible: boolean
  topVisible: boolean
  /** The thread's title has scrolled out and the header's controls make room for the page. */
  titleHidden: boolean
}

export const scrollUi = createStore<ScrollUi>({ bottomVisible: false, topVisible: false, titleHidden: false })

/** Reads where #outer is scrolled to, into scrollUi. */
export function readScroll(outer: HTMLElement): void {
  const distFromBottom = outer.scrollHeight - outer.scrollTop - outer.clientHeight
  const bottomVisible = distFromBottom > 120
  const floor = topFloor(outer)
  const lastMsg = outer.querySelector('.t-messages')?.lastElementChild as HTMLElement | null
  const lastMsgVisible = !lastMsg || lastMsg.getBoundingClientRect().top < outer.getBoundingClientRect().bottom
  scrollUi.set({
    bottomVisible,
    topVisible: outer.scrollTop > floor + 40,
    titleHidden: outer.scrollTop > floor && bottomVisible && !lastMsgVisible,
  })
}

export function ScrollButtons() {
  const { bottomVisible, topVisible } = useStore(scrollUi)
  const outer = () => document.getElementById('outer')
  return (
    <>
      <button id="scroll-to-top" aria-label="Scroll to top" className={[topVisible ? 'visible' : '', bottomVisible ? 'above-bottom' : ''].filter(Boolean).join(' ') || undefined}
        onClick={() => { const el = outer(); if (el) el.scrollTo({ top: topFloor(el), behavior: 'smooth' }) }}>
        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 5.5L13.5 11h-11L8 5.5z" /></svg>
      </button>
      <button id="scroll-to-bottom" aria-label="Scroll to bottom" className={bottomVisible ? 'visible' : undefined}
        onClick={() => { const el = outer(); if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' }) }}>
        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 10.5L2.5 5h11L8 10.5z" /></svg>
      </button>
    </>
  )
}
