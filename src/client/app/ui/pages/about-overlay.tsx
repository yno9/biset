// What comail is, over the sign-up page: a few full-screen slides that change by sliding up and down (not by scrolling): the wheel, a swipe, the arrow
// keys and the dots on the side take one step at a time. The link to the source is at the bottom left. Esc and the cross close it.
import { useEffect, useRef, useState } from 'react'
import { GitHubIcon } from '../account/github-icon.tsx'

const SLIDES: readonly { title: string; text: string }[] = [
  { title: 'comail', text: 'Email, reimagined for privacy and identity.' },
  { title: 'Your mail stays with you', text: 'Everything is kept encrypted on your own devices. No server holds a permanent mailbox, or a history of your messages.' },
  { title: 'An identity of your own', text: 'Your address stands on an identity that you control, from a wallet that you choose. comail reads public documents and never writes them.' },
  { title: 'Mail and DIDComm, bridged', text: 'Write to anyone who has an email address. Between comail users, messages travel over DIDComm; a bridge carries them to and from ordinary mail.' },
  { title: 'Your devices, in step', text: 'Your devices keep each other up to date over the same channel, with no sync server. Your history leaves and comes back as plain files, and threads can live on disk as Markdown.' },
  { title: 'Open source', text: 'Read the code, or run your own.' },
]

const SOURCE_URL = 'https://github.com/yno9/biset'
/** Quiet time after a step, so that one turn of the wheel (or a swipe that goes on) is one slide. */
const STEP_MS = 800

export function AboutOverlay({ onClose }: { onClose: () => void }) {
  const [at, setAt] = useState(0)
  const root = useRef<HTMLDivElement>(null)
  const lockedUntil = useRef(0)
  const touchFrom = useRef<number | undefined>(undefined)

  const go = (to: number): void => {
    const next = Math.max(0, Math.min(SLIDES.length - 1, to))
    if (next === at || Date.now() < lockedUntil.current) return
    lockedUntil.current = Date.now() + STEP_MS
    setAt(next)
  }
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null
    root.current?.focus()
    return () => before?.focus?.()
  }, [])
  // The keys are taken first (on the window, before the page under the overlay sees them): the left pane has its own use of the arrows and the space, and
  // would otherwise move off to another page with them.
  useEffect(() => {
    const onKey = (event: KeyboardEvent): void => {
      if (event.metaKey || event.ctrlKey || event.altKey) return
      const step = ['ArrowDown', 'PageDown', ' '].includes(event.key) ? 1 : ['ArrowUp', 'PageUp'].includes(event.key) ? -1 : 0
      if (event.key === 'Escape') onClose()
      else if (step !== 0) go(at + step)
      else if (event.key === 'Home') go(0)
      else if (event.key === 'End') go(SLIDES.length - 1)
      else if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return
      event.preventDefault()
      event.stopPropagation()
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  })

  return (
    <div id="about" ref={root} role="dialog" aria-modal="true" aria-label="About comail" tabIndex={-1}
      onWheel={event => { if (Math.abs(event.deltaY) > 12) go(at + Math.sign(event.deltaY)) }}
      onTouchStart={event => { touchFrom.current = event.touches[0]?.clientY }}
      onTouchEnd={event => {
        const from = touchFrom.current
        const to = event.changedTouches[0]?.clientY
        touchFrom.current = undefined
        if (from !== undefined && to !== undefined && Math.abs(from - to) > 48) go(at + (from > to ? 1 : -1))
      }}>
      <div className="about-track" style={{ transform: `translateY(${-at * 100}%)` }}>
        {SLIDES.map((slide, index) => (
          <section key={slide.title} className="about-slide" data-active={index === at ? '' : undefined} aria-hidden={index === at ? undefined : true}>
            <h2>{slide.title}</h2>
            <p>{slide.text}</p>
          </section>
        ))}
      </div>
      <button type="button" id="about-close" aria-label="Close" onClick={onClose}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" /></svg>
      </button>
      <nav id="about-dots" aria-label="Slides">
        {SLIDES.map((slide, index) => <button key={slide.title} type="button" aria-label={`${index + 1}: ${slide.title}`} aria-current={index === at ? 'true' : undefined} onClick={() => go(index)} />)}
      </nav>
      <a id="about-github" href={SOURCE_URL} target="_blank" rel="noreferrer" aria-label="comail on GitHub"><GitHubIcon size={24} /></a>
    </div>
  )
}
