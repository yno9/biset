// Asks for the display name in a card over the page, drawn like the alias change's (approve-dialog.tsx), both from embed-card.css
// (copied from dito at build time): the same box, a click outside it or Esc closes it. The field opens with a new random name, and the
// button on its right makes another. Resolves with the text in the field (empty: the caller makes a random one), or `null` when closed.
import { useEffect, useRef } from 'react'
import { createStore, useStore } from '../../react/store.ts'
import { randomDisplayName } from './default-name.ts'

const request = createStore<{ current: string; resolve(name: string | null): void } | undefined>(undefined)

export function requestDisplayName(current: string): Promise<string | null> {
  return new Promise(resolve => {
    request.get()?.resolve(null)
    request.set({ current, resolve })
  })
}

export function DisplayNameDialog() {
  const open = useStore(request)
  const dialog = useRef<HTMLDialogElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const answered = useRef(false)

  useEffect(() => {
    if (!open) return
    const el = dialog.current!
    answered.current = false
    const answer = (name: string | null) => {
      if (answered.current) return
      answered.current = true
      el.removeEventListener('close', onClose)
      el.removeEventListener('click', onOutside)
      if (el.open) el.close()
      request.set(undefined)
      open.resolve(name)
    }
    const onClose = () => answer(null)
    // The form fills the card (the padding is inside it), so a click on the dialog itself is a click on its backdrop.
    const onOutside = (event: MouseEvent) => { if (event.target === el) el.close() }
    const onSubmit = (event: Event) => { event.preventDefault(); answer(input.current!.value) }
    const form = el.querySelector('form')!
    el.addEventListener('close', onClose)
    el.addEventListener('click', onOutside)
    form.addEventListener('submit', onSubmit)
    input.current!.value = randomDisplayName()
    el.showModal()
    input.current!.select()
    return () => { form.removeEventListener('submit', onSubmit); answer(null) }
  }, [open])

  return (
    <dialog ref={dialog} id="display-name-dialog" className="ec-dialog">
      <form className="ec-card">
        <label htmlFor="display-name-input" className="ec-title">Display name</label>
        <div className="ec-field">
          <input ref={input} id="display-name-input" type="text" autoComplete="off" spellCheck={false} maxLength={200} />
          <button type="button" id="display-name-reload" className="ec-field-action" aria-label="New random name" data-tip="New random name"
            onClick={() => { input.current!.value = randomDisplayName(); input.current!.focus(); input.current!.select() }}>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M23 4v6h-6" /><path d="M1 20v-6h6" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></svg>
          </button>
        </div>
        <div className="ec-hint">Shown to the people you write to.</div>
        <button type="submit" className="ec-button">Save</button>
      </form>
    </dialog>
  )
}
