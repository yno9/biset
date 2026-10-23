// A card over the page that asks for one line of text, drawn like the alias change's (approve-dialog.tsx), both from embed-card.css
// (copied from dito at build time): the same box; a click outside it or Esc closes it. Used for the display name, the mediator's address
// and its onion address. Resolves with the text in the field when it is saved, or `null` when the card is closed.
import { useEffect, useRef } from 'react'
import { createStore, useStore } from '../../react/store.ts'

export interface TextRequest {
  title: string
  /** What the field starts with. */
  value: string
  hint?: string
  placeholder?: string
  button?: string
  /** A button on the right of the field that puts a new value in it (the display name's "another random one"). */
  reload?: { label: string; next(): string }
}
const request = createStore<(TextRequest & { resolve(text: string | null): void }) | undefined>(undefined)

export function requestText(options: TextRequest): Promise<string | null> {
  return new Promise(resolve => {
    request.get()?.resolve(null)
    request.set({ ...options, resolve })
  })
}

export function TextCardDialog() {
  const open = useStore(request)
  const dialog = useRef<HTMLDialogElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const answered = useRef(false)

  useEffect(() => {
    if (!open) return
    const el = dialog.current!
    answered.current = false
    const answer = (text: string | null) => {
      if (answered.current) return
      answered.current = true
      el.removeEventListener('close', onClose)
      el.removeEventListener('click', onOutside)
      if (el.open) el.close()
      request.set(undefined)
      open.resolve(text)
    }
    const onClose = () => answer(null)
    // The form fills the card (the padding is inside it), so a click on the dialog itself is a click on its backdrop.
    const onOutside = (event: MouseEvent) => { if (event.target === el) el.close() }
    const onSubmit = (event: Event) => { event.preventDefault(); answer(input.current!.value) }
    const form = el.querySelector('form')!
    el.addEventListener('close', onClose)
    el.addEventListener('click', onOutside)
    form.addEventListener('submit', onSubmit)
    input.current!.value = open.value
    el.showModal()
    input.current!.select()
    return () => { form.removeEventListener('submit', onSubmit); answer(null) }
  }, [open])

  return (
    <dialog ref={dialog} id="text-card-dialog" className="ec-dialog">
      <form className="ec-card">
        <label htmlFor="text-card-input" className="ec-title">{open?.title}</label>
        <div className="ec-field">
          <input ref={input} id="text-card-input" type="text" autoComplete="off" spellCheck={false} maxLength={2048} placeholder={open?.placeholder} />
          {open?.reload ? (
            <button type="button" id="text-card-reload" className="ec-field-action" aria-label={open.reload.label} data-tip={open.reload.label}
              onClick={() => { input.current!.value = open.reload!.next(); input.current!.focus(); input.current!.select() }}>
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M23 4v6h-6" /><path d="M1 20v-6h6" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></svg>
            </button>
          ) : null}
        </div>
        {open?.hint ? <div className="ec-hint">{open.hint}</div> : null}
        <button type="submit" className="ec-button">{open?.button ?? 'Save'}</button>
      </form>
    </dialog>
  )
}
