// Asks for the display name in a card over the page, drawn like the alias change's (approve-dialog.tsx): the same box, a click
// outside it or Esc closes it. Resolves with the text typed (empty: the caller makes a new random name), or `null` when closed.
import { useEffect, useRef } from 'react'
import { createStore, useStore } from '../../react/store.ts'

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
    input.current!.value = open.current
    el.showModal()
    input.current!.select()
    return () => { form.removeEventListener('submit', onSubmit); answer(null) }
  }, [open])

  return (
    <dialog ref={dialog} id="display-name-dialog" style={{ margin: 'auto', padding: 0, border: '1px solid color-mix(in srgb,CanvasText 20%,transparent)', borderRadius: 12, width: 'min(420px,92vw)', background: 'Canvas', color: 'CanvasText', overflow: 'hidden' }}>
      <form style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: 20 }}>
        <label htmlFor="display-name-input" style={{ fontSize: 14, fontWeight: 600 }}>Display name</label>
        <input ref={input} id="display-name-input" type="text" autoComplete="off" spellCheck={false} maxLength={200}
          style={{ padding: '12px 16px', border: 0, borderRadius: 8, background: 'color-mix(in srgb,CanvasText 6%,transparent)', color: 'inherit', font: 'inherit', outline: 'none' }} />
        <div style={{ fontSize: 12, opacity: 0.6 }}>Shown to the people you write to. Empty makes a new random one.</div>
        <button type="submit" style={{ marginTop: 6, padding: '12px 18px', border: 0, borderRadius: 999, background: 'CanvasText', color: 'Canvas', font: 'inherit', cursor: 'pointer' }}>Save</button>
      </form>
    </dialog>
  )
}
