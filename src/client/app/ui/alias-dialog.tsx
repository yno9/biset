// Changing the address (the DID's host) inside the page: dito's alias screen opens in a dialog over
// this page. The new name and the Passphrase are typed in dito's frame; this page only learns the new DID.
import { useEffect, useRef } from 'react'
import { createStore, useStore } from '../react/store.ts'
import { ditoEmbedOrigin, mountDito } from '../../identity/wallet/dito-embed.ts'

interface Change { origin: string; resolve(moved: { did: string, host: string }): void; reject(error: Error): void }

const change = createStore<Change | undefined>(undefined)

/** Asks dito, in a dialog, to move this browser's identity to another address. */
export function requestAddressChange(): Promise<{ did: string, host: string }> {
  const origin = ditoEmbedOrigin()
  if (!origin) return Promise.reject(new Error('Changing the address needs the embedded wallet.'))
  return new Promise((resolve, reject) => {
    if (change.get()) { reject(new Error('The address is already being changed.')); return }
    change.set({ origin, resolve, reject })
  })
}

function Open({ origin, resolve, reject }: Change) {
  const dialog = useRef<HTMLDialogElement>(null)
  const frame = useRef<HTMLIFrameElement>(null)
  useEffect(() => {
    const el = dialog.current!
    let settled = false
    let embed: { dispose(): void } | undefined
    const settle = (done: () => void) => { if (settled) return; settled = true; clearTimeout(fallback); embed?.dispose(); change.set(undefined); done() }
    el.addEventListener('close', () => settle(() => reject(new Error('Cancelled.'))))
    // Shown once dito has laid its screen out, not as an empty box that fills in.
    const reveal = () => { if (!settled && !el.open) el.showModal() }
    const fallback = setTimeout(reveal, 8000)
    mountDito(frame.current!, origin, 'alias', { resized: height => { if (height >= 40) reveal() } })
      .then(mounted => { embed = mounted; return mounted.moveAlias() })
      .then(moved => settle(() => resolve(moved)), error => settle(() => reject(error instanceof Error ? error : new Error(String(error)))))
  }, [])
  return (
    <dialog ref={dialog} style={{ margin: 'auto', padding: 0, border: '1px solid color-mix(in srgb,CanvasText 20%,transparent)', borderRadius: 12, width: 'min(420px,92vw)', background: 'Canvas', color: 'CanvasText', overflow: 'hidden' }}>
      <iframe ref={frame} title="did.md Wallet" style={{ display: 'block', width: '100%', height: 240, border: 0, colorScheme: 'normal' }} />
    </dialog>
  )
}

export function AliasDialog() {
  const current = useStore(change)
  return current ? <Open {...current} /> : null
}
