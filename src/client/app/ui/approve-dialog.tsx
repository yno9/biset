// Approvals inside the page (identity/wallet/dito-embed.ts): a request that needs the Passphrase -- a
// DID document edit -- opens dito's approve screen in a dialog over this page, so the person never
// leaves it. The dialog only frames dito's screen; nothing typed there reaches this page.
import { useEffect, useRef } from 'react'
import { createStore, useStore } from '../react/store.ts'
import { useDidMdWalletApprover } from '../../identity/wallet/did-md-oauth.ts'
import { ditoEmbedOrigin, mountDito } from '../../identity/wallet/dito-embed.ts'

interface Approval { origin: string; request: string; resolve(response: URLSearchParams): void; reject(error: Error): void }

const approval = createStore<Approval | undefined>(undefined)

/** Approvals run in dito's frame where dito is a sibling origin; elsewhere they stay full-page. */
export function installDitoApprover(): void {
  const origin = ditoEmbedOrigin()
  if (!origin) return
  useDidMdWalletApprover(request => new Promise<URLSearchParams>((resolve, reject) => {
    if (approval.get()) { reject(new Error('Another approval is already open.')); return }
    approval.set({ origin, request, resolve, reject })
  }))
}

function Open({ origin, request, resolve, reject }: Approval) {
  const dialog = useRef<HTMLDialogElement>(null)
  const frame = useRef<HTMLIFrameElement>(null)
  useEffect(() => {
    const el = dialog.current!
    let settled = false
    const settle = (done: () => void) => { if (settled) return; settled = true; approval.set(undefined); done() }
    // Escape (or any other way the dialog closes before the frame answers) is a refusal.
    el.addEventListener('close', () => settle(() => reject(new Error('Cancelled.'))))
    el.showModal()
    mountDito(frame.current!, origin, 'approve')
      .then(embed => embed.approve(request))
      .then(response => settle(() => resolve(response)), error => settle(() => reject(error instanceof Error ? error : new Error(String(error)))))
  }, [])
  return (
    <dialog ref={dialog} style={{ padding: 0, border: '1px solid color-mix(in srgb,CanvasText 20%,transparent)', borderRadius: 12, width: 'min(420px,92vw)', background: 'Canvas', color: 'CanvasText', overflow: 'hidden' }}>
      <iframe ref={frame} title="did.md Wallet" style={{ display: 'block', width: '100%', height: 240, border: 0, colorScheme: 'normal' }} />
    </dialog>
  )
}

export function ApproveDialog() {
  const current = useStore(approval)
  return current ? <Open {...current} /> : null
}
