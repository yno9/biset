// Approvals inside the page (identity/wallet/dito-embed.ts): a request that needs the Passphrase -- a
// DID document edit -- opens dito's approve screen in a dialog over this page, so the person never
// leaves it. The dialog only frames dito's screen; nothing typed there reaches this page.
import { useEffect, useRef } from 'react'
import { createStore, useStore } from '../react/store.ts'
import { useDidMdWalletApprover } from '../../identity/wallet/did-md-oauth.ts'
import { ditoEmbedOrigin, mountDito, type DitoEmbed } from '../../identity/wallet/dito-embed.ts'

interface Approval { origin: string; request: Promise<string>; resolve(response: URLSearchParams): void; reject(error: Error): void }

const approval = createStore<Approval | undefined>(undefined)

/** Approvals run in dito's frame where dito is a sibling origin; elsewhere they stay full-page. */
export function installDitoApprover(): void {
  const origin = ditoEmbedOrigin()
  if (!origin) return
  // Open the connection (DNS, TLS) now, so the frame's document starts loading the moment the dialog opens.
  const hint = document.createElement('link')
  hint.rel = 'preconnect'
  hint.href = origin
  document.head.append(hint)
  useDidMdWalletApprover(request => new Promise<URLSearchParams>((resolve, reject) => {
    if (approval.get()) { reject(new Error('Another approval is already open.')); return }
    approval.set({ origin, request, resolve, reject })
  }))
}

let reloadWarmFrame: (() => void) | undefined
/** Loads the waiting frame again: what it had restored is out of date (the identity moved to another address). */
export function refreshApproveFrame(): void { reloadWarmFrame?.() }

interface Warm { ready: Promise<DitoEmbed>; dispose(): void; onResize?(height: number): void }

/**
 * The frame is loaded in the background as soon as the page is idle and waits, closed, for a request:
 * dito has by then started and restored its identity, so an approval only has to hand it the request.
 * Each approval ends by loading a fresh frame for the next one.
 */
export function ApproveDialog() {
  const origin = ditoEmbedOrigin()
  const current = useStore(approval)
  const dialog = useRef<HTMLDialogElement>(null)
  const frame = useRef<HTMLIFrameElement>(null)
  const warm = useRef<Warm>(undefined)

  const start = (): Warm => {
    const slot: Warm = { ready: undefined as never, dispose: () => {} }
    slot.ready = mountDito(frame.current!, origin!, 'approve', { resized: height => slot.onResize?.(height) })
      .then(embed => { slot.dispose = embed.dispose; return embed })
    slot.ready.catch(() => {}) // reported to the approval that uses it
    warm.current = slot
    return slot
  }

  useEffect(() => {
    reloadWarmFrame = () => { if (approval.get()) return; warm.current?.dispose(); start() }
    return () => { reloadWarmFrame = undefined }
  }, [])

  useEffect(() => {
    if (!origin) return
    const idle = window.requestIdleCallback ?? ((run: () => void) => setTimeout(run, 500))
    idle(() => { if (!warm.current) start() }, { timeout: 3000 })
  }, [])

  useEffect(() => {
    if (!current) return
    const { request, resolve, reject } = current
    const el = dialog.current!
    const slot = warm.current ?? start()
    let settled = false
    const finish = (done: () => void) => {
      if (settled) return
      settled = true
      clearTimeout(fallback)
      slot.onResize = undefined
      el.removeEventListener('close', onClose)
      if (el.open) el.close()
      el.style.visibility = ''
      approval.set(undefined)
      slot.dispose()
      start()
      done()
    }
    // Escape (or any other way the dialog closes before the frame answers) is a refusal.
    const onClose = () => finish(() => reject(new Error('Cancelled.')))
    el.addEventListener('close', onClose)
    // Open at once (the backdrop answers the click) but keep the box invisible until dito has laid its
    // approval out: the frame is blank until it has the request. A frame that never reports a height
    // is shown after a while anyway.
    const reveal = () => { el.style.visibility = '' }
    el.style.visibility = 'hidden'
    el.showModal()
    const fallback = setTimeout(reveal, 8000)
    const t0 = performance.now()
    const lap = (what: string) => console.info(`[approve] ${what} +${Math.round(performance.now() - t0)}ms`)
    Promise.all([slot.ready, request])
      .then(([embed, search]) => {
        lap('frame ready, request prepared')
        slot.onResize = height => { if (height >= 40) { lap('approval laid out'); reveal() } }
        return embed.approve(search)
      })
      .then(response => finish(() => resolve(response)), error => finish(() => reject(error instanceof Error ? error : new Error(String(error)))))
  }, [current])

  if (!origin) return null
  return (
    <dialog ref={dialog} style={{ margin: 'auto', padding: 0, border: '1px solid color-mix(in srgb,CanvasText 20%,transparent)', borderRadius: 12, width: 'min(420px,92vw)', background: 'Canvas', color: 'CanvasText', overflow: 'hidden' }}>
      <iframe ref={frame} title="did.md Wallet" style={{ display: 'block', width: '100%', height: 240, border: 0, colorScheme: 'normal' }} />
    </dialog>
  )
}
