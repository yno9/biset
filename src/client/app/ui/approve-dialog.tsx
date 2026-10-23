// Approvals inside the page (identity/wallet/dito-embed.ts): a request that needs the Passphrase -- a
// DID document edit -- opens dito's approve screen in a dialog over this page, so the person never
// leaves it. The dialog only frames dito's screen; nothing typed there reaches this page. The same
// waiting frame also serves the alias change (dito's alias screen), so that opens at once too.
import { useEffect, useRef } from 'react'
import { createStore, useStore } from '../react/store.ts'
import { accountConfig } from './account/state.ts'
import { useDidMdWalletApprover } from '../../identity/wallet/did-md-oauth.ts'
import { ditoEmbedOrigin, mountDito, type DitoEmbed } from '../../identity/wallet/dito-embed.ts'

/** One thing asked of dito's waiting frame: `ready` is what `run` needs and is still being prepared. */
interface Approval { origin: string; /** A click outside the card closes it (Esc does too). */ dismissOutside?: boolean; ready: Promise<unknown>; run(embed: DitoEmbed, prepared: unknown): Promise<unknown>; resolve(result: unknown): void; reject(error: Error): void }

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
    approval.set({ origin, ready: request, run: (embed, search) => embed.approve(search as string), resolve, reject })
  }))
}

/** Asks dito, in the dialog, to move this browser's identity to another address; resolves with the new DID. */
export function requestAliasChange(): Promise<{ did: string, host: string }> {
  const origin = ditoEmbedOrigin()
  if (!origin) return Promise.reject(new Error('Changing the alias needs the embedded wallet.'))
  return new Promise((resolve, reject) => {
    if (approval.get()) { reject(new Error('Another approval is already open.')); return }
    approval.set({ origin, dismissOutside: true, ready: Promise.resolve(), run: embed => embed.moveAlias(), resolve, reject })
  })
}

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
    slot.ready = mountDito(frame.current!, origin!, 'approve', { resized: height => slot.onResize?.(height), escape: () => { if (dialog.current?.open) dialog.current.close() } })
      .then(embed => { slot.dispose = embed.dispose; return embed })
    slot.ready.catch(() => {}) // reported to the approval that uses it
    warm.current = slot
    return slot
  }

  // Nothing to approve before there is an account: the sign-up page keeps its one dito frame (a second
  // dito frame in the tab is one more thing for a password manager to track while the person signs up).
  const signedIn = useStore(accountConfig)?.did != null
  useEffect(() => {
    if (!origin || !signedIn) return
    const idle = window.requestIdleCallback ?? ((run: () => void) => setTimeout(run, 500))
    idle(() => { if (!warm.current) start() }, { timeout: 3000 })
  }, [signedIn])

  useEffect(() => {
    if (!current) return
    const { ready, run, resolve, reject, dismissOutside } = current
    const el = dialog.current!
    const slot = warm.current ?? start()
    let settled = false
    const finish = (done: () => void) => {
      if (settled) return
      settled = true
      clearTimeout(fallback)
      slot.onResize = undefined
      el.removeEventListener('close', onClose)
      el.removeEventListener('click', onOutside)
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
    // The frame fills the dialog, so a click on the dialog itself is a click on its backdrop.
    const onOutside = (event: MouseEvent) => { if (dismissOutside && event.target === el) el.close() }
    el.addEventListener('click', onOutside)
    // Open at once (the backdrop answers the click) but keep the box invisible until dito has laid its
    // approval out: the frame is blank until it has the request. A frame that never reports a height
    // is shown after a while anyway.
    const reveal = () => { el.style.visibility = '' }
    el.style.visibility = 'hidden'
    el.showModal()
    const fallback = setTimeout(reveal, 8000)
    const t0 = performance.now()
    const lap = (what: string) => console.info(`[approve] ${what} +${Math.round(performance.now() - t0)}ms`)
    Promise.all([slot.ready, ready])
      .then(([embed, prepared]) => {
        lap('frame ready, request prepared')
        slot.onResize = height => { if (height >= 40) { lap('approval laid out'); reveal() } }
        return run(embed, prepared)
      })
      .then(result => finish(() => resolve(result)), error => finish(() => reject(error instanceof Error ? error : new Error(String(error)))))
  }, [current])

  if (!origin) return null
  return (
    <dialog ref={dialog} style={{ margin: 'auto', padding: 0, border: '1px solid color-mix(in srgb,CanvasText 20%,transparent)', borderRadius: 12, width: 'min(420px,92vw)', background: 'Canvas', color: 'CanvasText', overflow: 'hidden' }}>
      <iframe ref={frame} title="did.md Wallet" style={{ display: 'block', width: '100%', height: 240, border: 0, colorScheme: 'normal' }} />
    </dialog>
  )
}
