// Approvals inside the page (see dito-embed.ts): a request that needs the Passphrase -- a DID
// document edit -- opens dito's approve screen in a dialog over this page, so the person never
// leaves it. The dialog only frames dito's screen; nothing typed there reaches this page.

import { ditoEmbedOrigin, mountDito } from './dito-embed.ts'
import { useDidMdWalletApprover } from './did-md-oauth.ts'

async function approveInDialog(origin: string, request: string): Promise<URLSearchParams> {
  const dialog = document.createElement('dialog')
  dialog.style.cssText = 'padding:0;border:1px solid color-mix(in srgb,CanvasText 20%,transparent);border-radius:12px;width:min(420px,92vw);background:Canvas;color:CanvasText;overflow:hidden'
  const frame = document.createElement('iframe')
  frame.title = 'did.md Wallet'
  frame.style.cssText = 'display:block;width:100%;height:240px;border:0;color-scheme:normal'
  dialog.append(frame)
  document.body.append(dialog)
  dialog.showModal()
  // Escape (or any other way the dialog closes before the frame answers) is a refusal.
  const dismissed = new Promise<never>((_, reject) => dialog.addEventListener('close', () => reject(new Error('Cancelled.')), { once: true }))
  try {
    const embed = await Promise.race([mountDito(frame, origin, 'approve'), dismissed])
    return await Promise.race([embed.approve(request), dismissed])
  } finally {
    dialog.remove()
  }
}

/** Approvals run in dito's frame where dito is a sibling origin; elsewhere they stay full-page. */
export function installDitoApprover(): void {
  const origin = ditoEmbedOrigin()
  if (origin) useDidMdWalletApprover(request => approveInDialog(origin, request))
}
