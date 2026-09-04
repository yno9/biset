// Ported at the flow level from src.bak/ui/shell.ts (443 lines), cut to the
// two things a read-only slice needs: dismissing the unlock/loading overlay
// once an identity's local vault is open, and a manual refresh (this slice
// has no incremental sync yet, so "refresh" is loadMessages' full reload,
// not a poll loop -- see PLAN.md §7's plan). Left out: everything
// send/compose (addPendingMessage and friends), the mobile-column
// MutationObserver, and every relay/session/DIDComm import shell.ts used only
// for those.
import { loadMessages, render, setupScrollButtons } from './thread.ts'
import { renderLeftList, setupLeftPane } from './left-pane.ts'
import type { LocalJmapReadModel } from '../local-jmap/gateway.ts'

export function showApp(): void {
  // #app is src.bak's own mail-UI container (id restored as-is 2026-08-24,
  // see PLAN.md §7's progress log) -- distinct from #overlay, which this
  // rewrite has no use for (no unlock step yet: record-store.ts's secrets
  // are still plaintext, so there's nothing to wait on between "identity
  // found" and showing mail).
  const $app = document.getElementById('app')
  if ($app) $app.style.display = 'flex'
  setupLeftPane()
  setupScrollButtons()
  render()
  renderLeftList()
}

// A Wallet session can receive a DIDComm SSE delivery while its MIMI Vault
// sync or an outgoing message is refreshing the same projection.  Letting
// those `loadMessages()` calls overlap permits an older snapshot to repaint
// the left list after a newer one painted the focused thread.  Serialize the
// read + both render targets as one UI transaction.
let inboxRefreshTail: Promise<void> = Promise.resolve()

export function refreshInbox(readModel: LocalJmapReadModel): Promise<void> {
  const task = inboxRefreshTail.then(async () => {
    await loadMessages(readModel)
    // Polling refreshes the data model, but must not navigate away from an
    // explicit menu page. render() repaints #active-thread as a conversation;
    // calling it while Account/Config/Compose owns that node caused a silent
    // page switch every ten seconds.
    if (!document.getElementById('app')?.hasAttribute('data-menu-page')) render()
    renderLeftList()
  })
  // Keep a rejected refresh observable to its caller without permanently
  // poisoning the queue for the next successful delivery.
  inboxRefreshTail = task.catch(() => {})
  return task
}

let sysMsgTimer: ReturnType<typeof setTimeout> | null = null

export function showSysMsg(text: string, durationMs = 1800): void {
  const el = document.getElementById('sys-msg')
  if (!el) return
  el.textContent = text
  el.classList.add('show')
  if (sysMsgTimer) clearTimeout(sysMsgTimer)
  sysMsgTimer = setTimeout(() => el.classList.remove('show'), durationMs)
}
