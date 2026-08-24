// Ported at the flow level from src.bak/ui/shell.ts (443 lines), cut to the
// two things a read-only slice needs: dismissing the unlock/loading overlay
// once an identity's local vault is open, and a manual refresh (this slice
// has no incremental sync yet, so "refresh" is loadMessages' full reload,
// not a poll loop -- see PLAN.md §7's plan). Left out: everything
// send/compose (addPendingMessage and friends), the mobile-column
// MutationObserver, and every relay/session/DIDComm import shell.ts used only
// for those.
import { loadMessages, render } from './thread.ts'
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
  render()
  renderLeftList()
}

export async function refreshInbox(readModel: LocalJmapReadModel): Promise<void> {
  await loadMessages(readModel)
  render()
  renderLeftList()
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
