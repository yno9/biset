// Ported at the DOM-shape level from src.bak/ui/left-pane.ts (5417 lines,
// makeLpItem/renderLeftInboxes) -- cut to only #left-list rendering and
// click-to-open, per PLAN.md §7's plan. Not a literal port: the old rows were
// keyed on InboxSummary, a per-contact summary across possibly many
// relays/sessions (multi-relay JamClient concept this rewrite doesn't have).
// This rewrite has one identity's one local vault, already thread-grouped by
// mail/message-view.ts's groupMessages() -- so rows are keyed on ThreadGroup
// instead, reusing the same `.lp-item`/`.lp-avatar`/`.lp-info` DOM shape (and
// CSS) the old rows used.
// Left out: search, compose, command palette, account/settings panel,
// drag-drop .eml import, per-item context menu, swipe-to-delete, the mobile
// thread-accordion-per-contact toggle, unread *counts* (this slice shows an
// unread dot from MailMessageView.seen, nothing relay/push-derived).
import { groupMessages } from '../mail/message-view.ts'
import type { ThreadGroup } from '../mail/message-view.ts'
import { avatarStyle, esc, previewText } from './format.ts'
import { getFocusedThreadKey, render, setFocusedThreadKey } from './thread.ts'

function latestOf(group: ThreadGroup) {
  return group.messages[group.messages.length - 1]!.msg
}

function makeLpItem(group: ThreadGroup, active: boolean): HTMLElement {
  const latest = latestOf(group)
  const label = group.subject || latest.from_name || latest.from || 'no title'
  const avatarSubject = latest.from_name || latest.from || label
  const unread = group.messages.some(p => p.msg.seen !== true)
  const a = document.createElement('a')
  a.className = 'lp-item' + (active ? ' current' : '')
  a.href = '#'
  a.dataset.threadKey = group.key
  a.innerHTML = `
    <div class="lp-inner">
      <div class="lp-avatar" style="${avatarStyle(avatarSubject)}">${avatarSubject.charAt(0).toUpperCase()}${unread ? '<div class="unread-dot"></div>' : ''}</div>
      <div class="lp-info">
        <div class="lp-name">${esc(label)}</div>
        <div class="lp-preview">${esc(previewText(latest.body))}</div>
      </div>
    </div>
  `
  a.addEventListener('click', e => {
    e.preventDefault()
    setFocusedThreadKey(group.key)
    render()
    renderLeftList()
  })
  return a
}

export function renderLeftList(): void {
  const list = document.getElementById('left-list')
  if (!list) return
  list.innerHTML = ''
  const groups = [...groupMessages()].sort((a, b) => latestOf(b).ts - latestOf(a).ts)
  const active = getFocusedThreadKey()
  for (const group of groups) list.appendChild(makeLpItem(group, group.key === active))
}
