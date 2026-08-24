// Port of src.bak/ui/left-pane.ts's #compose page (renderComposePage +
// onShowNew, ~850 lines). PAGE_HTML below is the original markup verbatim,
// per the same "don't trim inert elements" direction as account-page.ts.
// The wiring behind it is cut down hard: onShowNew's actual bulk is a
// multi-protocol (Mail/AP/DID) recipient picker with per-row protocol
// pills, DIDComm channel detection, and a From-identity selector across
// possibly many relay sessions -- none of which this rewrite has any
// concept of (one identity, one local vault, mail only, no DIDComm/AP
// adapter yet). What's left: a plain list of mail addresses in the To
// field (the "+" button adds another plain input, no protocol pills),
// From fixed to this identity's own mail address, Subject, Body, and Send
// -- reusing the exact same commit-then-submit pipeline main.ts's reply
// send path already goes through (buildOutboundRfc5322 -> commitMailMessage
// -> EmailSubmission/set), just with no inReplyTo/references. Attach
// (#new-attach-btn/#new-attach-input) stays unwired: rfc5322-builder.ts is
// plain-text-only, no MIME multipart.
import { render } from './thread.ts'
import type { ReplySendInput } from './thread.ts'

export interface ComposePageConfig {
  selfAddress: string
  sendMessage(input: ReplySendInput): Promise<void>
  onError?(message: string): void
}

let config: ComposePageConfig | undefined
let active = false

export function configureComposePage(next: ComposePageConfig): void {
  config = next
}

export function inComposeMode(): boolean {
  return active
}

const PAGE_HTML = `<div class="cmd-page-content compose-page">
  <div class="new-compose-card">
    <div class="new-compose-field">
      <div id="new-recipients" class="new-recipients-list">
        <div class="new-recipient-row" data-kind="to">
          <span class="new-field-label">To</span>
          <span class="new-recip-protos"></span>
          <input class="new-field-input" type="email" placeholder="recipient@example.com" autocomplete="off">
          <button id="new-add-btn" class="new-compose-add-btn" tabindex="-1" style="font-size:18px;padding:0 4px;line-height:1">+</button>
        </div>
      </div>
    </div>
    <div id="new-from-field" class="new-compose-field" style="align-items:center">
      <span class="new-field-label">From</span>
      <button type="button" id="new-from" class="new-field-input new-from-btn"></button>
    </div>
    <div id="new-title-field" class="new-compose-field">
      <span id="new-title-label" class="new-field-label">Subject</span>
      <input id="new-title" class="new-field-input" placeholder="(no subject)" autocomplete="off">
    </div>
    <div class="new-compose-body-field">
      <span class="new-field-label">Body</span>
      <textarea id="new-body" placeholder="Write a message…"></textarea>
    </div>
    <div class="reply-attachments" id="new-attachments" style="display:none"></div>
    <div class="new-compose-actions" style="justify-content:flex-end">
      <button id="new-attach-btn" class="reply-attach-btn" type="button" title="Attach file">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
      </button>
      <input id="new-attach-input" type="file" multiple style="display:none">
      <button id="new-send-btn" class="t-send-btn always-send" title="Send">
        <svg viewBox="0 0 24 24"><path d="M2 12L22 2L12 22L10 14L2 12Z"/></svg>
      </button>
    </div>
  </div>
</div>`

function recipients(): string[] {
  const inputs = document.querySelectorAll<HTMLInputElement>('#new-recipients .new-field-input')
  return [...inputs].map(i => i.value.trim()).filter(Boolean)
}

export function showComposePage(): void {
  const activeEl = document.getElementById('active-thread')
  const past = document.getElementById('past-threads')
  const app = document.getElementById('app')
  if (!activeEl || !config) return
  active = true
  app?.setAttribute('data-menu-page', '/compose')
  if (past) past.innerHTML = ''

  const card = document.createElement('div')
  card.className = 'cmd-thread-card'
  card.id = 'focused-thread-card'
  card.innerHTML = PAGE_HTML
  activeEl.innerHTML = ''
  activeEl.appendChild(card)

  const fromBtn = document.getElementById('new-from')
  if (fromBtn) fromBtn.textContent = config.selfAddress

  const recipientsDiv = document.getElementById('new-recipients')!
  document.getElementById('new-add-btn')?.addEventListener('click', () => {
    const row = document.createElement('div')
    row.className = 'new-recipient-row'
    row.innerHTML = `<span class="new-field-label"></span><input class="new-field-input" type="email" placeholder="recipient@example.com" autocomplete="off">`
    recipientsDiv.appendChild(row)
    row.querySelector('input')?.focus()
  })

  const bodyEl = document.getElementById('new-body') as HTMLTextAreaElement | null
  const titleEl = document.getElementById('new-title') as HTMLInputElement | null
  const sendBtn = document.getElementById('new-send-btn') as HTMLButtonElement | null

  let sending = false
  const send = async () => {
    if (!config || sending) return
    const toAddrs = recipients()
    const body = bodyEl?.value.trim() ?? ''
    if (toAddrs.length === 0) { config.onError?.('At least one recipient is required'); return }
    if (!body) { config.onError?.('Message cannot be empty'); return }
    sending = true
    if (sendBtn) sendBtn.disabled = true
    try {
      await config.sendMessage({ toAddrs, subject: titleEl?.value.trim() ?? '', body })
      hideComposePage()
    } catch (e) {
      config.onError?.(e instanceof Error ? e.message : 'Could not send')
    } finally {
      sending = false
      if (sendBtn) sendBtn.disabled = false
    }
  }
  sendBtn?.addEventListener('click', () => { void send() })

  const headerTitle = document.getElementById('header-thread-title')
  if (headerTitle) { headerTitle.textContent = 'compose'; headerTitle.className = '' }
  const groupIcon = document.getElementById('header-group-icon')
  if (groupIcon) groupIcon.style.display = 'none'
  const convMeta = document.getElementById('conv-meta')
  if (convMeta) convMeta.style.display = 'none'

  document.querySelector<HTMLInputElement>('#new-recipients .new-field-input')?.focus()
}

export function hideComposePage(): void {
  if (!active) return
  active = false
  document.getElementById('app')?.removeAttribute('data-menu-page')
  const convMeta = document.getElementById('conv-meta')
  if (convMeta) convMeta.style.display = ''
  render()
}
