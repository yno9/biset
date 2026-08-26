// Port of src.bak/ui/left-pane.ts's #compose page (renderComposePage +
// onShowNew, ~850 lines, read in full 2026-08-25 before this port). PAGE_HTML
// below is the original markup verbatim, per the same "don't trim inert
// elements" direction as account-page.ts.
//
// onShowNew's actual bulk doesn't apply here: ActivityPub (retired, no
// adapter exists), PGP/attachments-over-mail, MLS group conversations,
// multi-relay `sessions[]`/account switching, and the async AP-webfinger +
// DID-DNS-anchor discovery that decided a recipient's viable protocols --
// none of that exists in this rewrite (one identity, one local vault, mail
// + DIDComm only, PLAN.md §6.1/§7 scope).
//
// What DOES carry over, faithfully: the From<->To protocol-match src.bak's
// requiredFromProto/syncFromRequirement/fromOptionAllowed implemented --
// found missing here 2026-08-25 (a DIDComm "to" left "From" showing the
// mail address, when the actual sender for that send is the identity's own
// DID, main.ts's sendDidCommChat). Simplified from src.bak's async version
// because protocol detection here has nothing to wait on: src.bak had to
// probe AP webfinger + a DNS anchor over the network before it knew what an
// address could reach (real latency, hence the loading spinner / two-probe
// machinery); a "to" here is either a did:webvh string or a plain mail
// address, decided entirely by its shape, synchronously.
import { render } from './thread.ts'
import type { ReplySendInput } from './thread.ts'
import { shortWebvhDid, protocolFor, PROTO_COLOR, PROTO_TEXT } from './did-display.ts'
import type { Proto } from './did-display.ts'

export interface ComposePageConfig {
  selfAddress: string
  /** This identity's own DID -- undefined until enableDidComm has run
   * (main.ts's boot). Needed so "From" has a DID option to switch to at all
   * once "To" resolves to one; with none, DID recipients simply can't be
   * composed to from here (same as src.bak's own "create account first"
   * guard when fromOptions is empty). */
  selfDid?: string
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

// ── Protocol pill + DID elision ─────────────────────────────────────────────
/** The recipient's actual address -- `dataset.fullDid` when the field is
 * showing an elided DID, the raw input text otherwise. The one place that
 * reads a recipient row back for sending/protocol detection. */
function recipientAddress(inp: HTMLInputElement): string {
  return (inp.dataset.fullDid || inp.value).trim()
}

/** Elides a did:webvh the same way account-page.ts's own DID line does
 * (did-display.ts's shortWebvhDid) -- the real address stays in
 * `dataset.fullDid` for sending/copy; the visible text is the short form. A
 * plain mail address is shown as typed, no dataset. */
function setRecipientInputValue(inp: HTMLInputElement, address: string): void {
  if (address.startsWith('did:webvh:')) {
    inp.value = shortWebvhDid(address)
    inp.dataset.fullDid = address
  } else {
    inp.value = address
    delete inp.dataset.fullDid
  }
}

function protosEl(row: HTMLElement): HTMLElement | null {
  return row.querySelector<HTMLElement>('.new-recip-protos')
}

function renderRowProto(row: HTMLElement): void {
  const el = protosEl(row)
  const inp = row.querySelector<HTMLInputElement>('.new-field-input')
  if (!el || !inp) return
  const address = recipientAddress(inp)
  el.innerHTML = ''
  if (!address) return
  const proto = protocolFor(address)
  const badge = document.createElement('span')
  badge.textContent = PROTO_TEXT[proto]
  badge.style.cssText = `font-size:10px;font-weight:700;color:#fff;border-radius:4px;padding:1px 5px;margin-right:6px;flex-shrink:0;background:${PROTO_COLOR[proto]}`
  badge.title = proto === 'did' ? 'Sends over DIDComm' : 'Sends as mail'
  el.appendChild(badge)
}

function recipients(): string[] {
  const inputs = document.querySelectorAll<HTMLInputElement>('#new-recipients .new-field-input')
  return [...inputs].map(recipientAddress).filter(Boolean)
}

// ── From<->To protocol match (src.bak's requiredFromProto/syncFromRequirement) ──
// A message goes out over exactly one transport, decided by the FIRST filled
// recipient row's protocol (mixing mail and DIDComm recipients in one send
// isn't meaningful -- DIDComm doesn't have a "cc", and main.ts's own
// sendReply only ever branches on `toAddrs[0]`). "From" tracks that: `[Mail]
// d157@mail.biset.md` for a mail recipient, `[DID] did:webvh:...` (this
// identity's own DID) for a DIDComm one -- never a manual choice, since
// there is nothing to choose between once "to" has decided the transport.
interface FromOption { protocol: Proto; address: string }

function fromOptions(): FromOption[] {
  const opts: FromOption[] = [{ protocol: 'mail', address: config!.selfAddress }]
  if (config!.selfDid) opts.push({ protocol: 'did', address: config!.selfDid })
  return opts
}

/** The first filled recipient row's protocol, or null with nothing typed yet
 * -- src.bak's own rule (requiredFromProto): "From" only ever reflects a
 * transport "To" has actually settled on. */
function requiredFromProto(): Proto | null {
  const recipientsDiv = document.getElementById('new-recipients')
  if (!recipientsDiv) return null
  for (const row of recipientsDiv.querySelectorAll<HTMLElement>('.new-recipient-row')) {
    const inp = row.querySelector<HTMLInputElement>('.new-field-input')
    const address = inp ? recipientAddress(inp) : ''
    if (address) return protocolFor(address)
  }
  return null
}

/** Re-renders the From button's pill + address for whichever option matches
 * `requiredFromProto()` -- falls back to the mail option when nothing's
 * typed yet (an empty compose defaulting to "mail" reads as the ordinary
 * case, not a state needing a disabled/dimmed treatment: unlike src.bak,
 * protocol detection here is synchronous, so there's no "still resolving"
 * window to guard against). When "to" resolves to did but this identity has
 * no DID yet (selfDid unset), there's no matching From option -- surfaced at
 * send time (onError), not as a dimmed button here. */
function syncFromDisplay(): void {
  const fromBtn = document.getElementById('new-from')
  if (!fromBtn || !config) return
  const required = requiredFromProto()
  const opts = fromOptions()
  const selected = (required && opts.find(o => o.protocol === required)) || opts[0]!
  fromBtn.innerHTML = ''
  const badge = document.createElement('span')
  badge.textContent = PROTO_TEXT[selected.protocol]
  badge.style.cssText = `font-size:10px;font-weight:700;color:#fff;border-radius:4px;padding:1px 5px;margin-right:6px;flex-shrink:0;background:${PROTO_COLOR[selected.protocol]}`
  fromBtn.appendChild(badge)
  const addr = document.createElement('span')
  addr.style.cssText = 'white-space:nowrap;min-width:0;overflow:hidden;text-overflow:ellipsis'
  addr.textContent = selected.protocol === 'did' ? shortWebvhDid(selected.address) : selected.address
  addr.title = selected.address
  fromBtn.appendChild(addr)
}

/** Wires one recipient row's input: badge updates live as you type (raw
 * value -- a manual edit always clears any stale `dataset.fullDid`, same
 * reasoning as src.bak's own version), a typed did:webvh collapses to its
 * elided form on blur, and From re-syncs on every change since it tracks
 * whichever row resolves first. */
function wireRecipientRow(row: HTMLElement): void {
  const inp = row.querySelector<HTMLInputElement>('.new-field-input')
  if (!inp) return
  inp.addEventListener('input', () => {
    delete inp.dataset.fullDid
    renderRowProto(row)
    syncFromDisplay()
  })
  inp.addEventListener('blur', () => {
    const address = recipientAddress(inp)
    if (address) setRecipientInputValue(inp, address)
    renderRowProto(row)
    syncFromDisplay()
  })
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

  syncFromDisplay()

  const recipientsDiv = document.getElementById('new-recipients')!
  for (const row of recipientsDiv.querySelectorAll<HTMLElement>('.new-recipient-row')) wireRecipientRow(row)
  document.getElementById('new-add-btn')?.addEventListener('click', () => {
    const row = document.createElement('div')
    row.className = 'new-recipient-row'
    row.innerHTML = `<span class="new-field-label"></span><span class="new-recip-protos"></span><input class="new-field-input" type="email" placeholder="recipient@example.com" autocomplete="off">`
    recipientsDiv.appendChild(row)
    wireRecipientRow(row)
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
    if (toAddrs[0]!.startsWith('did:') && !config.selfDid) {
      config.onError?.('DIDComm is not set up on this identity yet')
      return
    }
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
  // Same stray-reply-box fix as account-page.ts's showAccountPage: nothing
  // clears #reply-dock just because a different page now occupies
  // #active-thread.
  const dock = document.getElementById('reply-dock')
  if (dock) dock.innerHTML = ''

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
