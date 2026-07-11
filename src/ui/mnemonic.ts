// Recovery-phrase (BIP39 24-word) display. This is the ONLY safety valve for the
// rotation-less root identity (DID.md): lose the phrase and the identity is
// unrecoverable, so the phrase must be shown to the user at least once and be
// re-viewable on demand. The seed itself is never persisted (see did/store.ts) —
// re-display re-derives it from the envelope + password, same as password change.
import { seedToMnemonic } from '../did/seed.ts'
import { fetchEnvelope, unsealEnvelope } from '../cryptenv.ts'

function overlay(): { root: HTMLElement; box: HTMLElement; dismiss: () => void } {
  const root = document.createElement('div')
  root.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:10002;display:flex;align-items:center;justify-content:center;padding:16px'
  const box = document.createElement('div')
  box.style.cssText = 'background:var(--bg);color:var(--text);border-radius:12px;padding:22px;max-width:460px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,0.35);max-height:92vh;overflow:auto'
  root.appendChild(box)
  const onKey = (ev: KeyboardEvent) => { if (ev.key === 'Escape') dismiss() }
  const dismiss = () => { document.removeEventListener('keydown', onKey); root.remove() }
  document.addEventListener('keydown', onKey)
  document.body.appendChild(root)
  return { root, box, dismiss }
}

function wordGrid(mnemonic: string): HTMLElement {
  const words = mnemonic.trim().split(/\s+/)
  const grid = document.createElement('div')
  grid.style.cssText = 'display:grid;grid-template-columns:repeat(2,1fr);gap:6px 14px;margin:16px 0;padding:14px;border:1px solid var(--header-border);border-radius:10px;background:var(--input-bg)'
  words.forEach((w, i) => {
    const cell = document.createElement('div')
    cell.style.cssText = 'display:flex;align-items:baseline;gap:8px;font-size:14px'
    const num = document.createElement('span')
    num.textContent = String(i + 1).padStart(2, '0')
    num.style.cssText = 'color:var(--text-dim);font-variant-numeric:tabular-nums;font-size:12px;min-width:18px'
    const word = document.createElement('span')
    word.textContent = w
    word.style.cssText = 'font-weight:600;font-family:ui-monospace,monospace'
    cell.append(num, word)
    grid.appendChild(cell)
  })
  return grid
}

// Renders the phrase + warning + copy/close into an existing box. `onClose` runs
// after the box is dismissed (used to continue a creation flow).
function renderPhrase(box: HTMLElement, dismiss: () => void, mnemonic: string, opts: { firstTime: boolean; onClose?: () => void }): void {
  box.textContent = ''
  const title = document.createElement('h3')
  title.textContent = 'Recovery phrase'
  title.style.cssText = 'margin:0 0 4px;font-size:17px'
  const sub = document.createElement('div')
  sub.textContent = opts.firstTime
    ? 'Write these 24 words down on paper, in order, and keep them somewhere safe.'
    : 'These 24 words restore your identity on any device.'
  sub.style.cssText = 'font-size:13px;color:var(--text-dim);line-height:1.4'

  const grid = wordGrid(mnemonic)

  const warn = document.createElement('div')
  warn.style.cssText = 'font-size:12.5px;color:#ff9500;line-height:1.45;margin-bottom:16px;display:flex;gap:8px'
  const warnIcon = document.createElement('span')
  warnIcon.textContent = '⚠'
  warnIcon.style.flexShrink = '0'
  const warnText = document.createElement('span')
  warnText.textContent = 'Anyone with this phrase can take over your identity. We can never show or reset it for you — lose it and your account is gone for good.'
  warn.append(warnIcon, warnText)

  const btnRow = document.createElement('div')
  btnRow.style.cssText = 'display:flex;justify-content:flex-end;gap:8px'
  const copyBtn = document.createElement('button')
  copyBtn.type = 'button'
  copyBtn.className = 'cmd-page-btn'
  copyBtn.textContent = 'Copy'
  copyBtn.style.cssText = 'width:auto;padding:7px 16px'
  copyBtn.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(mnemonic); copyBtn.textContent = 'Copied'; setTimeout(() => { copyBtn.textContent = 'Copy' }, 1200) } catch {}
  })
  const doneBtn = document.createElement('button')
  doneBtn.type = 'button'
  doneBtn.className = 'cmd-page-btn primary'
  doneBtn.textContent = opts.firstTime ? "I've saved it" : 'Close'
  doneBtn.style.cssText = 'width:auto;padding:7px 16px'
  doneBtn.addEventListener('click', () => { dismiss(); opts.onClose?.() })

  btnRow.append(copyBtn, doneBtn)
  box.append(title, sub, grid, warn, btnRow)
}

// Direct display — used right after account creation, when masterSecret is
// already in hand (no password re-entry needed).
export function showMnemonic(masterSecret: Uint8Array, opts: { firstTime: boolean; onClose?: () => void } = { firstTime: true }): void {
  const { box, dismiss } = overlay()
  renderPhrase(box, dismiss, seedToMnemonic(masterSecret), opts)
}

// On-demand display — used from /account. masterSecret isn't persisted, so we
// ask for the password, unseal the envelope, and derive the phrase transiently.
export function showMnemonicWithPassword(email: string, serverUrl: string): void {
  const { box, dismiss } = overlay()
  const form = document.createElement('form')
  form.autocomplete = 'off'
  form.style.cssText = 'display:flex;flex-direction:column;gap:10px'
  const title = document.createElement('h3')
  title.textContent = 'Recovery phrase'
  title.style.cssText = 'margin:0;font-size:17px'
  const sub = document.createElement('div')
  sub.textContent = 'Enter your password to reveal the 24-word phrase.'
  sub.style.cssText = 'font-size:13px;color:var(--text-dim)'
  const pw = document.createElement('input')
  pw.className = 'cmd-input'
  pw.type = 'password'
  pw.placeholder = 'Password'
  pw.autocomplete = 'current-password'
  pw.required = true
  const err = document.createElement('div')
  err.style.cssText = 'color:#ff3b30;font-size:12px;display:none'
  const row = document.createElement('div')
  row.style.cssText = 'display:flex;justify-content:flex-end;gap:8px;margin-top:4px'
  const cancel = document.createElement('button')
  cancel.type = 'button'; cancel.className = 'cmd-page-btn'; cancel.textContent = 'Cancel'
  cancel.style.cssText = 'width:auto;padding:6px 14px'
  cancel.addEventListener('click', dismiss)
  const submit = document.createElement('button')
  submit.type = 'submit'; submit.className = 'cmd-page-btn primary'; submit.textContent = 'Reveal'
  submit.style.cssText = 'width:auto;padding:6px 14px'
  row.append(cancel, submit)
  form.append(title, sub, pw, err, row)
  box.appendChild(form)
  pw.focus()

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault()
    err.style.display = 'none'
    submit.disabled = true; submit.textContent = 'Checking…'
    try {
      const env = await fetchEnvelope(serverUrl, email)
      if (!env) { err.textContent = 'Could not read the account envelope'; err.style.display = 'block'; return }
      let unsealed
      try { unsealed = await unsealEnvelope(env, pw.value) }
      catch { err.textContent = 'Incorrect password'; err.style.display = 'block'; return }
      renderPhrase(box, dismiss, seedToMnemonic(unsealed.masterSecret), { firstTime: false })
    } finally {
      submit.disabled = false; submit.textContent = 'Reveal'
    }
  })
}
