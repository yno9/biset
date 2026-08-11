// Recovery-phrase (BIP39 24-word) display. This is the ONLY safety valve for the
// rotation-less root identity (DID.md): lose the phrase and the identity is
// unrecoverable, so the phrase must be shown to the user at least once and be
// re-viewable on demand. The seed itself is never persisted (see did/store.ts) —
// re-display re-derives it from the envelope + password, same as password change.
import { seedToMnemonic } from '../did/seed.ts'
// password/envelope concept disabled — see showMnemonicWithPassword below.
// import { fetchEnvelope, unsealEnvelope } from '../cryptenv.ts'

function overlay(): { root: HTMLElement; box: HTMLElement; dismiss: () => void; setEscapable: (v: boolean) => void } {
  const root = document.createElement('div')
  root.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:10002;display:flex;align-items:center;justify-content:center;padding:16px'
  const box = document.createElement('div')
  box.style.cssText = 'background:var(--bg);color:var(--text);border-radius:12px;padding:22px;max-width:460px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,0.35);max-height:92vh;overflow:auto'
  root.appendChild(box)
  // Escape can be disabled (renderVerifyStep does, during its confirmation
  // step) — otherwise it would let the save-confirmation step below be
  // skipped entirely, defeating its one purpose.
  let escapable = true
  const onKey = (ev: KeyboardEvent) => { if (ev.key === 'Escape' && escapable) dismiss() }
  const dismiss = () => { document.removeEventListener('keydown', onKey); root.remove() }
  document.addEventListener('keydown', onKey)
  document.body.appendChild(root)
  return { root, box, dismiss, setEscapable: (v: boolean) => { escapable = v } }
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

function didBox(did: string): HTMLElement {
  const row = document.createElement('div')
  row.style.cssText = 'display:flex;align-items:center;gap:8px;margin:0 0 12px;padding:10px 12px;border:1px solid var(--header-border);border-radius:8px;background:var(--input-bg)'
  const text = document.createElement('div')
  text.textContent = did
  text.title = did
  text.style.cssText = 'flex:1;min-width:0;font-family:ui-monospace,monospace;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'
  const copyBtn = document.createElement('button')
  copyBtn.type = 'button'
  copyBtn.className = 'cmd-page-btn'
  copyBtn.textContent = 'Copy DID'
  copyBtn.style.cssText = 'width:auto;padding:5px 12px;font-size:12px;flex-shrink:0'
  copyBtn.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(did); copyBtn.textContent = 'Copied'; setTimeout(() => { copyBtn.textContent = 'Copy DID' }, 1200) } catch {}
  })
  row.append(text, copyBtn)
  return row
}

// Step 1/4: the phrase alone (word grid + warning + copy/close). `onClose`
// runs after the box is dismissed (used to continue a creation flow). Split
// from the DID (steps 3/4 below) into its own screen — cramming both onto
// one screen read as cluttered/confusing (user-reported, 2026-07-27) even
// though the phrase is the one thing every identity actually needs.
function renderPhrase(box: HTMLElement, dismiss: () => void, mnemonic: string, did: string, opts: { firstTime: boolean; onClose?: () => void }, setEscapable?: (v: boolean) => void): void {
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
  doneBtn.addEventListener('click', () => {
    // First-time only: "I've saved it" used to dismiss outright — clicking
    // through it proves nothing about whether the phrase (or the DID) was
    // actually saved anywhere. A spot-check per secret (one random word
    // typed back, then the DID pasted back) catches the "clicked past it
    // without saving" case at the one moment that still matters — neither
    // is shown again after this (user-requested, 2026-07-27: no password
    // exists to gate a later re-reveal with, so there is no later chance to
    // catch it).
    if (opts.firstTime) renderVerifyStep(box, dismiss, mnemonic, did, opts, setEscapable)
    else { dismiss(); opts.onClose?.() }
  })

  btnRow.append(copyBtn, doneBtn)
  box.append(title, sub, grid, warn, btnRow)
}

// Step 2/4: one-word spot-check on the phrase just shown. Picks a random
// position, asks the user to type back exactly that word. "Back" returns to
// step 1 (renderPhrase, same mnemonic) to re-copy/re-check. Success moves on
// to the DID (step 3), not straight to onClose. Escape is disabled for the
// remainder of the flow (overlay's setEscapable) so none of these steps can
// be skipped that way.
function renderVerifyStep(box: HTMLElement, dismiss: () => void, mnemonic: string, did: string, opts: { firstTime: boolean; onClose?: () => void }, setEscapable?: (v: boolean) => void): void {
  setEscapable?.(false)
  const words = mnemonic.trim().split(/\s+/)
  const idx = Math.floor(Math.random() * words.length)

  box.textContent = ''
  const title = document.createElement('h3')
  title.textContent = 'Confirm you saved it'
  title.style.cssText = 'margin:0 0 4px;font-size:17px'
  const sub = document.createElement('div')
  sub.textContent = `Enter word #${idx + 1} from the phrase you just wrote down.`
  sub.style.cssText = 'font-size:13px;color:var(--text-dim);line-height:1.4;margin:0 0 14px'

  const input = document.createElement('input')
  input.className = 'cmd-input'
  input.type = 'text'
  input.autocomplete = 'off'
  input.autocapitalize = 'off'
  input.spellcheck = false
  input.placeholder = `Word #${idx + 1}`

  const err = document.createElement('div')
  err.style.cssText = 'color:#ff3b30;font-size:12px;display:none;margin-top:8px'

  const btnRow = document.createElement('div')
  btnRow.style.cssText = 'display:flex;justify-content:space-between;gap:8px;margin-top:16px'
  const backBtn = document.createElement('button')
  backBtn.type = 'button'
  backBtn.className = 'cmd-page-btn'
  backBtn.textContent = 'Back'
  backBtn.style.cssText = 'width:auto;padding:7px 16px'
  backBtn.addEventListener('click', () => { setEscapable?.(true); renderPhrase(box, dismiss, mnemonic, did, opts, setEscapable) })
  const confirmBtn = document.createElement('button')
  confirmBtn.type = 'button'
  confirmBtn.className = 'cmd-page-btn primary'
  confirmBtn.textContent = 'Confirm'
  confirmBtn.style.cssText = 'width:auto;padding:7px 16px'
  const submit = () => {
    if (input.value.trim().toLowerCase() === words[idx]!.toLowerCase()) {
      renderDidShow(box, dismiss, mnemonic, did, opts, setEscapable)
    } else {
      err.textContent = `That's not word #${idx + 1} — check your copy and try again.`
      err.style.display = 'block'
      input.select()
    }
  }
  confirmBtn.addEventListener('click', submit)
  input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); submit() } })

  btnRow.append(backBtn, confirmBtn)
  box.append(title, sub, input, err, btnRow)
  input.focus()
}

// Step 3/4: the DID alone, its own screen (see renderPhrase's note on why
// this is split from the word grid rather than shown together). A
// did:webvh identity's DID string isn't derivable from the seed alone (its
// SCID depends on genesis TIME/domain/username, not just the root key —
// restore.ts's own file header) — the phrase alone restores a did:dht
// identity but silently CAN'T restore a did:webvh one without this too.
// Asked for uniformly (did:dht doesn't strictly need it) rather than
// branching this whole flow on which method the identity happens to use.
function renderDidShow(box: HTMLElement, dismiss: () => void, mnemonic: string, did: string, opts: { firstTime: boolean; onClose?: () => void }, setEscapable?: (v: boolean) => void): void {
  box.textContent = ''
  const title = document.createElement('h3')
  title.textContent = 'Your DID'
  title.style.cssText = 'margin:0 0 4px;font-size:17px'
  const sub = document.createElement('div')
  sub.textContent = 'Save this too. A did:webvh identity needs it alongside the phrase to restore (did:dht doesn\'t strictly need it, but saving it either way keeps this one step simple).'
  sub.style.cssText = 'font-size:13px;color:var(--text-dim);line-height:1.4;margin:0 0 14px'

  const btnRow = document.createElement('div')
  btnRow.style.cssText = 'display:flex;justify-content:space-between;gap:8px;margin-top:16px'
  const backBtn = document.createElement('button')
  backBtn.type = 'button'
  backBtn.className = 'cmd-page-btn'
  backBtn.textContent = 'Back'
  backBtn.style.cssText = 'width:auto;padding:7px 16px'
  backBtn.addEventListener('click', () => renderPhrase(box, dismiss, mnemonic, did, opts, setEscapable))
  const doneBtn = document.createElement('button')
  doneBtn.type = 'button'
  doneBtn.className = 'cmd-page-btn primary'
  doneBtn.textContent = "I've saved it"
  doneBtn.style.cssText = 'width:auto;padding:7px 16px'
  doneBtn.addEventListener('click', () => renderDidConfirm(box, dismiss, mnemonic, did, opts, setEscapable))

  btnRow.append(backBtn, doneBtn)
  box.append(title, sub, didBox(did), btnRow)
}

// Step 4/4: paste the DID back to prove it was actually copied somewhere,
// not just glanced at. Typing it from memory isn't realistic (unlike a
// single BIP39 word) — paste-and-match is the equivalent spot-check for an
// opaque string. "Back" returns to step 3 (renderDidShow) to re-copy.
function renderDidConfirm(box: HTMLElement, dismiss: () => void, mnemonic: string, did: string, opts: { firstTime: boolean; onClose?: () => void }, setEscapable?: (v: boolean) => void): void {
  box.textContent = ''
  const title = document.createElement('h3')
  title.textContent = 'Confirm your DID'
  title.style.cssText = 'margin:0 0 4px;font-size:17px'
  const sub = document.createElement('div')
  sub.textContent = 'Paste the DID you copied to confirm you saved that too.'
  sub.style.cssText = 'font-size:13px;color:var(--text-dim);line-height:1.4;margin:0 0 14px'

  // textarea, not a single-line input: a did:webvh string (SCID included)
  // routinely runs 60-90+ chars — a one-line input scrolls its cursor (and
  // thus the START of the value) out of view the moment you paste, which
  // reads as truncated even when the underlying value is intact
  // (user-reported, 2026-07-27, screenshotted as ":t.biset.md:dids:97c4" —
  // the tail end of a longer DID, not the whole thing). Wrapping across
  // lines keeps the entire pasted value visible for the user to actually
  // check before confirming.
  const input = document.createElement('textarea')
  input.className = 'cmd-input'
  input.rows = 3
  input.autocomplete = 'off'
  input.autocapitalize = 'off'
  input.spellcheck = false
  input.placeholder = 'did:…'
  input.style.cssText = 'font-family:ui-monospace,monospace;font-size:12.5px;line-height:1.4;resize:vertical;word-break:break-all;width:100%;box-sizing:border-box'

  const err = document.createElement('div')
  err.style.cssText = 'color:#ff3b30;font-size:12px;display:none;margin-top:8px'

  const btnRow = document.createElement('div')
  btnRow.style.cssText = 'display:flex;justify-content:space-between;gap:8px;margin-top:16px'
  const backBtn = document.createElement('button')
  backBtn.type = 'button'
  backBtn.className = 'cmd-page-btn'
  backBtn.textContent = 'Back'
  backBtn.style.cssText = 'width:auto;padding:7px 16px'
  backBtn.addEventListener('click', () => renderDidShow(box, dismiss, mnemonic, did, opts, setEscapable))
  const confirmBtn = document.createElement('button')
  confirmBtn.type = 'button'
  confirmBtn.className = 'cmd-page-btn primary'
  confirmBtn.textContent = 'Confirm'
  confirmBtn.style.cssText = 'width:auto;padding:7px 16px'
  const submit = () => {
    if (input.value.trim() === did) {
      setEscapable?.(true)
      dismiss()
      opts.onClose?.()
    } else {
      err.textContent = 'That doesn\'t match the DID shown earlier — copy it again and paste it here.'
      err.style.display = 'block'
      input.select()
    }
  }
  confirmBtn.addEventListener('click', submit)
  input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); submit() } })

  btnRow.append(backBtn, confirmBtn)
  box.append(title, sub, input, err, btnRow)
  input.focus()
}

// Direct display — used right after account creation, when masterSecret is
// already in hand (no password re-entry needed). `did` is passed in rather
// than derived here: did:webvh's DID isn't a pure function of the seed (see
// renderPhrase's note), so the caller's already-created DidRecord is the
// only source of truth for it.
export function showMnemonic(masterSecret: Uint8Array, did: string, opts: { firstTime: boolean; onClose?: () => void } = { firstTime: true }): void {
  const { box, dismiss, setEscapable } = overlay()
  renderPhrase(box, dismiss, seedToMnemonic(masterSecret), did, opts, setEscapable)
}

// password/envelope concept disabled (commented out for easy revival —
// account-create.ts's submit handler has the fuller note). This function is
// now also STRUCTURALLY impossible to bring back as-is: masterSecret is
// never wrapped into an envelope for any account created after that change,
// so there is nothing left to unseal — re-deriving the phrase on demand
// would need masterSecret to be persisted somewhere (a real security-posture
// change, not just uncommenting this), or the phrase accepted as a
// show-once-at-creation-only secret (showMnemonic above already covers
// that). Left here for reference / as a starting point if that tradeoff
// ever gets revisited.
//
// export function showMnemonicWithPassword(email: string, serverUrl: string): void {
//   const { box, dismiss } = overlay()
//   const form = document.createElement('form')
//   form.autocomplete = 'off'
//   form.style.cssText = 'display:flex;flex-direction:column;gap:10px'
//   const title = document.createElement('h3')
//   title.textContent = 'Recovery phrase'
//   title.style.cssText = 'margin:0;font-size:17px'
//   const sub = document.createElement('div')
//   sub.textContent = 'Enter your password to reveal the 24-word phrase.'
//   sub.style.cssText = 'font-size:13px;color:var(--text-dim)'
//   const pw = document.createElement('input')
//   pw.className = 'cmd-input'
//   pw.type = 'password'
//   pw.placeholder = 'Password'
//   pw.autocomplete = 'current-password'
//   pw.required = true
//   const err = document.createElement('div')
//   err.style.cssText = 'color:#ff3b30;font-size:12px;display:none'
//   const row = document.createElement('div')
//   row.style.cssText = 'display:flex;justify-content:flex-end;gap:8px;margin-top:4px'
//   const cancel = document.createElement('button')
//   cancel.type = 'button'; cancel.className = 'cmd-page-btn'; cancel.textContent = 'Cancel'
//   cancel.style.cssText = 'width:auto;padding:6px 14px'
//   cancel.addEventListener('click', dismiss)
//   const submit = document.createElement('button')
//   submit.type = 'submit'; submit.className = 'cmd-page-btn primary'; submit.textContent = 'Reveal'
//   submit.style.cssText = 'width:auto;padding:6px 14px'
//   row.append(cancel, submit)
//   form.append(title, sub, pw, err, row)
//   box.appendChild(form)
//   pw.focus()
//
//   form.addEventListener('submit', async (ev) => {
//     ev.preventDefault()
//     err.style.display = 'none'
//     submit.disabled = true; submit.textContent = 'Checking…'
//     try {
//       const env = await fetchEnvelope(serverUrl, email)
//       if (!env) { err.textContent = 'Could not read the account envelope'; err.style.display = 'block'; return }
//       let unsealed
//       try { unsealed = await unsealEnvelope(env, pw.value) }
//       catch { err.textContent = 'Incorrect password'; err.style.display = 'block'; return }
//       renderPhrase(box, dismiss, seedToMnemonic(unsealed.masterSecret), { firstTime: false })
//     } finally {
//       submit.disabled = false; submit.textContent = 'Reveal'
//     }
//   })
// }
