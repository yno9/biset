// Recovery-phrase (BIP39 24-word) display. This is the ONLY safety valve for the
// rotation-less root identity (DID.md): lose the phrase and the identity is
// unrecoverable, so the phrase must be shown to the user at least once and be
// re-viewable on demand. The seed itself is never persisted (see did/store.ts) —
// re-display re-derives it from the envelope + password, same as password change.
import { seedToMnemonic } from '../did/seed.ts'
// password/envelope concept disabled — see showMnemonicWithPassword below.
// import { fetchEnvelope, unsealEnvelope } from '../cryptenv.ts'

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

// The whole flow: the phrase (word grid + warning + copy/close). `onClose`
// runs after the box is dismissed (used to continue a creation flow).
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
  // One screen, no verification (2026-08-12, user-requested). This used to
  // run three more steps after it — type a random word back, then be shown
  // the DID and paste that back too — to catch someone clicking past without
  // saving. The DID half stopped being necessary once logging in only needs
  // the address (the DNS anchor supplies the DID, see account-create.ts's
  // logInExistingAddress), and the word spot-check went with it: it gated
  // account creation on a typing exercise while proving little, since the
  // phrase is on screen the whole time it's being asked for.
  doneBtn.addEventListener('click', () => { dismiss(); opts.onClose?.() })

  btnRow.append(copyBtn, doneBtn)
  box.append(title, sub, grid, warn, btnRow)
}

// Direct display — used right after account creation, when masterSecret is
// already in hand (no password re-entry needed). Takes no DID any more: the
// DID used to be shown and confirmed alongside the phrase because a
// did:webvh restore needed it typed back in, and it isn't derivable from the
// seed. Logging in resolves it from the address's DNS anchor instead
// (account-create.ts's logInExistingAddress), so the phrase is the only
// thing left worth writing down.
export function showMnemonic(masterSecret: Uint8Array, opts: { firstTime: boolean; onClose?: () => void } = { firstTime: true }): void {
  const { box, dismiss } = overlay()
  renderPhrase(box, dismiss, seedToMnemonic(masterSecret), opts)
}

/** Re-display, on demand, long after creation (2026-08-14). Possible at all
 * because the seed is now stored (did/store.ts's header) — it deliberately
 * was not, which is what made the phrase a show-once-or-lose-it secret and
 * made "clicked past the creation screen" a permanent account loss.
 *
 * The gesture comes from `revealMasterSeed`, which re-authenticates against
 * the passkey EVERY time rather than reusing the unlocked session: this is
 * the one action that puts the whole identity on screen in the clear, so it
 * should not ride on an unlock the user performed for something else.
 *
 * Silent on refusal — a cancelled biometric prompt is a decision, not an
 * error worth a dialog. Returns false when there is nothing to show: an
 * identity created before seeds were stored has none until its owner logs in
 * with the phrase once. */
export async function showStoredMnemonic(did: string): Promise<boolean> {
  const { revealMasterSeed } = await import('../did/store.ts')
  const seedHex = await revealMasterSeed(did)
  if (!seedHex) return false
  const seed = new Uint8Array((seedHex.match(/../g) ?? []).map(h => parseInt(h, 16)))
  const { box, dismiss } = overlay()
  renderPhrase(box, dismiss, seedToMnemonic(seed), { firstTime: false })
  return true
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
