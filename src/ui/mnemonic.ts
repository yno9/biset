// Recovery-phrase (BIP39 24-word) display. This is the ONLY safety valve for the
// rotation-less root identity (DID.md): lose the phrase and the identity is
// unrecoverable, so the phrase must be shown to the user at least once and be
// re-viewable on demand. The seed itself is never persisted (see did/store.ts) —
// re-display re-derives it from the envelope + password, same as password change.
import { seedToMnemonic, isValidMnemonic, mnemonicToSeed } from '../did/seed.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import { encodeMultikey } from '../did/webvh/multikey.ts'
import { multikeyHashBase58 } from '../did/webvh/hash.ts'
import { deriveRootKey } from '../did/keys.ts'

/** The Root Key's private scalar for a given seed — `#key-1` is
 * `deriveRootKey`'s SLIP-0010 output, never the raw seed (did/restore.ts
 * re-derives the same way before comparing), so a fingerprint shown next to a
 * ROOT KEY phrase has to go through it too or it would label the wrong key. */
function deriveRootKeySeed(seed: Uint8Array): Uint8Array {
  return deriveRootKey(seed).privateKey
}
// password/envelope concept disabled — see showMnemonicWithPassword below.
// import { fetchEnvelope, unsealEnvelope } from '../cryptenv.ts'

/** `onEscape`, when given, runs INSTEAD of the plain dismiss on the Escape
 * key — for a Promise-returning caller (showMnemonicOnce/promptForMnemonic
 * below) that must settle its promise no matter how the box closes, not
 * just when its own button is clicked. Existing callers (showMnemonic,
 * showStoredMnemonic) don't pass it, so Escape there is unchanged: just a
 * close, nothing to settle. */
function overlay(onEscape?: () => void): { root: HTMLElement; box: HTMLElement; dismiss: () => void } {
  const root = document.createElement('div')
  root.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:10002;display:flex;align-items:center;justify-content:center;padding:16px'
  const box = document.createElement('div')
  box.style.cssText = 'background:var(--bg);color:var(--text);border-radius:12px;padding:22px;max-width:460px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,0.35);max-height:92vh;overflow:auto'
  root.appendChild(box)
  const onKey = (ev: KeyboardEvent) => { if (ev.key === 'Escape') (onEscape ?? dismiss)() }
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
function renderPhrase(box: HTMLElement, dismiss: () => void, mnemonic: string, opts: { firstTime: boolean; onClose?: () => void; title?: string; subtitle?: string; badges?: string[]; fingerprint?: string }): void {
  box.textContent = ''
  const titleRow = document.createElement('div')
  titleRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin:0 0 4px;flex-wrap:wrap'
  // Own label chips, not a font change on the title — ROOT KEY (identity
  // creation) and SIGN KEY (pre-rotation, ui/prerotation.ts) name WHAT this
  // phrase controls, and a genesis identity's phrase controls both at once
  // (webvh/publish.ts's createGenesis: updateKeys and #key-1 start out as
  // the exact same key) — one badge could only ever say one of the two
  // (2026-08-17, user-requested after account creation's screen showed only
  // ROOT KEY for a phrase that was, at that moment, equally a sign key).
  for (const b of opts.badges ?? []) {
    const badge = document.createElement('span')
    badge.textContent = b
    badge.style.cssText = 'font-family:ui-monospace,monospace;font-size:11px;font-weight:800;letter-spacing:0.04em;color:var(--accent);background:var(--input-bg);border-radius:5px;padding:2px 6px;flex-shrink:0'
    titleRow.appendChild(badge)
  }
  const title = document.createElement('h3')
  title.textContent = opts.title ?? 'Recovery phrase'
  title.style.cssText = 'margin:0;font-size:17px' + (opts.badges?.length ? ';margin-left:6px' : '')
  titleRow.appendChild(title)
  const sub = document.createElement('div')
  sub.textContent = opts.subtitle ?? (opts.firstTime
    ? 'Copy these 24 words and keep them somewhere safe. Anyone with this phrase can take over your identity.'
    : 'These 24 words restore your identity on any device.')
  sub.style.cssText = 'font-size:13px;color:var(--text-dim);line-height:1.4'

  const grid = wordGrid(mnemonic)

  // The public key these words derive to, so the paper copy can be labelled
  // and later matched against what #config shows (PLANROTATION.md §3.4).
  // Three phrases can be in play at once — Root, Sign and Spare — and without
  // this there is no way to tell which one a given piece of paper is.
  const fp = document.createElement('div')
  if (opts.fingerprint) {
    fp.style.cssText = 'font-family:ui-monospace,monospace;font-size:11px;color:var(--text-dim);margin:-8px 0 14px;word-break:break-all'
    fp.textContent = `\u2192 ${opts.fingerprint}`
  }

  const btnRow = document.createElement('div')
  btnRow.style.cssText = 'display:flex;justify-content:flex-end;gap:8px'
  const copyBtn = document.createElement('button')
  copyBtn.type = 'button'
  copyBtn.className = 'cmd-page-btn'
  copyBtn.textContent = 'Copy'
  copyBtn.style.cssText = 'width:auto;padding:7px 16px'
  const doneBtn = document.createElement('button')
  doneBtn.type = 'button'
  doneBtn.className = 'cmd-page-btn primary'
  doneBtn.textContent = opts.firstTime ? "I've saved it" : 'Close'
  doneBtn.style.cssText = 'width:auto;padding:7px 16px'
  // Copy-gated (2026-08-17, user-requested): "I've saved it" is not proof of
  // anything on its own — someone can click straight past it without ever
  // having copied the phrase anywhere. Requiring a Copy click first at least
  // means the phrase left this box in some form before the flow can close.
  if (opts.firstTime) {
    doneBtn.disabled = true
    doneBtn.style.opacity = '0.5'
    doneBtn.style.cursor = 'not-allowed'
  }
  copyBtn.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(mnemonic); copyBtn.textContent = 'Copied'; setTimeout(() => { copyBtn.textContent = 'Copy' }, 1200) } catch {}
    doneBtn.disabled = false
    doneBtn.style.opacity = ''
    doneBtn.style.cursor = ''
  })
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
  box.append(titleRow, sub, grid, ...(opts.fingerprint ? [fp] : []), btnRow)
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
  // At genesis, updateKeys and #key-1 start out as the exact same key
  // (webvh/publish.ts's createGenesis) — this phrase genuinely controls
  // both until the first activate/rotate/revoke ever moves updateKeys away.
  // Safe precisely because there is no SPARE KEY yet (nextKeyHashes is
  // empty): sharing one phrase between root and sign only becomes a problem
  // once a lever exists to leak — PLANROTATION.md §3.1's rejected option D.
  renderPhrase(box, dismiss, seedToMnemonic(masterSecret), {
    ...opts,
    badges: ['ROOT KEY', 'SIGN KEY'],
    fingerprint: encodeMultikey(ed25519.getPublicKey(deriveRootKeySeed(masterSecret))),
  })
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
  // Re-display doesn't know whether updateKeys has since moved away from
  // #key-1 (an activate/rotate any time after creation would do that) —
  // labelling this SIGN KEY too would overclaim once that's happened, so
  // this stays the one badge that's always true regardless of pre-rotation
  // history: this phrase controls #key-1 (the identity) unconditionally.
  renderPhrase(box, dismiss, seedToMnemonic(seed), {
    firstTime: false,
    badges: ['ROOT KEY'],
    fingerprint: encodeMultikey(ed25519.getPublicKey(deriveRootKeySeed(seed))),
  })
  return true
}

/** Sign Key counterpart, from the #config Key rotation card's own click
 * affordance (this replaces the identity menu's old "Show recovery phrase"
 * item, split into two — one per key — 2026-08-17). Same re-authenticate
 * gesture as showStoredMnemonic, via revealSigningKey.
 *
 * signingPrivateKey is stored ONLY once updateKeys has actually diverged
 * from #key-1 (cacheSigningKey's own note) — before that, the Sign Key IS
 * the Root Key, same secret, so there is nothing distinct to reveal. Falls
 * back to the Root Key display in that case rather than reporting "nothing
 * stored", which would read as a bug rather than the expected state. */
export async function showSignKeyMnemonic(did: string): Promise<boolean> {
  const { revealSigningKey } = await import('../did/store.ts')
  const keyHex = await revealSigningKey(did)
  if (!keyHex) return showStoredMnemonic(did)
  const key = new Uint8Array((keyHex.match(/../g) ?? []).map(h => parseInt(h, 16)))
  const { box, dismiss } = overlay()
  // Unlike the Root Key, signingPrivateKey IS the raw 32-byte seed already
  // (generateSpareKeypair never derives it) — seedToMnemonic applies
  // directly, with no deriveRootKey step.
  renderPhrase(box, dismiss, seedToMnemonic(key), {
    firstTime: false,
    badges: ['SIGN KEY'],
    fingerprint: encodeMultikey(ed25519.getPublicKey(key)),
  })
  return true
}

/** Promise-based display for a mnemonic that is NOT the identity's main
 * recovery phrase — ui/prerotation.ts's pre-rotation spare key, shown once
 * right after it's generated. Resolves when the user confirms they saved
 * it (or closes the box, which counts the same way `renderPhrase`'s own
 * "I've saved it" button always has — there is no verification step here,
 * same reasoning as showMnemonic's own note on why one was removed). */
export function showMnemonicOnce(mnemonic: string, opts: { firstTime: boolean; title?: string; subtitle?: string; badges?: string[]; fingerprint?: string }): Promise<void> {
  return new Promise(resolve => {
    let settled = false
    const settle = () => { if (settled) return; settled = true; resolve() }
    const { box, dismiss } = overlay(() => { dismiss(); settle() })
    renderPhrase(box, dismiss, mnemonic, { ...opts, onClose: settle })
  })
}

/** The input counterpart: asks for a 24-word phrase pasted or typed as one
 * block, validates it as a real BIP39 mnemonic before resolving. Used by
 * ui/prerotation.ts wherever a saved pre-rotation phrase needs to be
 * produced (rotating into it, or deactivating pre-rotation — both require
 * it, see prerotation.ts's own header on why). Resolves `null` on cancel. */
export function promptForMnemonic(opts: { title: string; subtitle: string; badges?: string[]; expectedFingerprint?: string; expectedHashes?: string[] }): Promise<string | null> {
  return new Promise(resolve => {
    let settled = false
    const settle = (value: string | null) => { if (settled) return; settled = true; dismiss(); resolve(value) }
    const { box, dismiss } = overlay(() => settle(null))

    const form = document.createElement('form')
    form.autocomplete = 'off'
    form.style.cssText = 'display:flex;flex-direction:column;gap:10px'
    const titleRow = document.createElement('div')
    titleRow.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap'
    // Same chip convention as mnemonic.ts's renderPhrase — names WHAT this
    // prompt is asking for, since "your recovery phrase" is ambiguous once
    // an identity has both a root phrase and a sign-key phrase (2026-08-17,
    // user: syncのフレーズ要求がわかりにくい).
    for (const b of opts.badges ?? []) {
      const badge = document.createElement('span')
      badge.textContent = b
      badge.style.cssText = 'font-family:ui-monospace,monospace;font-size:11px;font-weight:800;letter-spacing:0.04em;color:var(--accent);background:var(--input-bg);border-radius:5px;padding:2px 6px;flex-shrink:0'
      titleRow.appendChild(badge)
    }
    const title = document.createElement('h3')
    title.textContent = opts.title
    title.style.cssText = 'margin:0;font-size:17px'
    titleRow.appendChild(title)
    const sub = document.createElement('div')
    sub.textContent = opts.subtitle
    sub.style.cssText = 'font-size:13px;color:var(--text-dim);line-height:1.4'
    const textarea = document.createElement('textarea')
    textarea.className = 'cmd-input'
    textarea.rows = 4
    textarea.placeholder = '24 words, separated by spaces'
    textarea.style.cssText = 'font-family:ui-monospace,monospace;resize:vertical'
    // Which key the typed words actually are, echoed live, so a paper labelled
    // at display time (renderPhrase's own fingerprint line) can be matched
    // BEFORE submitting — three phrases can be in play at once (Root / Sign /
    // Spare) and "wrong words" after the fact is a poor way to find out
    // (PLANROTATION.md §3.4). Raw multikey, not deriveRootKey's: both prompt
    // sites (revealAndVerify, revealCurrentSigner) want the raw key.
    const echo = document.createElement('div')
    echo.style.cssText = 'font-family:ui-monospace,monospace;font-size:11px;color:var(--text-dim);min-height:14px;word-break:break-all'
    if (opts.expectedFingerprint) echo.textContent = `expected \u2192 ${opts.expectedFingerprint}`
    const err = document.createElement('div')
    err.style.cssText = 'color:#ff3b30;font-size:12px;display:none'
    const row = document.createElement('div')
    row.style.cssText = 'display:flex;justify-content:flex-end;gap:8px;margin-top:4px'
    const cancel = document.createElement('button')
    cancel.type = 'button'; cancel.className = 'cmd-page-btn'; cancel.textContent = 'Cancel'
    cancel.style.cssText = 'width:auto;padding:6px 14px'
    cancel.addEventListener('click', () => settle(null))
    const submit = document.createElement('button')
    submit.type = 'submit'; submit.className = 'cmd-page-btn primary'; submit.textContent = 'Continue'
    submit.style.cssText = 'width:auto;padding:6px 14px'
    row.append(cancel, submit)
    form.append(titleRow, sub, textarea, echo, err, row)
    box.appendChild(form)
    textarea.focus()

    const refreshEcho = () => {
      const phrase = textarea.value.trim().toLowerCase().replace(/\s+/g, ' ')
      if (!isValidMnemonic(phrase)) {
        echo.textContent = opts.expectedFingerprint ? `expected \u2192 ${opts.expectedFingerprint}` : ''
        echo.style.color = 'var(--text-dim)'
        return
      }
      const mk = encodeMultikey(ed25519.getPublicKey(mnemonicToSeed(phrase)))
      // Two shapes of expectation. A Sign Key prompt knows the multikey
      // outright (it is in the log's updateKeys). A Spare Key prompt only has
      // hash(multikey) — nextKeyHashes never carries the key itself, that
      // being the whole point of a commitment — so it checks in hash space
      // while still echoing the multikey, which is what the paper was
      // labelled with at display time.
      const matches = opts.expectedHashes?.length
        ? opts.expectedHashes.includes(multikeyHashBase58(mk))
        : opts.expectedFingerprint ? mk === opts.expectedFingerprint : null
      echo.textContent = `${matches === false ? '\u2717' : matches === true ? '\u2713' : '\u2192'} ${mk}`
      echo.style.color = matches === false ? '#ff3b30' : matches === true ? '#34c759' : 'var(--text-dim)'
    }
    textarea.addEventListener('input', refreshEcho)

    form.addEventListener('submit', ev => {
      ev.preventDefault()
      const phrase = textarea.value.trim().toLowerCase().replace(/\s+/g, ' ')
      if (!isValidMnemonic(phrase)) {
        err.textContent = 'Not a valid 24-word phrase'
        err.style.display = 'block'
        return
      }
      settle(phrase)
    })
  })
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
