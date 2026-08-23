// Recovery-phrase (BIP39 24-word) display. This is the ONLY safety valve for
// the rotation-less root identity: lose the phrase and the identity is
// unrecoverable, so the phrase must be shown to the user at least once.
//
// Ported near-verbatim from src.bak/ui/mnemonic.ts's showMnemonic (import
// paths retargeted to this rewrite's identity/ module). Left out on
// purpose: showStoredMnemonic/showSignKeyMnemonic/promptForMnemonic — all
// three depend on src.bak/did/store.ts's passkey-sealed re-display
// (revealMasterSeed/revealSigningKey) and pre-rotation, neither ported yet
// (record-store.ts's own note on why secrets are still plaintext at rest).
import { seedToMnemonic } from '../identity/seed.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import { encodeMultikey } from '../identity/webvh/multikey.ts'
import { deriveRootKey } from '../identity/keys.ts'

/** The Root Key's private scalar for a given seed — `#key-1` is
 * `deriveRootKey`'s SLIP-0010 output, never the raw seed, so a fingerprint
 * shown next to a ROOT KEY phrase has to go through it too or it would
 * label the wrong key. */
function deriveRootKeySeed(seed: Uint8Array): Uint8Array {
  return deriveRootKey(seed).privateKey
}

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

function renderPhrase(box: HTMLElement, dismiss: () => void, mnemonic: string, opts: { firstTime: boolean; onClose?: () => void; title?: string; subtitle?: string; badges?: string[]; fingerprint?: string }): void {
  box.textContent = ''
  const titleRow = document.createElement('div')
  titleRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin:0 0 4px;flex-wrap:wrap'
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

  const fp = document.createElement('div')
  if (opts.fingerprint) {
    fp.style.cssText = 'font-family:ui-monospace,monospace;font-size:11px;color:var(--text-dim);margin:-8px 0 14px;word-break:break-all'
    fp.textContent = `→ ${opts.fingerprint}`
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
  // Copy-gated: "I've saved it" is not proof of anything on its own, so
  // requiring a Copy click first at least means the phrase left this box in
  // some form before the flow can close.
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
  doneBtn.addEventListener('click', () => { dismiss(); opts.onClose?.() })

  btnRow.append(copyBtn, doneBtn)
  box.append(titleRow, sub, grid, ...(opts.fingerprint ? [fp] : []), btnRow)
}

/** Direct display — used right after account creation, when masterSecret is
 * already in hand. At genesis, updateKeys and #key-1 start out as the exact
 * same key, so this phrase genuinely controls both. */
export function showMnemonic(masterSecret: Uint8Array, opts: { firstTime: boolean; onClose?: () => void } = { firstTime: true }): void {
  const { box, dismiss } = overlay()
  renderPhrase(box, dismiss, seedToMnemonic(masterSecret), {
    ...opts,
    badges: ['ROOT KEY', 'SIGN KEY'],
    fingerprint: encodeMultikey(ed25519.getPublicKey(deriveRootKeySeed(masterSecret))),
  })
}
