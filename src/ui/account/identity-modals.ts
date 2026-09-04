import { esc } from '../format.ts'
import { parseWebvhDid } from '../../identity/webvh/identifier.ts'
import { currentNextKeyHashes } from '../../identity/webvh/prerotation.ts'
import { showMnemonicOnce, promptForMnemonic } from '../mnemonic.ts'
import { seedToMnemonic, mnemonicToSeed } from '../../identity/seed.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import { encodeMultikey } from '../../identity/webvh/multikey.ts'
import { multikeyHashBase58 } from '../../identity/webvh/hash.ts'
import { openModal } from './modal.ts'
import { getAccountConfig } from './state.ts'

/** src.bak's openDisplayNameModal, narrowed: no relay/JMAP Identity write
 * (setLocalDisplayName/applyDisplayNameToRelay -- this rewrite has no
 * per-relay Identity concept), no mediator-gated republish side effect
 * (this rewrite's routing.json IS the one place a name lives, always
 * current the moment onEditName resolves, not something a separate publish
 * step catches up on later). Reachable from the name text/pencil icon
 * directly, same as src.bak's `identityName.onclick` -- NOT only via the
 * identity menu's own "Edit identity" item (found live, 2026-08-26: the
 * pencil icon did nothing because only the menu was wired). */
export function openDisplayNameModal(did: string, currentName: string): void {
  if (!getAccountConfig()?.onEditName) return
  const body = document.createElement('form')
  body.style.cssText = 'display:flex;flex-direction:column;gap:10px'
  body.innerHTML = `
    <div style="font-size:12px;color:var(--text-dim)">${esc(did)}</div>
    <input class="cmd-input" type="text" name="name" value="${esc(currentName)}" placeholder="Display name" required autofocus>
    <div data-role="error" style="color:#ff3b30;font-size:12px;display:none"></div>
    <div data-role="ok" style="color:#34c759;font-size:12px;display:none"></div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:4px">
      <button type="button" data-role="cancel" class="cmd-page-btn" style="width:auto;padding:6px 14px">Cancel</button>
      <button type="submit" data-role="submit" class="cmd-page-btn primary" style="width:auto;padding:6px 14px">Save</button>
    </div>`
  const dismiss = openModal('Change display name', body)
  body.querySelector<HTMLButtonElement>('[data-role=cancel]')!.addEventListener('click', dismiss)
  body.addEventListener('submit', async ev => {
    ev.preventDefault()
    const newName = (body.elements.namedItem('name') as HTMLInputElement).value.trim()
    const errEl = body.querySelector<HTMLElement>('[data-role=error]')!
    const okEl = body.querySelector<HTMLElement>('[data-role=ok]')!
    const submit = body.querySelector<HTMLButtonElement>('[data-role=submit]')!
    errEl.style.display = 'none'; okEl.style.display = 'none'
    if (!newName) { errEl.textContent = 'Display name required'; errEl.style.display = 'block'; return }
    submit.disabled = true; submit.textContent = 'Saving…'
    try {
      await getAccountConfig()!.onEditName!(newName)
      const identityNameEl = document.getElementById('cmd-acc-identity-name')
      if (identityNameEl) identityNameEl.textContent = newName
      okEl.textContent = 'Saved'; okEl.style.display = 'block'
      setTimeout(dismiss, 600)
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : 'Save failed'
      errEl.style.display = 'block'
    } finally {
      submit.disabled = false; submit.textContent = 'Save'
    }
  })
}

/** Ported from src.bak/did/webvh/publish.ts's own availability check
 * (via src.bak/ui/edit-identity.ts's checkAvailability), narrowed to
 * domain only -- this rewrite's did:webvh has no username path segment
 * (subdomain-per-identity, identity/webvh/identifier.ts), so there is no
 * separate axis to check. GET the candidate domain's own did.jsonl: 404 is
 * available, 200 with a different SCID in its first entry is taken, 200
 * with THIS identity's own SCID is "you used to be here", anything else is
 * honestly unknown rather than a false "available". */
async function checkDomainAvailability(domain: string, ownScid: string): Promise<'available' | 'taken' | 'own-history' | 'unknown'> {
  if (!domain) return 'unknown'
  try {
    const resp = await fetch(`https://${domain}/.well-known/did.jsonl`, { method: 'GET' })
    if (resp.status === 404) return 'available'
    if (!resp.ok) return 'unknown'
    try {
      const firstLine = (await resp.text()).split('\n').map(l => l.trim()).find(Boolean)
      const scid = firstLine ? (JSON.parse(firstLine) as { parameters?: { scid?: string } }).parameters?.scid : undefined
      return scid === ownScid ? 'own-history' : 'taken'
    } catch {
      return 'taken'
    }
  } catch {
    return 'unknown'
  }
}

/** Ported from src.bak/ui/edit-identity.ts's openEditIdentityModal, narrowed
 * to domain only (see checkDomainAvailability's own note on why there is no
 * username field here) -- everything else (the confirm-before-submit
 * copy, the availability line, the domain-changed warning) is that file's
 * own markup and wording, verbatim. */
export function openEditIdentityModal(did: string): void {
  if (!getAccountConfig()?.onMoveIdentity) return
  let currentDomain: string, currentScid: string
  try {
    const parsed = parseWebvhDid(did)
    currentDomain = parsed.domain
    currentScid = parsed.scid
  } catch {
    return
  }

  const body = document.createElement('form')
  body.style.cssText = 'display:flex;flex-direction:column;gap:10px'
  body.innerHTML = `
      <div style="font-size:12px;color:var(--text-dim)">
        Change this identity's domain. The identity's underlying key stays
        the same, so a contact who already knows you follows the change
        automatically the next time they resolve you.
      </div>
      <div data-role="domain-warning" style="font-size:12px;color:var(--text-dim)">
        Changing the domain moves this identity to a new destination. What
        that destination does with it from here on is entirely up to that
        destination, not biset — this only edits the bare identity document.
        Your mail address updates to match; existing mail history and your
        PGP key carry over unchanged.
      </div>
      <div style="display:flex;flex-direction:column;gap:3px">
        <label style="font-size:11px;color:var(--text-dim)">Domain</label>
        <input class="cmd-input" type="text" name="domain" required>
      </div>
      <div data-role="availability" style="font-size:12px;color:var(--text-dim);min-height:16px"></div>
      <div data-role="error" style="color:#ff3b30;font-size:12px;display:none"></div>
      <div data-role="ok" style="color:#34c759;font-size:12px;display:none"></div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:4px">
        <button type="button" data-role="cancel" class="cmd-page-btn" style="width:auto;padding:6px 14px">Cancel</button>
        <button type="submit" data-role="submit" class="cmd-page-btn primary" style="width:auto;padding:6px 14px" disabled>Save</button>
      </div>`
  const dismiss = openModal('Edit identity', body)
  body.querySelector<HTMLButtonElement>('[data-role=cancel]')!.addEventListener('click', dismiss)

  const domainInput = body.elements.namedItem('domain') as HTMLInputElement
  domainInput.value = currentDomain

  const availEl = body.querySelector<HTMLElement>('[data-role=availability]')!
  const submit = body.querySelector<HTMLButtonElement>('[data-role=submit]')!
  let availToken = 0

  const setSubmitEnabled = (enabled: boolean): void => {
    submit.disabled = !enabled
    submit.style.opacity = enabled ? '1' : '0.4'
    submit.style.cursor = enabled ? 'pointer' : 'not-allowed'
  }
  setSubmitEnabled(false)

  const refresh = (): void => {
    const domain = domainInput.value.trim().toLowerCase()
    const unchanged = domain === currentDomain
    setSubmitEnabled(!unchanged && !!domain)
    if (unchanged || !domain) { availEl.textContent = ''; return }
    const token = ++availToken
    availEl.textContent = 'Checking availability…'
    checkDomainAvailability(domain, currentScid).then(status => {
      if (token !== availToken) return
      availEl.textContent = status === 'available' ? '✓ Available'
        : status === 'own-history' ? '↺ You used to be here — may or may not accept a move back, depending on the destination'
        : status === 'taken' ? '✗ Already in use at that location'
        : '? Could not check — the destination may not answer GET, or is unreachable'
      availEl.style.color = status === 'available' ? '#34c759' : status === 'own-history' ? '#ff9500' : status === 'taken' ? '#ff3b30' : 'var(--text-dim)'
    })
  }
  domainInput.addEventListener('input', refresh)

  body.addEventListener('submit', async ev => {
    ev.preventDefault()
    const domain = domainInput.value.trim().toLowerCase()
    const errEl = body.querySelector<HTMLElement>('[data-role=error]')!
    const okEl = body.querySelector<HTMLElement>('[data-role=ok]')!
    errEl.style.display = 'none'; okEl.style.display = 'none'
    if (!domain) { errEl.textContent = 'Domain required'; errEl.style.display = 'block'; return }
    if (!confirm(`This will move this identity to ${domain}. It publishes a move entry to your current location and to the new one. It cannot be undone from here.`)) return

    setSubmitEnabled(false); submit.textContent = 'Saving…'
    try {
      const expectedHashes = await currentNextKeyHashes(did)
      const phrase = await promptForMnemonic({ title: 'Current Spare Key', badges: ['SPARE KEY'], expectedHashes, subtitle: 'A domain move is also a permanent pre-rotation transition.' })
      if (!phrase) return
      const revealed = spareKeyFromSeed(mnemonicToSeed(phrase))
      const nextSeed = crypto.getRandomValues(new Uint8Array(32))
      const nextSpare = spareKeyFromSeed(nextSeed)
      const nextKeyHash = multikeyHashBase58(encodeMultikey(nextSpare.publicKey))
      await showMnemonicOnce(seedToMnemonic(nextSeed), { firstTime: false, title: 'New Spare Key', badges: ['SPARE KEY'], fingerprint: encodeMultikey(nextSpare.publicKey), subtitle: 'Write this down. The previous Spare Key becomes the current Sign Key when the move completes.' })
      const newDid = await getAccountConfig()!.onMoveIdentity!(domain, revealed.privateKey, revealed.publicKey, nextKeyHash)
      okEl.textContent = `Saved — now ${newDid}`
      okEl.style.display = 'block'
      setTimeout(dismiss, 1200)
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : String(e)
      errEl.style.display = 'block'
    } finally {
      setSubmitEnabled(true); submit.textContent = 'Save'
    }
  })
}

/** A Spare/Sign Key phrase is its OWN independent 32-byte random seed, not
 * part of this identity's BIP39-master-seed hierarchy (unlike the Root Key,
 * identity/keys.ts's deriveRootKey) — so there is nothing to derive via
 * SLIP-10; the raw seed IS the ed25519 private key, same convention
 * ui/mnemonic.ts's promptForMnemonic echo already assumes. Using
 * deriveRootKey here would silently produce a DIFFERENT keypair than what
 * the echo shows, so the two must stay in lockstep. */
function spareKeyFromSeed(seed: Uint8Array): { privateKey: Uint8Array; publicKey: Uint8Array } {
  return { privateKey: seed, publicKey: ed25519.getPublicKey(seed) }
}
