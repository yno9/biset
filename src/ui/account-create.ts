// New-identity onboarding AND recovery-phrase login (#app's own
// new-user-page, index.html). Ported at the flow level from
// src.bak/ui/account-create.ts's submit handler (both its signup and its
// logInExistingAddress branches), cut down to what identity/bootstrap.ts's
// createNewIdentity/restoreIdentity actually need. Left out (all present in
// the pre-rewrite version, none ported yet):
//
//   - "is this name already someone's?" DNS-anchor lookup that decided
//     signup-vs-login automatically (src.bak/did/discovery.ts) -- this
//     rewrite has no such lookup, so the user picks login explicitly via
//     the "Log in with a recovery phrase" toggle instead.
//   - mail/AP relay reachability gating and provisioning, DIDComm mediator
//     registration -- all relay-adapter/DIDComm-adapter concerns this
//     rewrite does not have yet (PLAN.md §6).
//   - passkey-sealed-at-rest enrollment after showing the mnemonic
//     (record-store.ts's own note on why secrets are still plaintext).
import { createNewIdentity, restoreIdentity } from '../identity/bootstrap.ts'
import { IndexedDbIdentityRecordStore } from '../identity/record-store.ts'
import { IndexedDbMlsSelfGroupStore } from '../mls/store.ts'
import { IndexedDbMlsKeyPackageStore } from '../mls/keypackage-store.ts'
import { deliverySeq } from '../protocol/ids.ts'
import { showMnemonic } from './mnemonic.ts'

declare const __BISET_CONFIG__: { apexDomain?: string; coreBaseUrl?: string } | undefined

function config(): { apexDomain: string; coreBaseUrl: string } {
  const cfg = (window as unknown as { __BISET_CONFIG__?: typeof __BISET_CONFIG__ }).__BISET_CONFIG__ ?? {}
  return { apexDomain: cfg.apexDomain ?? '', coreBaseUrl: cfg.coreBaseUrl ?? '' }
}

export function randomHex4(): string {
  const arr = new Uint32Array(1)
  crypto.getRandomValues(arr)
  return (arr[0] & 0xffff).toString(16).padStart(4, '0')
}

let _wired = false
let loginMode = false

export function setupNewUserPage(): void {
  if (_wired) return
  _wired = true

  const usernameInput = document.getElementById('nu-username') as HTMLInputElement
  const phraseEl = document.getElementById('nu-phrase') as HTMLTextAreaElement
  const submitBtn = document.getElementById('nu-submit') as HTMLButtonElement
  const errEl = document.getElementById('nu-error')!
  const apexEl = document.getElementById('nu-apex')
  const toggleLink = document.getElementById('nu-toggle-login')!

  const { apexDomain } = config()
  if (apexEl) apexEl.textContent = apexDomain
  usernameInput.value = randomHex4()

  const applyMode = () => {
    phraseEl.style.display = loginMode ? '' : 'none'
    submitBtn.textContent = loginMode ? 'Log in' : 'Create'
    toggleLink.textContent = loginMode ? 'Create a new identity instead' : 'Log in with a recovery phrase instead'
    errEl.style.display = 'none'
  }
  toggleLink.addEventListener('click', ev => {
    ev.preventDefault()
    loginMode = !loginMode
    applyMode()
  })
  applyMode()

  submitBtn.addEventListener('click', async () => {
    const { apexDomain, coreBaseUrl } = config()
    const username = usernameInput.value.trim()
    errEl.style.display = 'none'
    if (!username) { errEl.textContent = 'Username required'; errEl.style.display = 'block'; return }
    if (!apexDomain) { errEl.textContent = 'apexDomain not set in config'; errEl.style.display = 'block'; return }
    if (!coreBaseUrl) { errEl.textContent = 'coreBaseUrl not set in config'; errEl.style.display = 'block'; return }
    const domain = `${username}.${apexDomain}`

    if (loginMode) {
      const mnemonic = phraseEl.value.trim()
      if (!mnemonic) { errEl.textContent = 'Paste your 24-word recovery phrase'; errEl.style.display = 'block'; return }

      submitBtn.disabled = true
      submitBtn.textContent = 'Logging in…'
      try {
        const recordStore = new IndexedDbIdentityRecordStore()
        const selfGroupStore = new IndexedDbMlsSelfGroupStore()
        const keyStore = new IndexedDbMlsKeyPackageStore()
        await restoreIdentity(recordStore, selfGroupStore, keyStore, {
          domain, coreBaseUrl, mnemonic, didWebMirror: true,
          // TODO(PLAN.md §2.3/§3.3): should be the CURRENT vault-delivery
          // latestSeq, not 0 -- vault delivery's pull API is not wired up to
          // this UI yet, so a restored device on an identity with existing
          // vault content would wrongly be handed history from the start.
          deliveryFloorForNewDevice: async () => deliverySeq(0n),
        })
        location.reload()
      } catch (e) {
        errEl.textContent = 'Error: ' + (e instanceof Error ? e.message : String(e))
        errEl.style.display = 'block'
        submitBtn.textContent = 'Log in'
        submitBtn.disabled = false
      }
      return
    }

    submitBtn.disabled = true
    submitBtn.textContent = 'Creating…'
    try {
      const recordStore = new IndexedDbIdentityRecordStore()
      const selfGroupStore = new IndexedDbMlsSelfGroupStore()
      const keyStore = new IndexedDbMlsKeyPackageStore()
      const created = await createNewIdentity(recordStore, selfGroupStore, keyStore, {
        domain, coreBaseUrl, didWebMirror: true,
      })

      showMnemonic(created.masterSeed, { firstTime: true })
      submitBtn.textContent = 'Created'
    } catch (e) {
      errEl.textContent = 'Error: ' + (e instanceof Error ? e.message : String(e))
      errEl.style.display = 'block'
      submitBtn.textContent = 'Create'
      submitBtn.disabled = false
    }
  })
}
