// New-identity onboarding AND recovery-phrase login (#app's own
// new-user-page, index.html -- now src.bak's original DOM, restored as-is
// per user direction 2026-08-24; see PLAN.md §7's progress log). Ported at
// the flow level from src.bak/ui/account-create.ts's submit handler (both
// its signup and its logInExistingAddress branches), cut down to what
// identity/bootstrap.ts's createNewIdentity/restoreIdentity actually need.
//
// The original DOM has no explicit signup/login toggle (src.bak's JS used
// a DNS-anchor lookup this rewrite doesn't have to auto-detect which one a
// name meant, src.bak/did/discovery.ts) -- with no such lookup, and no new
// UI element to add (HTML/CSS is being brought back untouched), mode is
// inferred straight from the existing #nu-phrase field instead: filled in
// means login, empty means create. All the fields specific to the old
// did:dht/did:webvh dual scheme or pre-rotation (#nu-sign-phrase, the
// commented-out did-method toggle) stay untouched/hidden -- no equivalent
// concept in this rewrite's identity layer.
//
// Left out (all present in the pre-rewrite version, none ported yet):
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
import { readBisetConfig as config } from './config.ts'

export function randomHex4(): string {
  const arr = new Uint32Array(1)
  crypto.getRandomValues(arr)
  return (arr[0] & 0xffff).toString(16).padStart(4, '0')
}

let _wired = false

export function setupNewUserPage(): void {
  if (_wired) return
  _wired = true

  const usernameInput = document.getElementById('nu-username') as HTMLInputElement
  const phraseEl = document.getElementById('nu-phrase') as HTMLTextAreaElement
  const submitBtn = document.getElementById('nu-submit') as HTMLButtonElement
  const errEl = document.getElementById('nu-error')!
  const hostnameEl = document.getElementById('nu-hostname')
  const tosCheckbox = document.getElementById('nu-tos') as HTMLInputElement | null

  const { apexDomain } = config()
  if (hostnameEl) hostnameEl.textContent = apexDomain
  usernameInput.value = randomHex4()
  // No signup/login toggle in this DOM -- the phrase field is always
  // visible (src.bak had it hidden, shown only after its own now-absent
  // DNS lookup decided this was a login), and its emptiness is the mode
  // signal (see file header).
  phraseEl.style.display = ''

  submitBtn.addEventListener('click', async () => {
    const { apexDomain, coreBaseUrl } = config()
    const username = usernameInput.value.trim()
    const mnemonic = phraseEl.value.trim()
    const loginMode = mnemonic.length > 0
    errEl.style.display = 'none'
    if (!username) { errEl.textContent = 'Username required'; errEl.style.display = 'block'; return }
    if (!apexDomain) { errEl.textContent = 'apexDomain not set in config'; errEl.style.display = 'block'; return }
    if (!coreBaseUrl) { errEl.textContent = 'coreBaseUrl not set in config'; errEl.style.display = 'block'; return }
    if (tosCheckbox && !loginMode && !tosCheckbox.checked) {
      errEl.textContent = 'Please agree to the Terms of Beta-testing'; errEl.style.display = 'block'; return
    }
    const domain = `${username}.${apexDomain}`

    if (loginMode) {
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
        submitBtn.textContent = 'Start'
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
      submitBtn.textContent = 'Start'
      submitBtn.disabled = false
    }
  })
}
