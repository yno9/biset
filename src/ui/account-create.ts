// New-identity onboarding (#app's own new-user-page, index.html). Ported at
// the flow level from src.bak/ui/account-create.ts's submit handler, cut
// down to what identity/bootstrap.ts's createNewIdentity actually needs:
// username -> subdomain, submit, mnemonic. Left out (all present in the
// pre-rewrite version, none ported yet):
//
//   - "is this name already someone's?" DNS-anchor lookup that turned the
//     form into a login (src.bak/did/discovery.ts) -- there is no restore
//     path yet (identity/bootstrap.ts's own header), so every submit here
//     is unconditionally a signup.
//   - mail/AP relay reachability gating and provisioning, DIDComm mediator
//     registration -- all relay-adapter/DIDComm-adapter concerns this
//     rewrite does not have yet (PLAN.md §6).
//   - passkey-sealed-at-rest enrollment after showing the mnemonic
//     (record-store.ts's own note on why secrets are still plaintext).
import { createNewIdentity } from '../identity/bootstrap.ts'
import { IndexedDbIdentityRecordStore } from '../identity/record-store.ts'
import { IndexedDbMlsSelfGroupStore } from '../mls/store.ts'
import { IndexedDbMlsKeyPackageStore } from '../mls/keypackage-store.ts'
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

export function setupNewUserPage(): void {
  if (_wired) return
  _wired = true

  const usernameInput = document.getElementById('nu-username') as HTMLInputElement
  const submitBtn = document.getElementById('nu-submit') as HTMLButtonElement
  const errEl = document.getElementById('nu-error')!
  const apexEl = document.getElementById('nu-apex')

  const { apexDomain } = config()
  if (apexEl) apexEl.textContent = apexDomain
  usernameInput.value = randomHex4()

  submitBtn.addEventListener('click', async () => {
    const { apexDomain, coreBaseUrl } = config()
    const username = usernameInput.value.trim()
    errEl.style.display = 'none'
    if (!username) { errEl.textContent = 'Username required'; errEl.style.display = 'block'; return }
    if (!apexDomain) { errEl.textContent = 'apexDomain not set in config'; errEl.style.display = 'block'; return }
    if (!coreBaseUrl) { errEl.textContent = 'coreBaseUrl not set in config'; errEl.style.display = 'block'; return }

    submitBtn.disabled = true
    submitBtn.textContent = 'Creating…'
    try {
      const recordStore = new IndexedDbIdentityRecordStore()
      const selfGroupStore = new IndexedDbMlsSelfGroupStore()
      const keyStore = new IndexedDbMlsKeyPackageStore()
      const created = await createNewIdentity(recordStore, selfGroupStore, keyStore, {
        domain: `${username}.${apexDomain}`, coreBaseUrl, didWebMirror: true,
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
