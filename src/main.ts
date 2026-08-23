import type { AccountSession } from './local-jmap/transport.ts'
import { IndexedDbIdentityRecordStore } from './identity/record-store.ts'
import { maintainSelfGroup } from './identity/bootstrap.ts'
import { IndexedDbMlsSelfGroupStore } from './mls/store.ts'
import { IndexedDbMlsKeyPackageStore } from './mls/keypackage-store.ts'
import { setupNewUserPage } from './ui/account-create.ts'

declare const __BISET_CONFIG__: { coreBaseUrl?: string } | undefined

/**
 * New-client bootstrap. Feature modules are intentionally not imported until
 * the local vault and Local JMAP contracts are implemented.
 *
 * The only branch this makes today is "does this device already have an
 * identity locally": with none, it shows the new-user page
 * (ui/account-create.ts, identity/bootstrap.ts's createNewIdentity). With
 * one, there is no login/vault UI yet to hand off to (PLAN.md §3's local
 * vault ingest workflow and §5's Local JMAP Gateway are both still open),
 * so this just reports the identity found — but still runs
 * `maintainSelfGroup` (self-group catch-up + roster reflection + KeyPackage
 * pool top-up) so an identity found on this device does not silently drift
 * out of sync with other devices just because there is no vault UI to open
 * yet.
 */
export async function bootClient(): Promise<void> {
  const root = document.querySelector<HTMLElement>('#app') ?? document.body
  const newUserPage = document.getElementById('new-user-page')

  const records = await new IndexedDbIdentityRecordStore().list().catch(() => [])
  if (records.length === 0) {
    if (newUserPage) newUserPage.style.display = 'flex'
    setupNewUserPage()
    return
  }

  if (newUserPage) newUserPage.style.display = 'none'
  root.replaceChildren()
  const heading = document.createElement('h1')
  heading.textContent = 'biset'
  const description = document.createElement('p')
  description.textContent = `Identity found: ${records[0]!.did} — vault UI not implemented yet.`
  root.append(heading, description)

  const coreBaseUrl = (window as unknown as { __BISET_CONFIG__?: typeof __BISET_CONFIG__ }).__BISET_CONFIG__?.coreBaseUrl
  if (!coreBaseUrl) return
  const selfGroupStore = new IndexedDbMlsSelfGroupStore()
  const keyStore = new IndexedDbMlsKeyPackageStore()
  for (const record of records) {
    await maintainSelfGroup(selfGroupStore, keyStore, record, { coreBaseUrl }).catch(e => {
      console.warn(`[maintainSelfGroup] ${record.did}:`, e instanceof Error ? e.message : e)
    })
  }
}

/** Keeps the initial public API explicit while account routing is implemented. */
export function accountKind(session: AccountSession): AccountSession['kind'] {
  return session.kind
}

bootClient()
