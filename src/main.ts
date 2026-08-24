import type { AccountSession } from './local-jmap/transport.ts'
import { IndexedDbIdentityRecordStore } from './identity/record-store.ts'
import { buildLocalJmapReadModel, maintainSelfGroup } from './identity/bootstrap.ts'
import { IndexedDbMlsSelfGroupStore } from './mls/store.ts'
import { IndexedDbMlsKeyPackageStore } from './mls/keypackage-store.ts'
import { IndexedDbVaultStore } from './vault/store.ts'
import { setupNewUserPage } from './ui/account-create.ts'
import { refreshInbox, showApp, showSysMsg } from './ui/shell.ts'

declare const __BISET_CONFIG__: { coreBaseUrl?: string } | undefined

/**
 * New-client bootstrap. The only branch this makes is "does this device
 * already have an identity locally": with none, it shows the new-user page
 * (ui/account-create.ts, identity/bootstrap.ts's createNewIdentity). With
 * one, it opens the read-only inbox first slice (PLAN.md §7's plan) against
 * the first local identity's vault, and still runs `maintainSelfGroup` for
 * every local identity (self-group catch-up + roster reflection + KeyPackage
 * pool top-up) so a second identity on this device doesn't silently drift
 * out of sync just because there's no account switcher yet.
 */
export async function bootClient(): Promise<void> {
  const newUserPage = document.getElementById('new-user-page')

  const records = await new IndexedDbIdentityRecordStore().list().catch(() => [])
  if (records.length === 0) {
    if (newUserPage) newUserPage.style.display = 'flex'
    setupNewUserPage()
    return
  }

  if (newUserPage) newUserPage.style.display = 'none'

  const selfGroupStore = new IndexedDbMlsSelfGroupStore()
  const vaultStore = await IndexedDbVaultStore.open()
  // Single-account slice: the vault UI reads the first local identity's
  // vault. maintainSelfGroup below still runs for every identity on this
  // device, so a second one doesn't silently drift out of sync just because
  // there's no account switcher yet (PLAN.md §7 plan, out of scope).
  const readModel = buildLocalJmapReadModel(vaultStore, selfGroupStore, records[0]!.did)
  showApp()
  await refreshInbox(readModel).catch(e => {
    showSysMsg('Could not load the inbox')
    console.warn('[refreshInbox]', e instanceof Error ? e.message : e)
  })

  const coreBaseUrl = (window as unknown as { __BISET_CONFIG__?: typeof __BISET_CONFIG__ }).__BISET_CONFIG__?.coreBaseUrl
  if (!coreBaseUrl) return
  const keyStore = new IndexedDbMlsKeyPackageStore()
  for (const record of records) {
    await maintainSelfGroup(selfGroupStore, keyStore, record, { coreBaseUrl, wraps: vaultStore, segments: vaultStore }).catch(e => {
      console.warn(`[maintainSelfGroup] ${record.did}:`, e instanceof Error ? e.message : e)
    })
  }
}

/** Keeps the initial public API explicit while account routing is implemented. */
export function accountKind(session: AccountSession): AccountSession['kind'] {
  return session.kind
}

bootClient()
