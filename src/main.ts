import type { AccountSession } from './local-jmap/transport.ts'
import { IndexedDbIdentityRecordStore } from './identity/record-store.ts'
import { setupNewUserPage } from './ui/account-create.ts'

/**
 * New-client bootstrap. Feature modules are intentionally not imported until
 * the local vault and Local JMAP contracts are implemented.
 *
 * The only branch this makes today is "does this device already have an
 * identity locally": with none, it shows the new-user page
 * (ui/account-create.ts, identity/bootstrap.ts's createNewIdentity). With
 * one, there is no login/vault UI yet to hand off to (PLAN.md §3's local
 * vault ingest workflow and §5's Local JMAP Gateway are both still open),
 * so this just reports the identity found rather than pretending to open it.
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
}

/** Keeps the initial public API explicit while account routing is implemented. */
export function accountKind(session: AccountSession): AccountSession['kind'] {
  return session.kind
}

bootClient()
