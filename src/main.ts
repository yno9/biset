import type { AccountSession } from './local-jmap/transport.ts'

/**
 * New-client bootstrap. Feature modules are intentionally not imported until
 * the local vault and Local JMAP contracts are implemented.
 */
export function bootClient(): void {
  const root = document.querySelector<HTMLElement>('#app') ?? document.body
  root.replaceChildren()

  const heading = document.createElement('h1')
  heading.textContent = 'biset'
  const description = document.createElement('p')
  description.textContent = 'Vault Core を初期化しています。'
  root.append(heading, description)
}

/** Keeps the initial public API explicit while account routing is implemented. */
export function accountKind(session: AccountSession): AccountSession['kind'] {
  return session.kind
}

bootClient()
