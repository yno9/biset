import type { AccountSession, AccountTransport, LocalVaultSession, RemoteJmapSession } from './transport.ts'

export type BisetAccountId = `biset:${string}`
export type RemoteAccountId = `remote:${string}:${string}`

export type ParsedAccountId =
  | { kind: 'local-vault'; accountId: BisetAccountId; identityId: string }
  | { kind: 'remote-jmap'; accountId: RemoteAccountId; provider: string; remoteId: string }

export function localAccountId(identityId: string): BisetAccountId {
  if (!identityId) throw new TypeError('Biset identity ID is required')
  return `biset:${identityId}`
}

export function remoteAccountId(provider: string, id: string): RemoteAccountId {
  if (!provider || !id || provider.includes(':') || id.includes(':')) throw new TypeError('remote provider and ID must be non-empty colon-free strings')
  return `remote:${provider}:${id}`
}

export function parseAccountId(value: string): ParsedAccountId {
  if (value.startsWith('biset:') && value.length > 'biset:'.length) {
    return { kind: 'local-vault', accountId: value as BisetAccountId, identityId: value.slice('biset:'.length) }
  }
  if (value.startsWith('remote:')) {
    const parts = value.split(':')
    if (parts.length === 3 && parts[1] && parts[2]) {
      return { kind: 'remote-jmap', accountId: value as RemoteAccountId, provider: parts[1], remoteId: parts[2] }
    }
  }
  throw new TypeError('unsupported account ID')
}

/**
 * UI code resolves one account to one transport. It intentionally exposes no
 * multi-account `call`, because JMAP has no atomic batch across backends.
 */
export class AccountRouter {
  private readonly sessions = new Map<string, AccountSession>()

  registerLocal(identityId: string, jmap: AccountTransport): LocalVaultSession {
    const accountId = localAccountId(identityId)
    const session: LocalVaultSession = { kind: 'local-vault', accountId, identityId, jmap }
    this.register(session)
    return session
  }

  registerRemote(provider: string, id: string, jmap: AccountTransport): RemoteJmapSession {
    const accountId = remoteAccountId(provider, id)
    const session: RemoteJmapSession = { kind: 'remote-jmap', accountId, jmap }
    this.register(session)
    return session
  }

  resolve(accountId: string): AccountSession {
    parseAccountId(accountId)
    const session = this.sessions.get(accountId)
    if (!session) throw new Error('account is not registered in this client')
    return session
  }

  list(): AccountSession[] {
    return [...this.sessions.values()]
  }

  private register(session: AccountSession): void {
    if (this.sessions.has(session.accountId)) throw new TypeError('account is already registered')
    this.sessions.set(session.accountId, session)
  }
}
