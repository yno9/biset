/**
 * JMAP is the client/backend contract. A Biset identity routes calls locally;
 * a conventional account routes them to its remote JMAP service.
 */
export interface JmapMethodCall {
  name: string
  arguments: Record<string, unknown>
  callId: string
}

export interface JmapSession {
  apiUrl: string
  downloadUrl: string
  capabilities: Record<string, unknown>
  accounts: Record<string, unknown>
  [key: string]: unknown
}

export interface AccountTransport {
  session(): Promise<JmapSession>
  call<T>(methodCalls: JmapMethodCall[]): Promise<T>
  download(blobId: string, range?: { start: number; end?: number }): Promise<Uint8Array>
}

export interface LocalVaultSession {
  kind: 'local-vault'
  accountId: string
  identityId: string
  jmap: AccountTransport
}

export interface RemoteJmapSession {
  kind: 'remote-jmap'
  accountId: string
  jmap: AccountTransport
}

export type AccountSession = LocalVaultSession | RemoteJmapSession
