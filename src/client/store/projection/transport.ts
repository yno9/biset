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
  /** Local-vault sync is pull-based (main.ts's syncMailIngress), never SSE --
   * always undefined. Kept on the type (not omitted) so UI code ported from
   * src.bak's own AccountSession.eventSourceUrl doesn't need a kind-specific
   * branch just to read this field. */
  eventSourceUrl?: null
}

export interface RemoteJmapSession {
  kind: 'remote-jmap'
  accountId: string
  jmap: AccountTransport
  /** A third-party JMAP server's EventSource push URL, when its Session
   * object advertises one. Not implemented yet (no remote-jmap transport
   * exists to populate it) -- present on the type so ported UI code
   * type-checks against the eventual real thing, not a stub. */
  eventSourceUrl?: string | null
}

export type AccountSession = LocalVaultSession | RemoteJmapSession
