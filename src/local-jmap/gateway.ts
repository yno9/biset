import type { AccountTransport, JmapMethodCall, JmapSession } from './transport.ts'

export const JMAP_CORE_CAPABILITY = 'urn:ietf:params:jmap:core'
export const JMAP_MAIL_CAPABILITY = 'urn:ietf:params:jmap:mail'

export interface LocalJmapMailbox {
  id: string
  name: string
  role?: string
  parentId?: string | null
  totalEmails: number
  unreadEmails: number
}

export interface LocalJmapEmail {
  id: string
  blobId?: string
  threadId: string
  mailboxIds: Record<string, true>
  keywords: Record<string, true>
  receivedAt: string
  sentAt?: string
  from?: Array<{ email?: string; name?: string }>
  to?: Array<{ email?: string; name?: string }>
  subject?: string
  preview?: string
  size?: number
}

export interface LocalJmapSnapshot {
  state: string
  mailboxes: LocalJmapMailbox[]
  emails: LocalJmapEmail[]
}

/** The versioned shape persisted as a local vault's JMAP projection. */
export interface LocalJmapProjectionV1 extends LocalJmapSnapshot {
  version: 1
  identityId: string
}

/** Read-model boundary: IndexedDB vault projection replaces this memory store. */
export interface LocalJmapReadModel {
  snapshot(): Promise<LocalJmapSnapshot>
  download(blobId: string, range?: { start: number; end?: number }): Promise<Uint8Array>
}

export interface LocalJmapGatewayOptions {
  accountId: string
  identityId: string
  readModel: LocalJmapReadModel
  mutationSink?: LocalJmapMutationSink
}

/** Local write implementation; it commits immutable vault records, not rows in this projection. */
export interface LocalJmapMutationSink {
  emailSet(arguments_: Record<string, unknown>, snapshot: LocalJmapSnapshot): Promise<Record<string, unknown>>
}

export class LocalJmapGateway {
  private readonly sessionValue: JmapSession

  constructor(private readonly options: LocalJmapGatewayOptions) {
    if (!options.accountId || !options.identityId) throw new TypeError('local JMAP account and identity are required')
    this.sessionValue = {
      apiUrl: `biset://local/${encodeURIComponent(options.accountId)}/jmap`,
      downloadUrl: `biset://local/${encodeURIComponent(options.accountId)}/download/{blobId}`,
      capabilities: {
        [JMAP_CORE_CAPABILITY]: { maxSizeRequest: 5_000_000, maxCallsInRequest: 16 },
        [JMAP_MAIL_CAPABILITY]: {},
      },
      accounts: {
        [options.accountId]: {
          name: options.identityId,
          isPersonal: true,
          isReadOnly: true,
          accountCapabilities: { [JMAP_MAIL_CAPABILITY]: {} },
        },
      },
      primaryAccounts: { [JMAP_MAIL_CAPABILITY]: options.accountId },
    }
  }

  session(): JmapSession {
    return this.sessionValue
  }

  async call<T>(methodCalls: JmapMethodCall[]): Promise<T> {
    const snapshot = await this.options.readModel.snapshot()
    const methodResponses: unknown[] = []
    for (const call of methodCalls) {
      methodResponses.push(await this.dispatch(call, snapshot))
    }
    return { methodResponses, sessionState: snapshot.state } as T
  }

  download(blobId: string, range?: { start: number; end?: number }): Promise<Uint8Array> {
    return this.options.readModel.download(blobId, range)
  }

  private async dispatch(call: JmapMethodCall, snapshot: LocalJmapSnapshot): Promise<[string, Record<string, unknown>, string]> {
    if (!call.name || !call.callId || call.arguments === null || typeof call.arguments !== 'object' || Array.isArray(call.arguments)) {
      throw new TypeError('invalid local JMAP method call')
    }
    const accountId = call.arguments.accountId
    if (accountId !== undefined && accountId !== this.options.accountId) {
      return ['error', { type: 'accountNotFound', description: 'unknown local account' }, call.callId]
    }
    switch (call.name) {
      case 'Mailbox/get': return ['Mailbox/get', mailboxGet(this.options.accountId, snapshot, call.arguments), call.callId]
      case 'Email/get': return ['Email/get', emailGet(this.options.accountId, snapshot, call.arguments), call.callId]
      case 'Email/query': return ['Email/query', emailQuery(this.options.accountId, snapshot, call.arguments), call.callId]
      case 'Email/set':
        if (!this.options.mutationSink) return ['error', { type: 'forbidden', description: 'local vault writes are not configured' }, call.callId]
        return ['Email/set', await this.options.mutationSink.emailSet(call.arguments, snapshot), call.callId]
      default: return ['error', { type: 'unknownMethod', description: `unsupported local JMAP method: ${call.name}` }, call.callId]
    }
  }
}

/** AccountTransport facade used by existing JMAP-oriented UI code. */
export class LocalJmapTransport implements AccountTransport {
  constructor(private readonly gateway: LocalJmapGateway) {}

  async session(): Promise<JmapSession> { return this.gateway.session() }
  call<T>(methodCalls: JmapMethodCall[]): Promise<T> { return this.gateway.call<T>(methodCalls) }
  download(blobId: string, range?: { start: number; end?: number }): Promise<Uint8Array> { return this.gateway.download(blobId, range) }
}

export class MemoryLocalJmapReadModel implements LocalJmapReadModel {
  constructor(private snapshotValue: LocalJmapSnapshot, private readonly blobs = new Map<string, Uint8Array>()) {}

  async snapshot(): Promise<LocalJmapSnapshot> {
    return {
      state: this.snapshotValue.state,
      mailboxes: this.snapshotValue.mailboxes.map(copyMailbox),
      emails: this.snapshotValue.emails.map(copyEmail),
    }
  }

  async download(blobId: string, range?: { start: number; end?: number }): Promise<Uint8Array> {
    const bytes = this.blobs.get(blobId)
    if (!bytes) throw new Error('local JMAP blob not found')
    const start = range?.start ?? 0
    const end = range?.end === undefined ? bytes.length : range.end + 1
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || end > bytes.length) {
      throw new RangeError('invalid local JMAP blob range')
    }
    return bytes.slice(start, end)
  }
}

export function localJmapSnapshotFromProjection(value: unknown, identityId: string): LocalJmapSnapshot {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('local JMAP projection must be an object')
  const projection = value as Partial<LocalJmapProjectionV1>
  if (projection.version !== 1 || projection.identityId !== identityId || typeof projection.state !== 'string') {
    throw new TypeError('local JMAP projection has an invalid version, identity, or state')
  }
  if (!Array.isArray(projection.mailboxes) || !Array.isArray(projection.emails)) throw new TypeError('local JMAP projection lacks mailbox or email lists')
  for (const mailbox of projection.mailboxes) {
    if (!mailbox || typeof mailbox.id !== 'string' || !mailbox.id || typeof mailbox.name !== 'string') throw new TypeError('local JMAP projection has an invalid mailbox')
  }
  for (const email of projection.emails) {
    if (!email || typeof email.id !== 'string' || !email.id || typeof email.threadId !== 'string' || !email.threadId
      || !email.mailboxIds || typeof email.mailboxIds !== 'object' || Array.isArray(email.mailboxIds)
      || !email.keywords || typeof email.keywords !== 'object' || Array.isArray(email.keywords)
      || typeof email.receivedAt !== 'string' || Number.isNaN(Date.parse(email.receivedAt))) {
      throw new TypeError('local JMAP projection has an invalid email')
    }
  }
  return {
    state: projection.state,
    mailboxes: projection.mailboxes.map(copyMailbox),
    emails: projection.emails.map(copyEmail),
  }
}

function mailboxGet(accountId: string, snapshot: LocalJmapSnapshot, arguments_: Record<string, unknown>): Record<string, unknown> {
  const ids = stringIds(arguments_.ids)
  const byId = new Map(snapshot.mailboxes.map(mailbox => [mailbox.id, mailbox]))
  const list = (ids ?? snapshot.mailboxes.map(mailbox => mailbox.id)).flatMap(id => byId.has(id) ? [copyMailbox(byId.get(id)!)] : [])
  return { accountId, state: snapshot.state, list, notFound: ids?.filter(id => !byId.has(id)) ?? [] }
}

function emailGet(accountId: string, snapshot: LocalJmapSnapshot, arguments_: Record<string, unknown>): Record<string, unknown> {
  const ids = stringIds(arguments_.ids)
  const byId = new Map(snapshot.emails.map(email => [email.id, email]))
  const list = (ids ?? snapshot.emails.map(email => email.id)).flatMap(id => byId.has(id) ? [copyEmail(byId.get(id)!)] : [])
  return { accountId, state: snapshot.state, list, notFound: ids?.filter(id => !byId.has(id)) ?? [] }
}

function emailQuery(accountId: string, snapshot: LocalJmapSnapshot, arguments_: Record<string, unknown>): Record<string, unknown> {
  const filter = arguments_.filter
  const mailboxId = filter !== null && typeof filter === 'object' && !Array.isArray(filter) && typeof (filter as Record<string, unknown>).inMailbox === 'string'
    ? (filter as Record<string, string>).inMailbox
    : undefined
  const position = nonNegativeInt(arguments_.position, 0, 'position')
  const limit = nonNegativeInt(arguments_.limit, 50, 'limit')
  const emails = snapshot.emails
    .filter(email => !mailboxId || email.mailboxIds[mailboxId] === true)
    .sort((left, right) => right.receivedAt.localeCompare(left.receivedAt) || left.id.localeCompare(right.id))
  return {
    accountId,
    queryState: snapshot.state,
    canCalculateChanges: false,
    position,
    ids: emails.slice(position, position + limit).map(email => email.id),
    total: emails.length,
  }
}

function stringIds(value: unknown): string[] | undefined {
  if (value === undefined || value === null) return undefined
  if (!Array.isArray(value) || value.some(id => typeof id !== 'string' || !id)) throw new TypeError('JMAP ids must be an array of non-empty strings')
  return value
}

function nonNegativeInt(value: unknown, defaultValue: number, name: string): number {
  if (value === undefined) return defaultValue
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError(`JMAP ${name} must be a non-negative integer`)
  return value as number
}

function copyMailbox(value: LocalJmapMailbox): LocalJmapMailbox { return { ...value } }
function copyEmail(value: LocalJmapEmail): LocalJmapEmail {
  return {
    ...value,
    mailboxIds: { ...value.mailboxIds },
    keywords: { ...value.keywords },
    from: value.from?.map(value => ({ ...value })),
    to: value.to?.map(value => ({ ...value })),
  }
}
