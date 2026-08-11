// JMAP core types — use directly from jmap-rfc-types, do not redefine here.
// Email, Mailbox, Thread, Identity, EmailSubmission, ID, Session, etc.
export type { Email, Mailbox, Thread, Identity, EmailSubmission, ID, Session } from 'jmap-rfc-types'

export interface InboxSummary {
  user: string
  mailbox: string
  contact: string
  latest_ts?: number
  latest_body?: string
  latest_subject?: string
  inbox_type?: 'direct' | 'group'
  has_unread?: boolean
  unread_count?: number
  archived?: boolean
  participants?: string[]
  avatar_url?: string
  cc_addrs?: string[]
  group_id?: string
  group_name?: string
  relay?: string   // serverUrl of the relay this conversation arrived on (reply routing + protocol label)
}

export interface StoredAccount {
  serverUrl: string
  email: string
  password: string   // base64(authToken)
  // The identity this endpoint belongs to (did:dht:…). Identity-by-DID: one DID
  // may span several (serverUrl, email) endpoints — including different email
  // addresses after a move. Populated at password login (derived from the seed)
  // and persisted so a silent reboot can group without re-deriving. Absent =
  // not yet known; such an endpoint falls back to grouping by email.
  did?: string
}

export interface Config {
  accounts: StoredAccount[]
}

export interface AccountSession {
  account: StoredAccount
  jmapAccountId: string
  jmapClient: import('jmap-jam').JamClient
  eventSourceUrl: string | null
}

export interface SendReplyOptions {
  subject?: string
  inReplyTo?: string
  cc?: string
  bcc?: string
}

export interface SendNewOptions {
  to: string
  from: string
  cc?: string
  bcc?: string
  subject?: string
  body: string
}

export interface PendingSubmission {
  id: string
  mailboxName: string
  contact: string
  subject?: string
  body: string
  threadId?: string
  inReplyTo?: string
  createdAt: string
  recipients?: string[]
  group_id?: string
  group_name?: string
}
