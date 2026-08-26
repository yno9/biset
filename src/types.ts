// JMAP core types — use directly from jmap-rfc-types, do not redefine here.
// Email, Mailbox, Thread, Identity, EmailSubmission, ID, Session, etc.
export type { Email, Mailbox, Thread, Identity, EmailSubmission, ID, Session } from 'jmap-rfc-types'

// The live session/transport types now live in local-jmap/transport.ts --
// AccountSession there already IS "one identity routes calls locally, a
// conventional account routes them to its remote JMAP service" (that
// module's own header), replacing this file's old AccountSession (a bare
// `jmapClient: JamClient` wrapper, which only ever meant "remote"). Re-exported
// here so ported UI code's `import { AccountSession } from '../types.ts'`
// keeps resolving without a second, incompatible definition existing.
export type { AccountSession, LocalVaultSession, RemoteJmapSession, AccountTransport } from './local-jmap/transport.ts'

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

/**
 * Durable, persisted account config (survives a reload) -- distinct from
 * AccountSession (local-jmap/transport.ts), which is the LIVE session built
 * from one of these. Two kinds, matching AccountSession's own discriminant:
 *
 *   local-vault: this identity's own Vault Core account. No password -- the
 *     identity itself is the credential (identity/record-store.ts's
 *     IdentityRecord holds the actual key material; a StoredAccount here is
 *     just enough to know which local identity this entry names).
 *   remote-jmap: a conventional third-party JMAP server login -- what every
 *     StoredAccount in src.bak meant (that version had no local-vault
 *     concept at all).
 */
export interface StoredAccount {
  kind: 'local-vault' | 'remote-jmap'
  accountId: string
  // remote-jmap only:
  serverUrl?: string
  // The JMAP LOGIN identity — for a SCID-primary account (PLANSCID.md) this
  // is the permanent `<scid>@<domain>` address, never the human-chosen
  // name. Never shown to a human directly; see `displayEmail` for that.
  email?: string
  // What a human sees and what goes in a compose "From" — the relay's own
  // alias for this account (what other people actually use to reach it).
  // Falls back to `email` for an account still on the legacy scheme, where
  // the two ARE the same address.
  displayEmail?: string
  password?: string   // base64(authToken), remote-jmap only
  // The identity this endpoint belongs to (did:webvh:…), either kind: a
  // local-vault entry's did is its own identityId; a remote-jmap entry's is
  // populated once discovered (a claim, a DID-document resolve), same as
  // src.bak's own field. Absent = not yet known; such an entry falls back
  // to grouping by email.
  did?: string
}

export interface Config {
  accounts: StoredAccount[]
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
