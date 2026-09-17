import { Database } from 'bun:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { b64url, b64urlDecodeToBytes, identityFromKeys, type PeerIdentity } from '../../protocol/didcomm/peer.ts'
import { canonicalHash } from '../../protocol/canonical.ts'

/** Relay-only state.  It intentionally has no mediator queue or connection
 * tables: a did.md mail relay is independent from whichever mediator a
 * recipient publishes. */
export class SqliteMailRelayStore {
  private constructor(private readonly database: Database) {
    database.run('CREATE TABLE IF NOT EXISTS relay_identity (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), x_priv TEXT NOT NULL, ed_priv TEXT NOT NULL)')
    database.run('CREATE TABLE IF NOT EXISTS mail_submission_results (message_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, result TEXT NOT NULL, created_at INTEGER NOT NULL)')
  }

  static open(path: string): SqliteMailRelayStore {
    if (!path) throw new TypeError('mail relay SQLite path is required')
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    return new SqliteMailRelayStore(new Database(path, { create: true }))
  }

  loadIdentity(): PeerIdentity {
    type Row = { x_priv: string; ed_priv: string }
    let row = this.database.query<Row, []>('SELECT x_priv, ed_priv FROM relay_identity WHERE singleton = 1').get()
    if (!row) {
      const xPriv = x25519.utils.randomSecretKey()
      const edPriv = ed25519.utils.randomSecretKey()
      this.database.query('INSERT INTO relay_identity (singleton, x_priv, ed_priv) VALUES (1, ?, ?)').run(b64url(xPriv), b64url(edPriv))
      row = { x_priv: b64url(xPriv), ed_priv: b64url(edPriv) }
    }
    return identityFromKeys(b64urlDecodeToBytes(row.x_priv), b64urlDecodeToBytes(row.ed_priv))
  }

  close(): void { this.database.close() }

  submissionResult(messageId: string, request: { mailFrom: string; rcptTo: string[]; rawRfc5322: Uint8Array }): string | undefined {
    const hash = canonicalHash('biset/mail-relay/submission/v1', { mailFrom: request.mailFrom, rcptTo: request.rcptTo, rawRfc5322: b64url(request.rawRfc5322) })
    const row = this.database.query<{ request_hash: string; result: string }, [string]>('SELECT request_hash, result FROM mail_submission_results WHERE message_id = ?').get(messageId)
    if (!row) return undefined
    if (row.request_hash !== hash) throw new Error('mail submission idempotency key was reused with another message')
    return row.result
  }

  saveSubmissionResult(messageId: string, request: { mailFrom: string; rcptTo: string[]; rawRfc5322: Uint8Array }, result: string): void {
    const hash = canonicalHash('biset/mail-relay/submission/v1', { mailFrom: request.mailFrom, rcptTo: request.rcptTo, rawRfc5322: b64url(request.rawRfc5322) })
    this.database.query('INSERT INTO mail_submission_results (message_id, request_hash, result, created_at) VALUES (?, ?, ?, ?)').run(messageId, hash, result, Date.now())
  }
}
