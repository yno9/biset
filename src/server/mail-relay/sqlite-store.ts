import { Database } from 'bun:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { b64url, b64urlDecodeToBytes, identityFromKeys, type PeerIdentity } from '../../protocol/didcomm/peer.ts'

/** Relay-only state.  It intentionally has no mediator queue or connection
 * tables: a did.md mail relay is independent from whichever mediator a
 * recipient publishes. */
export class SqliteMailRelayStore {
  private constructor(private readonly database: Database) {
    database.run('CREATE TABLE IF NOT EXISTS relay_identity (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), x_priv TEXT NOT NULL, ed_priv TEXT NOT NULL)')
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
}
