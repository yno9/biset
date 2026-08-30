import { Database } from 'bun:sqlite'
import { p256 } from '@noble/curves/nist.js'
import type { AnchorAuthorizationCodeStore, AuthorizationCodeRecord, RefreshTokenRecord } from './oidc.ts'
import type {
  AnchorLoginCredentialRecord,
  AnchorOid4vpCompletion,
  AnchorOid4vpEnrollmentChallenge,
  AnchorOid4vpSession,
  AnchorOid4vpStore,
  AnchorOid4vpTransaction,
} from './oid4vp.ts'
import { bytesToBase64url } from '../protocol/canonical.ts'

interface CodeRow {
  code_hash: string
  client_id: string
  redirect_uri: string
  root_subject: string
  generation: string
  sector_identifier: string
  audience: string
  scopes_json: string
  code_challenge: string
  nonce: string
  authenticated_at: number
  expires_at: number
}

export interface AnchorOidcSecrets {
  signingPrivateKey: Uint8Array
  pairwiseSecret: Uint8Array
  credentialSigningPrivateKey: Uint8Array
}

/** Durable, one-use authorization codes and stable OIDC issuer secrets. */
export class SqliteAnchorOidcState implements AnchorAuthorizationCodeStore, AnchorOid4vpStore {
  constructor(private readonly database: Database) {
    database.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS oidc_secrets (name TEXT PRIMARY KEY, value BLOB NOT NULL);
      CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
        code_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        root_subject TEXT NOT NULL,
        sector_identifier TEXT NOT NULL,
        audience TEXT NOT NULL,
        scopes_json TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        nonce TEXT NOT NULL,
        authenticated_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS oidc_authorization_codes_expiry ON oidc_authorization_codes(expires_at);
      CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        root_subject TEXT NOT NULL,
        sector_identifier TEXT NOT NULL,
        audience TEXT NOT NULL,
        scopes_json TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS oidc_refresh_tokens_expiry ON oidc_refresh_tokens(expires_at);
      CREATE TABLE IF NOT EXISTS oid4vp_accounts (
        root_subject TEXT PRIMARY KEY,
        account_ref TEXT NOT NULL UNIQUE
      );
      CREATE TABLE IF NOT EXISTS oid4vp_login_credentials (
        credential_id TEXT PRIMARY KEY,
        credential_hash TEXT NOT NULL UNIQUE,
        account_ref TEXT NOT NULL,
        root_subject TEXT NOT NULL,
        holder_key_id TEXT NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS oid4vp_login_credentials_expiry ON oid4vp_login_credentials(expires_at);
      CREATE TABLE IF NOT EXISTS oid4vp_transactions (
        transaction_id TEXT PRIMARY KEY,
        state TEXT NOT NULL UNIQUE,
        nonce TEXT NOT NULL,
        return_url TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS oid4vp_transactions_expiry ON oid4vp_transactions(expires_at);
      CREATE TABLE IF NOT EXISTS oid4vp_completions (
        response_code_hash TEXT PRIMARY KEY,
        root_subject TEXT NOT NULL,
        authenticated_at INTEGER NOT NULL,
        return_url TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS oid4vp_completions_expiry ON oid4vp_completions(expires_at);
      CREATE TABLE IF NOT EXISTS oid4vp_sessions (
        session_hash TEXT PRIMARY KEY,
        root_subject TEXT NOT NULL,
        authenticated_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS oid4vp_sessions_expiry ON oid4vp_sessions(expires_at);
      CREATE TABLE IF NOT EXISTS oid4vp_enrollment_challenges (
        challenge_hash TEXT PRIMARY KEY,
        did TEXT NOT NULL,
        holder_key_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS oid4vp_enrollment_challenges_expiry ON oid4vp_enrollment_challenges(expires_at);
    `)
    addColumnIfMissing(database, 'oidc_authorization_codes', 'generation', "TEXT NOT NULL DEFAULT ''")
    addColumnIfMissing(database, 'oidc_refresh_tokens', 'generation', "TEXT NOT NULL DEFAULT ''")
    addColumnIfMissing(database, 'oid4vp_login_credentials', 'generation', "TEXT NOT NULL DEFAULT ''")
    addColumnIfMissing(database, 'oid4vp_completions', 'generation', "TEXT NOT NULL DEFAULT ''")
    addColumnIfMissing(database, 'oid4vp_sessions', 'generation', "TEXT NOT NULL DEFAULT ''")
  }

  static open(path: string): SqliteAnchorOidcState {
    if (!path) throw new TypeError('Anchor OIDC database path is required')
    return new SqliteAnchorOidcState(new Database(path))
  }

  close(): void { this.database.close() }

  secrets(): AnchorOidcSecrets {
    return {
      signingPrivateKey: this.secret('es256-signing-private-key', () => p256.keygen().secretKey),
      pairwiseSecret: this.secret('pairwise-subject-secret', () => crypto.getRandomValues(new Uint8Array(32))),
      credentialSigningPrivateKey: this.secret('oid4vp-credential-es256-signing-private-key', () => p256.keygen().secretKey),
    }
  }

  async put(value: AuthorizationCodeRecord): Promise<void> {
    this.database.query(`INSERT INTO oidc_authorization_codes
      (code_hash, client_id, redirect_uri, root_subject, generation, sector_identifier, audience, scopes_json, code_challenge, nonce, authenticated_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(value.codeHash, value.clientId, value.redirectUri, value.rootSubject, value.generation, value.sectorIdentifier, value.audience, JSON.stringify(value.scopes), value.codeChallenge, value.nonce, value.authenticatedAt, value.expiresAt)
  }

  async take(codeHash: string): Promise<AuthorizationCodeRecord | undefined> {
    const take = this.database.transaction(() => {
      const row = this.database.query<CodeRow, [string]>('SELECT * FROM oidc_authorization_codes WHERE code_hash = ?').get(codeHash)
      this.database.query('DELETE FROM oidc_authorization_codes WHERE code_hash = ?').run(codeHash)
      return row
    })
    const row = take()
    if (!row) return undefined
    let scopes: unknown
    try { scopes = JSON.parse(row.scopes_json) } catch { throw new Error('stored OIDC authorization code scopes are corrupt') }
    if (!Array.isArray(scopes) || !scopes.every(scope => typeof scope === 'string')) throw new Error('stored OIDC authorization code scopes are corrupt')
    return {
      codeHash: row.code_hash, clientId: row.client_id, redirectUri: row.redirect_uri,
      rootSubject: row.root_subject, generation: row.generation, sectorIdentifier: row.sector_identifier,
      audience: row.audience, scopes, codeChallenge: row.code_challenge, nonce: row.nonce,
      authenticatedAt: row.authenticated_at, expiresAt: row.expires_at,
    }
  }

  async putRefresh(value: RefreshTokenRecord): Promise<void> {
    this.database.query('INSERT INTO oidc_refresh_tokens (token_hash, client_id, root_subject, generation, sector_identifier, audience, scopes_json, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(value.tokenHash, value.clientId, value.rootSubject, value.generation, value.sectorIdentifier, value.audience, JSON.stringify(value.scopes), value.expiresAt)
  }

  async takeRefresh(tokenHash: string): Promise<RefreshTokenRecord | undefined> {
    const row = this.database.transaction(() => {
      const value = this.database.query<{ token_hash: string; client_id: string; root_subject: string; generation: string; sector_identifier: string; audience: string; scopes_json: string; expires_at: number }, [string]>('SELECT * FROM oidc_refresh_tokens WHERE token_hash=?').get(tokenHash)
      this.database.query('DELETE FROM oidc_refresh_tokens WHERE token_hash=?').run(tokenHash)
      return value
    })()
    if (!row) return undefined
    const scopes = JSON.parse(row.scopes_json) as unknown
    if (!Array.isArray(scopes) || !scopes.every(value => typeof value === 'string')) throw new Error('stored OIDC refresh token scopes are corrupt')
    return { tokenHash: row.token_hash, clientId: row.client_id, rootSubject: row.root_subject, generation: row.generation, sectorIdentifier: row.sector_identifier, audience: row.audience, scopes, expiresAt: row.expires_at }
  }

  expire(now = new Date()): number {
    const expiry = Math.floor(now.getTime() / 1000)
    return this.database.transaction(() => [
      'oidc_authorization_codes', 'oidc_refresh_tokens', 'oid4vp_transactions', 'oid4vp_completions', 'oid4vp_sessions', 'oid4vp_enrollment_challenges',
    ].reduce((total, table) => total + this.database.query(`DELETE FROM ${table} WHERE expires_at <= ?`).run(expiry).changes, 0))()
  }

  async accountRef(rootSubject: string): Promise<string> {
    const get = () => this.database.query<{ account_ref: string }, [string]>('SELECT account_ref FROM oid4vp_accounts WHERE root_subject = ?').get(rootSubject)?.account_ref
    const transaction = this.database.transaction(() => {
      const existing = get()
      if (existing) return existing
      const accountRef = bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)))
      this.database.query('INSERT INTO oid4vp_accounts (root_subject, account_ref) VALUES (?, ?)').run(rootSubject, accountRef)
      return accountRef
    })
    return transaction()
  }

  async putCredential(value: AnchorLoginCredentialRecord): Promise<void> {
    this.database.query(`INSERT INTO oid4vp_login_credentials
      (credential_id, credential_hash, account_ref, root_subject, generation, holder_key_id, issued_at, expires_at, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(value.credentialId, value.credentialHash, value.accountRef, value.rootSubject, value.generation, value.holderKeyId, value.issuedAt, value.expiresAt, value.revokedAt ?? null)
  }

  async credential(credentialId: string): Promise<AnchorLoginCredentialRecord | undefined> {
    const row = this.database.query<CredentialRow, [string]>('SELECT * FROM oid4vp_login_credentials WHERE credential_id = ?').get(credentialId)
    return row ? credentialRow(row) : undefined
  }

  async revokeCredential(credentialId: string, revokedAt: number): Promise<boolean> {
    return this.database.query('UPDATE oid4vp_login_credentials SET revoked_at = COALESCE(revoked_at, ?) WHERE credential_id = ?').run(revokedAt, credentialId).changes === 1
  }

  async putTransaction(value: AnchorOid4vpTransaction): Promise<void> {
    this.database.query('INSERT INTO oid4vp_transactions (transaction_id, state, nonce, return_url, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(value.transactionId, value.state, value.nonce, value.returnUrl, value.expiresAt)
  }

  async transaction(transactionId: string): Promise<AnchorOid4vpTransaction | undefined> {
    const row = this.database.query<TransactionRow, [string]>('SELECT * FROM oid4vp_transactions WHERE transaction_id = ?').get(transactionId)
    return row ? transactionRow(row) : undefined
  }

  async takeTransactionByState(state: string): Promise<AnchorOid4vpTransaction | undefined> {
    return this.database.transaction(() => {
      const row = this.database.query<TransactionRow, [string]>('SELECT * FROM oid4vp_transactions WHERE state = ?').get(state)
      if (row) this.database.query('DELETE FROM oid4vp_transactions WHERE transaction_id = ?').run(row.transaction_id)
      return row ? transactionRow(row) : undefined
    })()
  }

  async putCompletion(value: AnchorOid4vpCompletion): Promise<void> {
    this.database.query('INSERT INTO oid4vp_completions (response_code_hash, root_subject, generation, authenticated_at, return_url, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(value.responseCodeHash, value.rootSubject, value.generation, value.authenticatedAt, value.returnUrl, value.expiresAt)
  }

  async takeCompletion(responseCodeHash: string): Promise<AnchorOid4vpCompletion | undefined> {
    return this.database.transaction(() => {
      const row = this.database.query<CompletionRow, [string]>('SELECT * FROM oid4vp_completions WHERE response_code_hash = ?').get(responseCodeHash)
      this.database.query('DELETE FROM oid4vp_completions WHERE response_code_hash = ?').run(responseCodeHash)
      return row ? completionRow(row) : undefined
    })()
  }

  async putSession(value: AnchorOid4vpSession): Promise<void> {
    this.database.query('INSERT INTO oid4vp_sessions (session_hash, root_subject, generation, authenticated_at, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(value.sessionHash, value.rootSubject, value.generation, value.authenticatedAt, value.expiresAt)
  }

  async session(sessionHash: string): Promise<AnchorOid4vpSession | undefined> {
    const row = this.database.query<SessionRow, [string]>('SELECT * FROM oid4vp_sessions WHERE session_hash = ?').get(sessionHash)
    return row ? sessionRow(row) : undefined
  }

  async putEnrollmentChallenge(value: AnchorOid4vpEnrollmentChallenge): Promise<void> {
    this.database.query('INSERT INTO oid4vp_enrollment_challenges (challenge_hash, did, holder_key_id, expires_at) VALUES (?, ?, ?, ?)')
      .run(value.challengeHash, value.did, value.holderKeyId, value.expiresAt)
  }

  async takeEnrollmentChallenge(challengeHash: string): Promise<AnchorOid4vpEnrollmentChallenge | undefined> {
    return this.database.transaction(() => {
      const row = this.database.query<EnrollmentRow, [string]>('SELECT * FROM oid4vp_enrollment_challenges WHERE challenge_hash = ?').get(challengeHash)
      this.database.query('DELETE FROM oid4vp_enrollment_challenges WHERE challenge_hash = ?').run(challengeHash)
      return row ? { challengeHash: row.challenge_hash, did: row.did, holderKeyId: row.holder_key_id, expiresAt: row.expires_at } : undefined
    })()
  }

  private secret(name: string, generate: () => Uint8Array): Uint8Array {
    const existing = this.database.query<{ value: Uint8Array }, [string]>('SELECT value FROM oidc_secrets WHERE name = ?').get(name)
    if (existing) return new Uint8Array(existing.value)
    const value = generate()
    this.database.query('INSERT INTO oidc_secrets (name, value) VALUES (?, ?)').run(name, value)
    return value.slice()
  }
}

interface CredentialRow { credential_id: string; credential_hash: string; account_ref: string; root_subject: string; generation: string; holder_key_id: string; issued_at: number; expires_at: number; revoked_at: number | null }
interface TransactionRow { transaction_id: string; state: string; nonce: string; return_url: string; expires_at: number }
interface CompletionRow { response_code_hash: string; root_subject: string; generation: string; authenticated_at: number; return_url: string; expires_at: number }
interface SessionRow { session_hash: string; root_subject: string; generation: string; authenticated_at: number; expires_at: number }
interface EnrollmentRow { challenge_hash: string; did: string; holder_key_id: string; expires_at: number }
function credentialRow(row: CredentialRow): AnchorLoginCredentialRecord { return { credentialId: row.credential_id, credentialHash: row.credential_hash, accountRef: row.account_ref, rootSubject: row.root_subject, generation: row.generation, holderKeyId: row.holder_key_id, issuedAt: row.issued_at, expiresAt: row.expires_at, ...(row.revoked_at === null ? {} : { revokedAt: row.revoked_at }) } }
function transactionRow(row: TransactionRow): AnchorOid4vpTransaction { return { transactionId: row.transaction_id, state: row.state, nonce: row.nonce, returnUrl: row.return_url, expiresAt: row.expires_at } }
function completionRow(row: CompletionRow): AnchorOid4vpCompletion { return { responseCodeHash: row.response_code_hash, rootSubject: row.root_subject, generation: row.generation, authenticatedAt: row.authenticated_at, returnUrl: row.return_url, expiresAt: row.expires_at } }
function sessionRow(row: SessionRow): AnchorOid4vpSession { return { sessionHash: row.session_hash, rootSubject: row.root_subject, generation: row.generation, authenticatedAt: row.authenticated_at, expiresAt: row.expires_at } }

function addColumnIfMissing(database: Database, table: string, column: string, definition: string): void {
  const columns = database.query<{ name: string }, []>(`PRAGMA table_info(${table})`).all()
  if (!columns.some(value => value.name === column)) database.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`)
}
