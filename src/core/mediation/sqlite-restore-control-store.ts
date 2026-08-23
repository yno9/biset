import { Database } from 'bun:sqlite'
import type { DeviceId, IdentityId } from '../../protocol/ids.ts'
import type { RestoreCancelV1, RestoreControlPullV1, RestoreOfferV1, RestoreRequestV1 } from '../../protocol/vault.ts'
import { assertRestoreCancel, assertRestoreControlPull, assertRestoreOffer, assertRestoreRequest, ProtocolValidationError } from '../../protocol/validate.ts'
import { noopRestorePushNotifier, notifyPendingRestore, type RestoreControlAuthorizer, type RestorePushNotifier, type RestoreControlStore } from './restore-control-store.ts'

export interface RestoreControlStoreLimits {
  maxIdentityRequests: number
  maxOffersPerRequest: number
}

const DEFAULT_LIMITS: RestoreControlStoreLimits = {
  maxIdentityRequests: 32,
  maxOffersPerRequest: 16,
}

interface RequestRow {
  identity_id: string
  request_id: string
  requester_device_id: string
  reason: RestoreRequestV1['reason']
  known_manifest_root: string | null
  requested_at: string
  expires_at: string
  signature: Uint8Array
}

interface OfferRow {
  identity_id: string
  request_id: string
  requester_device_id: string
  responder_device_id: string
  manifest_root: string
  offered_at: string
  expires_at: string
  signature: Uint8Array
}

/**
 * Crash-safe storage for only short restore signalling. It cannot accept a
 * manifest, ciphertext, blob, or chunk; payload transfer stays peer-to-peer.
 */
export class SqliteRestoreControlStore implements RestoreControlStore {
  private readonly limits: RestoreControlStoreLimits

  constructor(
    private readonly database: Database,
    private readonly authorizer: RestoreControlAuthorizer,
    limits: RestoreControlStoreLimits = DEFAULT_LIMITS,
    private readonly notifier: RestorePushNotifier = noopRestorePushNotifier,
  ) {
    if (!Number.isSafeInteger(limits.maxIdentityRequests) || limits.maxIdentityRequests < 1) throw new TypeError('maxIdentityRequests must be a positive safe integer')
    if (!Number.isSafeInteger(limits.maxOffersPerRequest) || limits.maxOffersPerRequest < 1) throw new TypeError('maxOffersPerRequest must be a positive safe integer')
    this.limits = limits
    installSchema(database)
  }

  static open(path: string, authorizer: RestoreControlAuthorizer, limits?: RestoreControlStoreLimits, notifier?: RestorePushNotifier): SqliteRestoreControlStore {
    if (!path) throw new TypeError('SQLite restore control store path is required')
    return new SqliteRestoreControlStore(new Database(path), authorizer, limits, notifier)
  }

  close(): void { this.database.close() }

  async request(input: RestoreRequestV1, now = new Date()): Promise<void> {
    assertRestoreRequest(input)
    await this.expire(now)
    if (Date.parse(input.expiresAt) <= now.getTime()) throw new ProtocolValidationError('restore request is already expired')
    if (!(await this.authorizer.isTrustedDevice(input.identityId, input.requesterDeviceId))) throw new ProtocolValidationError('restore requester is not trusted')
    if (!(await this.authorizer.verifyRequest(input))) throw new ProtocolValidationError('restore request signature is invalid')
    const existing = this.requestRow(input.identityId, input.requestId)
    if (existing) {
      if (!sameRequest(fromRequestRow(existing), input)) throw new ProtocolValidationError('restore request ID conflicts with existing request')
      return
    }
    const count = Number(this.database.query<{ count: number }, [string]>('SELECT count(*) AS count FROM restore_requests WHERE identity_id = ?').get(input.identityId)?.count ?? 0)
    if (count >= this.limits.maxIdentityRequests) throw new ProtocolValidationError('restore request limit reached')
    this.database.query('INSERT INTO restore_requests (identity_id, request_id, requester_device_id, reason, known_manifest_root, requested_at, expires_at, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(input.identityId, input.requestId, input.requesterDeviceId, input.reason, input.knownManifestRoot ?? null, input.requestedAt, input.expiresAt, input.signature)
    await notifyPendingRestore(this.notifier, input)
  }

  async pullRequests(input: RestoreControlPullV1, now = new Date()): Promise<RestoreRequestV1[]> {
    await this.authorizePull(input, 'requests', now)
    const rows = this.database.query<RequestRow, [string, string]>('SELECT * FROM restore_requests WHERE identity_id = ? AND requester_device_id <> ? ORDER BY requested_at, request_id').all(input.identityId, input.deviceId)
    const visible: RestoreRequestV1[] = []
    for (const row of rows) {
      if (await this.authorizer.isTrustedDevice(input.identityId, row.requester_device_id)) visible.push(fromRequestRow(row))
    }
    return visible
  }

  async offer(input: RestoreOfferV1, now = new Date()): Promise<void> {
    assertRestoreOffer(input)
    await this.expire(now)
    if (Date.parse(input.expiresAt) <= now.getTime()) throw new ProtocolValidationError('restore offer is already expired')
    const request = this.requestRow(input.identityId, input.requestId)
    if (!request || request.requester_device_id !== input.requesterDeviceId) throw new ProtocolValidationError('restore request is absent or no longer active')
    if (Date.parse(input.expiresAt) > Date.parse(request.expires_at)) throw new ProtocolValidationError('restore offer cannot outlive its request')
    if (!(await this.authorizer.isTrustedDevice(input.identityId, input.responderDeviceId))) throw new ProtocolValidationError('restore responder is not trusted')
    if (!(await this.authorizer.isTrustedDevice(input.identityId, input.requesterDeviceId))) throw new ProtocolValidationError('restore requester is no longer trusted')
    if (!(await this.authorizer.verifyOffer(input))) throw new ProtocolValidationError('restore offer signature is invalid')
    const existing = this.offerRow(input.identityId, input.requestId, input.responderDeviceId)
    if (existing) {
      if (!sameOffer(fromOfferRow(existing), input)) throw new ProtocolValidationError('restore offer conflicts with existing responder offer')
      return
    }
    const count = Number(this.database.query<{ count: number }, [string, string]>('SELECT count(*) AS count FROM restore_offers WHERE identity_id = ? AND request_id = ?').get(input.identityId, input.requestId)?.count ?? 0)
    if (count >= this.limits.maxOffersPerRequest) throw new ProtocolValidationError('restore offer limit reached')
    this.database.query('INSERT INTO restore_offers (identity_id, request_id, requester_device_id, responder_device_id, manifest_root, offered_at, expires_at, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(input.identityId, input.requestId, input.requesterDeviceId, input.responderDeviceId, input.manifestRoot, input.offeredAt, input.expiresAt, input.signature)
  }

  async pullOffers(input: RestoreControlPullV1, now = new Date()): Promise<RestoreOfferV1[]> {
    await this.authorizePull(input, 'offers', now)
    const rows = this.database.query<OfferRow, [string, string]>('SELECT * FROM restore_offers WHERE identity_id = ? AND requester_device_id = ? ORDER BY offered_at, responder_device_id').all(input.identityId, input.deviceId)
    const visible: RestoreOfferV1[] = []
    for (const row of rows) {
      if (await this.authorizer.isTrustedDevice(input.identityId, row.responder_device_id)) visible.push(fromOfferRow(row))
    }
    return visible
  }

  async cancel(input: RestoreCancelV1, now = new Date()): Promise<void> {
    assertRestoreCancel(input)
    await this.expire(now)
    const request = this.requestRow(input.identityId, input.requestId)
    if (!request) return
    if (request.requester_device_id !== input.requesterDeviceId) throw new ProtocolValidationError('restore cancel requester does not match request')
    if (!(await this.authorizer.verifyCancel(input, fromRequestRow(request)))) throw new ProtocolValidationError('restore cancel signature is invalid')
    this.database.query('DELETE FROM restore_requests WHERE identity_id = ? AND request_id = ?').run(input.identityId, input.requestId)
  }

  async expire(now = new Date()): Promise<void> {
    const at = now.toISOString()
    const transaction = this.database.transaction(() => {
      this.database.query('DELETE FROM restore_offers WHERE expires_at <= ?').run(at)
      this.database.query('DELETE FROM restore_requests WHERE expires_at <= ?').run(at)
    })
    transaction()
  }

  private async authorizePull(input: RestoreControlPullV1, expectedKind: RestoreControlPullV1['kind'], now: Date): Promise<void> {
    assertRestoreControlPull(input)
    if (input.kind !== expectedKind) throw new ProtocolValidationError(`restore control pull kind must be ${expectedKind}`)
    await this.expire(now)
    if (!(await this.authorizer.isTrustedDevice(input.identityId, input.deviceId))) throw new ProtocolValidationError('restore peer is not trusted')
    if (!(await this.authorizer.verifyPull(input))) throw new ProtocolValidationError('restore control pull signature is invalid')
  }

  private requestRow(identityId: IdentityId, requestId: string): RequestRow | undefined {
    return this.database.query<RequestRow, [string, string]>('SELECT * FROM restore_requests WHERE identity_id = ? AND request_id = ?').get(identityId, requestId) ?? undefined
  }

  private offerRow(identityId: IdentityId, requestId: string, responderDeviceId: DeviceId): OfferRow | undefined {
    return this.database.query<OfferRow, [string, string, string]>('SELECT * FROM restore_offers WHERE identity_id = ? AND request_id = ? AND responder_device_id = ?').get(identityId, requestId, responderDeviceId) ?? undefined
  }
}

function installSchema(database: Database): void {
  database.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS restore_requests (
      identity_id TEXT NOT NULL, request_id TEXT NOT NULL, requester_device_id TEXT NOT NULL, reason TEXT NOT NULL,
      known_manifest_root TEXT, requested_at TEXT NOT NULL, expires_at TEXT NOT NULL, signature BLOB NOT NULL,
      PRIMARY KEY (identity_id, request_id)
    );
    CREATE TABLE IF NOT EXISTS restore_offers (
      identity_id TEXT NOT NULL, request_id TEXT NOT NULL, requester_device_id TEXT NOT NULL, responder_device_id TEXT NOT NULL,
      manifest_root TEXT NOT NULL, offered_at TEXT NOT NULL, expires_at TEXT NOT NULL, signature BLOB NOT NULL,
      PRIMARY KEY (identity_id, request_id, responder_device_id),
      FOREIGN KEY (identity_id, request_id) REFERENCES restore_requests(identity_id, request_id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS restore_requests_by_identity ON restore_requests (identity_id, requested_at);
    CREATE INDEX IF NOT EXISTS restore_offers_by_requester ON restore_offers (identity_id, requester_device_id, offered_at);
  `)
}

function fromRequestRow(row: RequestRow): RestoreRequestV1 {
  return { version: 1, requestId: row.request_id, identityId: row.identity_id, requesterDeviceId: row.requester_device_id, reason: row.reason, ...(row.known_manifest_root === null ? {} : { knownManifestRoot: row.known_manifest_root }), requestedAt: row.requested_at, expiresAt: row.expires_at, signature: new Uint8Array(row.signature) }
}

function fromOfferRow(row: OfferRow): RestoreOfferV1 {
  return { version: 1, requestId: row.request_id, identityId: row.identity_id, requesterDeviceId: row.requester_device_id, responderDeviceId: row.responder_device_id, manifestRoot: row.manifest_root, offeredAt: row.offered_at, expiresAt: row.expires_at, signature: new Uint8Array(row.signature) }
}

function sameRequest(left: RestoreRequestV1, right: RestoreRequestV1): boolean {
  return left.requestId === right.requestId && left.identityId === right.identityId && left.requesterDeviceId === right.requesterDeviceId && left.reason === right.reason && left.knownManifestRoot === right.knownManifestRoot && left.requestedAt === right.requestedAt && left.expiresAt === right.expiresAt && equalBytes(left.signature, right.signature)
}

function sameOffer(left: RestoreOfferV1, right: RestoreOfferV1): boolean {
  return left.requestId === right.requestId && left.identityId === right.identityId && left.requesterDeviceId === right.requesterDeviceId && left.responderDeviceId === right.responderDeviceId && left.manifestRoot === right.manifestRoot && left.offeredAt === right.offeredAt && left.expiresAt === right.expiresAt && equalBytes(left.signature, right.signature)
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  let different = 0
  for (let index = 0; index < left.length; index += 1) different |= left[index] ^ right[index]
  return different === 0
}
