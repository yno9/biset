import { Database } from 'bun:sqlite'
import {
  assertAcceptedSelfGroupProjection,
  compareMlsEpoch,
  sameAcceptedSelfGroupProjection,
  type AcceptedSelfGroupProjectionV1,
  type TrustedDeviceRoster,
  type TrustedDeviceV1,
} from './device-roster.ts'
import type { DeliverySeq, DeviceId, IdentityId } from '../../protocol/ids.ts'
import { stableIdKey } from '../../identity/idkey.ts'

/**
 * Crash-safe public identity projection; it never receives MLS private state.
 *
 * Rows are indexed by `identity_key` (`stableIdKey(identityId)`, the SCID),
 * not the raw `identity_id` column -- same reasoning as
 * device-roster.ts's own MemoryTrustedDeviceRoster and mls/self-group.ts's
 * selfGroupIdentityKey: a did:webvh domain move changes the DID string one
 * device at a time, and indexing by the mutable string would silently split
 * one identity's roster into two the moment the first device migrated.
 * `identity_id` itself stays a plain column (not part of the key) so
 * `projection()` can still echo back a real, currently-resolvable DID --
 * whichever one the MOST RECENT installAcceptedProjection call used.
 */
export class SqliteTrustedDeviceRoster implements TrustedDeviceRoster {
  constructor(private readonly database: Database) { installSchema(database) }

  static open(path: string): SqliteTrustedDeviceRoster {
    if (!path) throw new TypeError('SQLite roster path is required')
    return new SqliteTrustedDeviceRoster(new Database(path))
  }

  close(): void { this.database.close() }

  async installAcceptedProjection(projection: AcceptedSelfGroupProjectionV1): Promise<'installed' | 'already-current'> {
    assertAcceptedSelfGroupProjection(projection)
    const key = stableIdKey(projection.identityId)
    const existing = await this.projection(projection.identityId)
    if (existing) {
      if (existing.selfGroupId !== projection.selfGroupId) throw new TypeError('self group ID cannot change for an identity')
      const ordering = compareMlsEpoch(projection.epoch, existing.epoch)
      if (ordering < 0) throw new TypeError('cannot install a stale MLS projection')
      if (ordering === 0) {
        if (!sameAcceptedSelfGroupProjection(existing, projection)) throw new TypeError('same MLS epoch has conflicting device roster')
        return 'already-current'
      }
    }
    const transaction = this.database.transaction(() => {
      this.database.query('INSERT INTO accepted_self_groups (identity_key, identity_id, self_group_id, epoch, accepted_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(identity_key) DO UPDATE SET identity_id = excluded.identity_id, self_group_id = excluded.self_group_id, epoch = excluded.epoch, accepted_at = excluded.accepted_at').run(key, projection.identityId, projection.selfGroupId, projection.epoch, projection.acceptedAt)
      this.database.query('DELETE FROM accepted_self_group_devices WHERE identity_key = ?').run(key)
      projection.devices.forEach((device, position) => this.database.query('INSERT INTO accepted_self_group_devices (identity_key, device_id, delivery_floor, signing_key_id, position) VALUES (?, ?, ?, ?, ?)').run(key, device.deviceId, device.deliveryFloor, device.signingKeyId, position))
    })
    transaction()
    return 'installed'
  }

  async projection(identityId: IdentityId): Promise<AcceptedSelfGroupProjectionV1 | undefined> {
    const key = stableIdKey(identityId)
    const header = this.database.query<{ identity_id: string; self_group_id: string; epoch: string; accepted_at: string }, [string]>('SELECT identity_id, self_group_id, epoch, accepted_at FROM accepted_self_groups WHERE identity_key = ?').get(key)
    if (!header) return undefined
    const devices = this.database.query<{ device_id: string; delivery_floor: string; signing_key_id: string }, [string]>('SELECT device_id, delivery_floor, signing_key_id FROM accepted_self_group_devices WHERE identity_key = ? ORDER BY position').all(key)
    return { version: 1, identityId: header.identity_id, selfGroupId: header.self_group_id, epoch: header.epoch, acceptedAt: header.accepted_at, devices: devices.map(device => ({ deviceId: device.device_id, deliveryFloor: device.delivery_floor, signingKeyId: device.signing_key_id })) }
  }

  async isTrustedDevice(identityId: IdentityId, deviceId: DeviceId): Promise<boolean> {
    return this.database.query<{ present: number }, [string, string]>('SELECT 1 AS present FROM accepted_self_group_devices WHERE identity_key = ? AND device_id = ?').get(stableIdKey(identityId), deviceId)?.present === 1
  }

  async deliveryFloor(identityId: IdentityId, deviceId: DeviceId): Promise<DeliverySeq | undefined> {
    return this.database.query<{ delivery_floor: string }, [string, string]>('SELECT delivery_floor FROM accepted_self_group_devices WHERE identity_key = ? AND device_id = ?').get(stableIdKey(identityId), deviceId)?.delivery_floor
  }

  async trustedDevices(identityId: IdentityId): Promise<TrustedDeviceV1[]> {
    return this.database.query<{ device_id: string; delivery_floor: string; signing_key_id: string }, [string]>('SELECT device_id, delivery_floor, signing_key_id FROM accepted_self_group_devices WHERE identity_key = ? ORDER BY position').all(stableIdKey(identityId)).map(device => ({ deviceId: device.device_id, deliveryFloor: device.delivery_floor, signingKeyId: device.signing_key_id }))
  }
}

function installSchema(database: Database): void {
  database.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS accepted_self_groups (identity_key TEXT PRIMARY KEY, identity_id TEXT NOT NULL, self_group_id TEXT NOT NULL, epoch TEXT NOT NULL, accepted_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS accepted_self_group_devices (identity_key TEXT NOT NULL, device_id TEXT NOT NULL, delivery_floor TEXT NOT NULL, signing_key_id TEXT NOT NULL, position INTEGER NOT NULL, PRIMARY KEY (identity_key, device_id));
  `)
}
