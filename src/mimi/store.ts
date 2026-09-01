/**
 * SQLite state for a single MIMI hub deployment.  Unlike the transitional
 * identity-blind MLS DS, this store deliberately persists the participant
 * list and MLS credentials required by a specification-conformant hub.
 */
import { Database } from 'bun:sqlite'
import { equalBytes } from '../protocol/canonical.ts'
import { createFrankingKeyMaterial, type FrankingKeyMaterial } from './franking.ts'
import { decodeMimiConsentEntryWire, encodeMimiConsentEntryWire } from './federation.ts'
import { decodeFrankWire, encodeFrankWire } from './wire.ts'
import {
  decodeRoomStateWire,
  encodeRoomStateWire,
} from './wire.ts'
import type {
  KeyPackagePublishRequest,
  MimiConsentEntry,
  MimiCredential,
  MimiDeliveryEntry,
  MimiDeliveryKind,
  MimiEpoch,
  MimiRoomId,
  MimiUserUri,
  MlsRequiredCapabilities,
  PublishedKeyPackage,
  RoomState,
  UpdateRoomRequest,
  Frank,
} from './protocol-types.ts'

const MAX_ROOMS = 10_000
const MAX_PARTICIPANTS = 512
const MAX_CREDENTIALS = 2_048
const MAX_KEY_PACKAGES_PER_CLIENT = 32
const MAX_DELIVERIES_PER_ROOM = 256
const MAX_DELIVERIES_PER_PULL = 32
const MAX_PROVIDER_FANOUT_DEDUPES = 4_096

export class MimiStoreCapacityError extends Error {}
export class MimiStoreStateError extends Error {}

export type MimiUpdateStoreResult =
  | { ok: true; state: RoomState; entries: MimiDeliveryEntry[] }
  | { ok: false; reason: 'wrongEpoch' | 'notAllowed' | 'invalidProposal' | 'roomExists'; currentEpoch?: MimiEpoch; message: string }

interface RoomRow { room_id: string; state_json: string; next_seq: number }
interface DeliveryRow { seq: number; kind: MimiDeliveryKind; payload: Uint8Array; epoch: string; accepted_at: string; frank_json: string | null }
interface KeyPackageRow {
  reference: Uint8Array
  user_uri: string
  client_uri: string
  key_package: Uint8Array
  capabilities_json: string | null
  published_at: string
  expires_at: string | null
  source_provider: string | null
}
interface FrankingKeyRow { hub_key: Uint8Array; signing_private_key: Uint8Array; signing_public_key: Uint8Array }
interface ConsentRow { entry_json: string; source_provider: string; updated_at: string }

/** Hub-owned room state, ordered local deliveries, and KeyPackage directory. */
export class SqliteMimiStore {
  private readonly watchers = new Map<MimiRoomId, Set<(entries: MimiDeliveryEntry[]) => void>>()

  constructor(private readonly database: Database) { installSchema(database) }

  static open(path: string): SqliteMimiStore {
    if (!path) throw new TypeError('SQLite MIMI database path is required')
    return new SqliteMimiStore(new Database(path))
  }

  close(): void { this.database.close() }

  room(roomId: MimiRoomId): RoomState | undefined {
    const row = this.roomRow(roomId)
    return row === undefined ? undefined : decodeRoomStateWire(row.state_json)
  }

  /** Number of live SSE listeners; exposed only for stream lifecycle tests. */
  subscriberCount(roomId: MimiRoomId): number { return this.watchers.get(roomId)?.size ?? 0 }

  subscribe(roomId: MimiRoomId, listener: (entries: MimiDeliveryEntry[]) => void): () => void {
    let listeners = this.watchers.get(roomId)
    if (!listeners) { listeners = new Set(); this.watchers.set(roomId, listeners) }
    listeners.add(listener)
    return () => {
      listeners!.delete(listener)
      if (listeners!.size === 0) this.watchers.delete(roomId)
    }
  }

  canReceive(roomId: MimiRoomId, user: MimiUserUri): boolean {
    return this.room(roomId)?.participantList.participants.some(participant => participant.user === user) ?? false
  }

  /** Returns a bounded post-cursor batch only to a current participant. */
  deliveriesSince(roomId: MimiRoomId, user: MimiUserUri, afterSeq: number, limit = MAX_DELIVERIES_PER_PULL): MimiDeliveryEntry[] | undefined {
    if (!this.canReceive(roomId, user)) return undefined
    return this.database.query<DeliveryRow, [string, number, number]>(
      'SELECT seq, kind, payload, epoch, accepted_at, frank_json FROM mimi_deliveries WHERE room_id = ? AND seq > ? ORDER BY seq LIMIT ?',
    ).all(roomId, afterSeq, limit).map(deliveryFromRow)
  }

  /**
   * Applies the hub-visible half of an accepted update.  MLS message parsing
   * remains client/MLS-engine work; this method serializes the one accepted
   * commit per epoch and stores the associated participant state atomically.
   */
  submitUpdate(request: UpdateRoomRequest): MimiUpdateStoreResult {
    return this.database.transaction((): MimiUpdateStoreResult => {
      const existing = this.roomRow(request.roomId)
      if (!existing) return this.createFromInitialUpdate(request)
      if (request.initialState !== undefined) return { ok: false, reason: 'roomExists', message: 'room already exists' }

      const state = decodeRoomStateWire(existing.state_json)
      if (!isParticipant(state, credentialUser(request.sender))) return { ok: false, reason: 'notAllowed', message: 'sender is not an active participant' }
      if (request.epoch !== state.epoch) return { ok: false, reason: 'wrongEpoch', currentEpoch: state.epoch, message: 'MLS epoch does not match hub state' }

      const next = applyStateUpdate(state, request)
      try { validateRoomState(next) } catch (error) {
        return { ok: false, reason: 'invalidProposal', message: error instanceof Error ? error.message : 'invalid room state update' }
      }

      const entries = this.appendBundle(request.roomId, existing.next_seq, request, state.epoch)
      if (request.bundle.kind === 'commit') next.epoch = nextEpoch(state.epoch)
      next.updatedAt = request.submittedAt
      this.saveRoom(next, existing.next_seq + entries.length)
      this.notify(request.roomId, entries)
      return { ok: true, state: next, entries }
    })()
  }

  /** Publishes locally-held spare KeyPackages.  Publication is a provider-internal operation in the MIMI draft. */
  publishKeyPackages(request: KeyPackagePublishRequest): number {
    if (request.packages.length === 0) throw new MimiStoreStateError('at least one KeyPackage is required')
    return this.database.transaction(() => {
      let published = 0
      for (const item of request.packages) {
        validatePackageForCredential(item, request.credential)
        const count = this.database.query<{ count: number }, [string]>(
          'SELECT COUNT(*) AS count FROM mimi_key_packages WHERE client_uri = ?',
        ).get(item.client)?.count ?? 0
        if (count >= MAX_KEY_PACKAGES_PER_CLIENT) throw new MimiStoreCapacityError(`KeyPackage capacity reached for ${item.client}`)
        try {
          this.database.query(
            'INSERT INTO mimi_key_packages (reference, user_uri, client_uri, key_package, capabilities_json, published_at, expires_at, source_provider) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          ).run(item.reference, item.user, item.client, item.keyPackage, item.capabilities === undefined ? null : JSON.stringify(item.capabilities), item.publishedAt, item.expiresAt ?? null, item.sourceProvider ?? null)
          published += 1
        } catch (error) {
          if (String(error).includes('UNIQUE')) throw new MimiStoreStateError('KeyPackage reference is already published')
          throw error
        }
      }
      return published
    })()
  }

  /**
   * Atomically reserves one compatible, non-expired KeyPackage per client for
   * a target user.  A returned package is deleted before this method returns,
   * satisfying the draft's single-use requirement.
   */
  takeKeyPackages(targetUser: MimiUserUri, required: MlsRequiredCapabilities, now = new Date()): PublishedKeyPackage[] {
    return this.database.transaction(() => {
      const rows = this.database.query<KeyPackageRow, [string]>(
        'SELECT reference, user_uri, client_uri, key_package, capabilities_json, published_at, expires_at, source_provider FROM mimi_key_packages WHERE user_uri = ? ORDER BY published_at, rowid',
      ).all(targetUser)
      const selected = new Map<string, { row: KeyPackageRow; capabilities?: MlsRequiredCapabilities }>()
      for (const row of rows) {
        if (selected.has(row.client_uri) || isExpired(row.expires_at, now)) continue
        const capabilities = row.capabilities_json === null ? undefined : parseCapabilities(row.capabilities_json)
        if (isCompatible(capabilities, required)) selected.set(row.client_uri, { row, capabilities })
      }
      const packages: PublishedKeyPackage[] = []
      for (const { row, capabilities } of selected.values()) {
        this.database.query('DELETE FROM mimi_key_packages WHERE reference = ?').run(row.reference)
        packages.push({
          reference: new Uint8Array(row.reference), user: row.user_uri, client: row.client_uri, keyPackage: new Uint8Array(row.key_package), capabilities,
          publishedAt: row.published_at, expiresAt: row.expires_at ?? undefined, sourceProvider: row.source_provider ?? undefined,
        })
      }
      return packages
    })()
  }

  keyPackageCount(user: MimiUserUri): number {
    return this.database.query<{ count: number }, [string]>('SELECT COUNT(*) AS count FROM mimi_key_packages WHERE user_uri = ?').get(user)?.count ?? 0
  }

  /** Durable provider-to-provider consent state keyed by draft §5.7 ConsentScope. */
  recordConsent(entry: MimiConsentEntry, sourceProvider: string, receivedAt: string): void {
    const roomScope = entry.roomId ?? ''
    if (entry.consentOperation === 'cancel') {
      this.database.query('DELETE FROM mimi_consents WHERE requester_uri = ? AND target_uri = ? AND room_id = ?').run(entry.requesterUri, entry.targetUri, roomScope)
      return
    }
    this.database.query(
      'INSERT INTO mimi_consents (requester_uri, target_uri, room_id, entry_json, source_provider, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(requester_uri, target_uri, room_id) DO UPDATE SET entry_json = excluded.entry_json, source_provider = excluded.source_provider, updated_at = excluded.updated_at',
    ).run(entry.requesterUri, entry.targetUri, roomScope, encodeMimiConsentEntryWire(entry), sourceProvider, receivedAt)
  }

  consent(requesterUri: MimiUserUri, targetUri: MimiUserUri, roomId?: MimiRoomId): { entry: MimiConsentEntry; sourceProvider: string; updatedAt: string } | undefined {
    const row = this.database.query<ConsentRow, [string, string, string]>('SELECT entry_json, source_provider, updated_at FROM mimi_consents WHERE requester_uri = ? AND target_uri = ? AND room_id = ?').get(requesterUri, targetUri, roomId ?? '')
    return row == null ? undefined : { entry: decodeMimiConsentEntryWire(row.entry_json), sourceProvider: row.source_provider, updatedAt: row.updated_at }
  }

  /** Accepts a follower-facing hub batch exactly once, then wakes local SSE clients. */
  acceptProviderFanout(roomId: MimiRoomId, sourceProvider: string, bodyHash: string, entries: MimiDeliveryEntry[]): 'accepted' | 'duplicate' | 'noSuchRoom' {
    return this.database.transaction(() => {
      const room = this.roomRow(roomId)
      if (!room) return 'noSuchRoom' as const
      try {
        this.database.query('INSERT INTO mimi_provider_fanout_dedupes (source_provider, body_hash, received_at) VALUES (?, ?, ?)').run(sourceProvider, bodyHash, new Date().toISOString())
      } catch (error) {
        if (String(error).includes('UNIQUE')) return 'duplicate' as const
        throw error
      }
      const state = decodeRoomStateWire(room.state_json)
      const accepted = entries.map((entry, index) => ({ ...entry, seq: room.next_seq + index, payload: new Uint8Array(entry.payload), frank: entry.frank }))
      for (const entry of accepted) this.database.query('INSERT INTO mimi_deliveries (room_id, seq, kind, payload, epoch, accepted_at, frank_json) VALUES (?, ?, ?, ?, ?, ?, ?)').run(roomId, entry.seq, entry.kind, entry.payload, entry.epoch, entry.acceptedAt, entry.frank === undefined ? null : encodeFrankWire(entry.frank))
      this.saveRoom({ ...state, updatedAt: accepted.at(-1)?.acceptedAt ?? state.updatedAt }, room.next_seq + accepted.length)
      this.database.query('DELETE FROM mimi_provider_fanout_dedupes WHERE rowid NOT IN (SELECT rowid FROM mimi_provider_fanout_dedupes ORDER BY received_at DESC, rowid DESC LIMIT ?)').run(MAX_PROVIDER_FANOUT_DEDUPES)
      this.notify(roomId, accepted)
      return 'accepted' as const
    })()
  }

  submitMessage(roomId: MimiRoomId, sender: MimiUserUri, epoch: MimiEpoch, payload: Uint8Array, frank: Frank, acceptedAt: string): { ok: true; entry: MimiDeliveryEntry } | { ok: false; currentEpoch?: MimiEpoch } {
    return this.database.transaction((): { ok: true; entry: MimiDeliveryEntry } | { ok: false; currentEpoch?: MimiEpoch } => {
      const row = this.roomRow(roomId)
      if (!row) return { ok: false }
      const state = decodeRoomStateWire(row.state_json)
      if (!isParticipant(state, sender) || state.epoch !== epoch) return { ok: false, currentEpoch: state.epoch }
      const entry: MimiDeliveryEntry = { seq: row.next_seq, kind: 'application', payload: new Uint8Array(payload), epoch, acceptedAt, frank }
      this.database.query('INSERT INTO mimi_deliveries (room_id, seq, kind, payload, epoch, accepted_at, frank_json) VALUES (?, ?, ?, ?, ?, ?, ?)').run(roomId, entry.seq, entry.kind, entry.payload, entry.epoch, entry.acceptedAt, encodeFrankWire(frank))
      this.saveRoom({ ...state, updatedAt: acceptedAt }, row.next_seq + 1)
      this.notify(roomId, [entry])
      return { ok: true, entry }
    })()
  }

  /** Per-room secrets for hub franking; never appear in RoomState or wire JSON. */
  frankingKeys(roomId: MimiRoomId): FrankingKeyMaterial | undefined {
    if (!this.roomRow(roomId)) return undefined
    const found = this.database.query<FrankingKeyRow, [string]>('SELECT hub_key, signing_private_key, signing_public_key FROM mimi_franking_keys WHERE room_id = ?').get(roomId)
    if (found) return copyFrankingKeys(found)
    const created = createFrankingKeyMaterial()
    this.database.query('INSERT INTO mimi_franking_keys (room_id, hub_key, signing_private_key, signing_public_key) VALUES (?, ?, ?, ?)').run(roomId, created.hubKey, created.signingPrivateKey, created.signingPublicKey)
    return created
  }

  private createFromInitialUpdate(request: UpdateRoomRequest): MimiUpdateStoreResult {
    if (!request.initialState) return { ok: false, reason: 'notAllowed', message: 'room does not exist' }
    if (request.epoch !== '0') return { ok: false, reason: 'wrongEpoch', currentEpoch: '0', message: 'initial room epoch must be 0' }
    if (this.roomCount() >= MAX_ROOMS) throw new MimiStoreCapacityError('MIMI room capacity reached')
    const state: RoomState = {
      roomId: request.roomId, protocol: request.protocol, epoch: '0', basePolicy: request.initialState.basePolicy,
      participantList: request.initialState.participantList, memberCredentials: request.initialState.memberCredentials, metadata: request.initialState.metadata,
      groupInfo: request.bundle.groupInfo, ratchetTree: request.bundle.ratchetTree, createdAt: request.submittedAt, updatedAt: request.submittedAt,
    }
    try { validateRoomState(state) } catch (error) {
      return { ok: false, reason: 'invalidProposal', message: error instanceof Error ? error.message : 'invalid initial room state' }
    }
    if (!isParticipant(state, credentialUser(request.sender)) || !containsCredential(state.memberCredentials, request.sender)) {
      return { ok: false, reason: 'notAllowed', message: 'creator must be an initial participant' }
    }
    const entries = this.appendBundle(request.roomId, 1, request, state.epoch)
    state.epoch = request.bundle.kind === 'commit' ? nextEpoch(state.epoch) : state.epoch
    this.saveRoom(state, 1 + entries.length)
    this.frankingKeys(request.roomId)
    this.notify(request.roomId, entries)
    return { ok: true, state, entries }
  }

  private appendBundle(roomId: MimiRoomId, firstSeq: number, request: UpdateRoomRequest, epoch: MimiEpoch): MimiDeliveryEntry[] {
    const entries: MimiDeliveryEntry[] = []
    const append = (kind: MimiDeliveryKind, payload: Uint8Array) => {
      const entry: MimiDeliveryEntry = { seq: firstSeq + entries.length, kind, payload: new Uint8Array(payload), epoch, acceptedAt: request.submittedAt }
      this.database.query('INSERT INTO mimi_deliveries (room_id, seq, kind, payload, epoch, accepted_at, frank_json) VALUES (?, ?, ?, ?, ?, ?, NULL)').run(roomId, entry.seq, entry.kind, entry.payload, entry.epoch, entry.acceptedAt)
      entries.push(entry)
    }
    if (request.bundle.kind === 'commit') {
      if (request.bundle.welcome) append('welcome', request.bundle.welcome)
      append('commit', request.bundle.proposalOrCommit)
    } else {
      append('proposal', request.bundle.proposalOrCommit)
      for (const proposal of request.bundle.moreProposals ?? []) append('proposal', proposal)
    }
    this.database.query(
      'DELETE FROM mimi_deliveries WHERE room_id = ? AND seq NOT IN (SELECT seq FROM mimi_deliveries WHERE room_id = ? ORDER BY seq DESC LIMIT ?)',
    ).run(roomId, roomId, MAX_DELIVERIES_PER_ROOM)
    return entries
  }

  private roomRow(roomId: MimiRoomId): RoomRow | undefined {
    return this.database.query<RoomRow, [string]>('SELECT room_id, state_json, next_seq FROM mimi_rooms WHERE room_id = ?').get(roomId) ?? undefined
  }

  private roomCount(): number { return this.database.query<{ count: number }, []>('SELECT COUNT(*) AS count FROM mimi_rooms').get()?.count ?? 0 }

  private saveRoom(state: RoomState, nextSeq: number): void {
    this.database.query(
      'INSERT INTO mimi_rooms (room_id, state_json, next_seq) VALUES (?, ?, ?) ON CONFLICT(room_id) DO UPDATE SET state_json = excluded.state_json, next_seq = excluded.next_seq',
    ).run(state.roomId, encodeRoomStateWire(state), nextSeq)
  }

  private notify(roomId: MimiRoomId, entries: MimiDeliveryEntry[]): void {
    for (const listener of this.watchers.get(roomId) ?? []) listener(entries)
  }
}

function applyStateUpdate(state: RoomState, request: UpdateRoomRequest): RoomState {
  const update = request.stateUpdate
  return {
    ...state,
    basePolicy: update?.basePolicy ?? state.basePolicy,
    participantList: update?.participantList ?? state.participantList,
    memberCredentials: update?.memberCredentials ?? state.memberCredentials,
    metadata: update?.metadata ?? state.metadata,
    groupInfo: request.bundle.groupInfo ?? state.groupInfo,
    ratchetTree: request.bundle.ratchetTree ?? state.ratchetTree,
  }
}

function validateRoomState(state: RoomState): void {
  if (!state.roomId || state.metadata.roomUri !== state.roomId) throw new MimiStoreStateError('room metadata URI must equal room ID')
  if (state.participantList.participants.length === 0) throw new MimiStoreStateError('room must have at least one participant')
  if (state.participantList.participants.length > MAX_PARTICIPANTS) throw new MimiStoreCapacityError('participant capacity reached')
  if (state.memberCredentials.length > MAX_CREDENTIALS) throw new MimiStoreCapacityError('credential capacity reached')
  const users = new Set<string>()
  for (const participant of state.participantList.participants) {
    if (!participant.user || !Number.isSafeInteger(participant.roleIndex) || participant.roleIndex < 0 || users.has(participant.user)) throw new MimiStoreStateError('participant list has an invalid or duplicate user')
    users.add(participant.user)
  }
  const clients = new Set<string>()
  for (const credential of state.memberCredentials) {
    const user = credential.kind === 'visible' ? credential.user : credential.userPseudonym
    const client = credential.kind === 'visible' ? credential.client : credential.clientPseudonym
    if (!users.has(user) || clients.has(client)) throw new MimiStoreStateError('credential does not correspond to exactly one participant')
    clients.add(client)
  }
}

function containsCredential(credentials: MimiCredential[], required: MimiCredential): boolean {
  return credentials.some(candidate => {
    if (candidate.kind !== required.kind) return false
    if (candidate.kind === 'visible' && required.kind === 'visible') return candidate.client === required.client && equalBytes(candidate.signaturePublicKey, required.signaturePublicKey)
    if (candidate.kind === 'pseudonymous' && required.kind === 'pseudonymous') return candidate.clientPseudonym === required.clientPseudonym && equalBytes(candidate.signaturePublicKey, required.signaturePublicKey)
    return false
  })
}

function credentialUser(credential: MimiCredential): MimiUserUri {
  return credential.kind === 'visible' ? credential.user : credential.userPseudonym
}

function isParticipant(state: RoomState, user: MimiUserUri): boolean { return state.participantList.participants.some(participant => participant.user === user) }

function nextEpoch(epoch: MimiEpoch): MimiEpoch {
  const next = BigInt(epoch) + 1n
  if (next > 18_446_744_073_709_551_615n) throw new MimiStoreStateError('MLS epoch overflow')
  return next.toString()
}

function deliveryFromRow(row: DeliveryRow): MimiDeliveryEntry {
  return { seq: row.seq, kind: row.kind, payload: new Uint8Array(row.payload), epoch: row.epoch, acceptedAt: row.accepted_at, frank: row.frank_json === null ? undefined : decodeFrankWire(row.frank_json) }
}

function validatePackageForCredential(item: PublishedKeyPackage, credential: MimiCredential): void {
  const user = credential.kind === 'visible' ? credential.user : credential.userPseudonym
  const client = credential.kind === 'visible' ? credential.client : credential.clientPseudonym
  if (item.user !== user || item.client !== client) throw new MimiStoreStateError('KeyPackage identity does not match publishing credential')
}

function parseCapabilities(value: string): MlsRequiredCapabilities {
  try {
    const parsed: unknown = JSON.parse(value)
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error()
    return parsed as MlsRequiredCapabilities
  } catch { throw new MimiStoreStateError('stored KeyPackage capabilities are invalid') }
}

function isCompatible(candidate: MlsRequiredCapabilities | undefined, required: MlsRequiredCapabilities): boolean {
  return containsAll(candidate?.credentialTypes, required.credentialTypes) && containsAll(candidate?.proposalTypes, required.proposalTypes) && containsAll(candidate?.extensions, required.extensions)
}

function containsAll(have: number[] | undefined, required: number[] | undefined): boolean {
  if (!required || required.length === 0) return true
  return have !== undefined && required.every(value => have.includes(value))
}

function isExpired(value: string | null, now: Date): boolean { return value !== null && Date.parse(value) <= now.valueOf() }

function installSchema(database: Database): void {
  database.run(`
    CREATE TABLE IF NOT EXISTS mimi_rooms (
      room_id TEXT PRIMARY KEY NOT NULL,
      state_json TEXT NOT NULL,
      next_seq INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mimi_deliveries (
      room_id TEXT NOT NULL,
      seq INTEGER NOT NULL,
      kind TEXT NOT NULL,
      payload BLOB NOT NULL,
      epoch TEXT NOT NULL,
      accepted_at TEXT NOT NULL,
      frank_json TEXT,
      PRIMARY KEY (room_id, seq)
    );
    CREATE INDEX IF NOT EXISTS mimi_deliveries_room_seq ON mimi_deliveries (room_id, seq);
    CREATE TABLE IF NOT EXISTS mimi_key_packages (
      reference BLOB PRIMARY KEY NOT NULL,
      user_uri TEXT NOT NULL,
      client_uri TEXT NOT NULL,
      key_package BLOB NOT NULL,
      capabilities_json TEXT,
      published_at TEXT NOT NULL,
      expires_at TEXT,
      source_provider TEXT
    );
    CREATE INDEX IF NOT EXISTS mimi_key_packages_user ON mimi_key_packages (user_uri, client_uri, published_at);
    CREATE TABLE IF NOT EXISTS mimi_franking_keys (
      room_id TEXT PRIMARY KEY NOT NULL,
      hub_key BLOB NOT NULL,
      signing_private_key BLOB NOT NULL,
      signing_public_key BLOB NOT NULL,
      FOREIGN KEY(room_id) REFERENCES mimi_rooms(room_id)
    );
    CREATE TABLE IF NOT EXISTS mimi_consents (
      requester_uri TEXT NOT NULL,
      target_uri TEXT NOT NULL,
      room_id TEXT NOT NULL,
      entry_json TEXT NOT NULL,
      source_provider TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (requester_uri, target_uri, room_id)
    );
    CREATE TABLE IF NOT EXISTS mimi_provider_fanout_dedupes (
      source_provider TEXT NOT NULL,
      body_hash TEXT NOT NULL,
      received_at TEXT NOT NULL,
      PRIMARY KEY (source_provider, body_hash)
    );
  `)
  const columns = database.query<{ name: string }, []>('PRAGMA table_info(mimi_deliveries)').all()
  if (!columns.some(column => column.name === 'frank_json')) database.run('ALTER TABLE mimi_deliveries ADD COLUMN frank_json TEXT')
}

function copyFrankingKeys(row: FrankingKeyRow): FrankingKeyMaterial {
  return { hubKey: new Uint8Array(row.hub_key), signingPrivateKey: new Uint8Array(row.signing_private_key), signingPublicKey: new Uint8Array(row.signing_public_key) }
}
