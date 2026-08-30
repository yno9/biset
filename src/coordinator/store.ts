import { Database } from 'bun:sqlite'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64url, equalBytes, sha256Bytes } from '../protocol/canonical.ts'
import { deliverySeq, type DeliverySeq, type VaultId } from '../protocol/ids.ts'
import { vaultGroupViewHash, vaultGroupViewSigningBytes, type VaultGroupViewV1 } from '../protocol/vault-group-view.ts'
import { decodeVaultGroupView, encodeVaultGroupView } from '../protocol/vault-group-view.ts'
import {
  decodeVaultMlsKeyPackage,
  encodeVaultMlsKeyPackage,
  vaultMlsKeyPackageSigningBytes,
  vaultMlsMemberRequestSigningBytes,
  vaultMlsTransitionSigningBytes,
  type VaultMlsKeyPackagePublishV1,
  type VaultMlsMemberRequestV1,
  type VaultMlsTransitionItemV1,
  type VaultMlsTransitionV1,
  type VaultMlsWelcomeDeliveryV1,
  type VaultMlsInvitationRedeemV1,
  type VaultMlsInvitationV1,
} from '../protocol/vault-mls-ds.ts'
import type {
  VaultCoordinatorAckV1,
  VaultCoordinatorAppendV1,
  VaultCoordinatorItemV1,
  VaultCoordinatorPullResult,
  VaultCoordinatorPullV1,
  VaultCoordinatorRestoreReason,
} from '../protocol/coordinator.ts'
import { vaultCoordinatorAckSigningBytes, vaultCoordinatorAppendSigningBytes, vaultCoordinatorCheckpointSigningBytes, vaultCoordinatorPullSigningBytes } from '../protocol/coordinator.ts'
import type { VaultCoordinatorCheckpointPutV1, VaultCoordinatorCheckpointV1, VaultCoordinatorOwnedVaultV1 } from '../protocol/coordinator.ts'
import type { VaultStreamAppendV2, VaultStreamCheckpointPutV2, VaultStreamCheckpointV2, VaultStreamItemV2, VaultStreamPullResultV2, VaultStreamV2 } from '../protocol/coordinator-stream.ts'

export class VaultCoordinatorStoreError extends Error {}
export class VaultCoordinatorConflictError extends VaultCoordinatorStoreError {}
export class VaultCoordinatorGenerationError extends VaultCoordinatorStoreError {}
export class VaultCoordinatorNotFoundError extends VaultCoordinatorStoreError {}

export interface VaultCoordinatorStoreLimits {
  maxPayloadBytes: number
  maxCheckpointBytes: number
  maxVaultPayloadBytes: number
  maxVaultPendingItems: number
  deliveryTtlMs: number
}

const DEFAULT_LIMITS: VaultCoordinatorStoreLimits = {
  maxPayloadBytes: 25 * 1024 * 1024,
  maxCheckpointBytes: 100 * 1024 * 1024,
  maxVaultPayloadBytes: 100 * 1024 * 1024,
  maxVaultPendingItems: 128,
  deliveryTtlMs: 30 * 24 * 60 * 60 * 1000,
}

type EntryState = 'pending' | 'completed' | 'expired'
interface EntryRow { vault_id: string; seq: string; append_id: string; sender_member_id: string | null; group_epoch: string; sent_at: string | null; append_signature: Uint8Array | null; payload: Uint8Array; payload_hash: Uint8Array; created_at: string; expires_at: string; state: EntryState; gap_reason: VaultCoordinatorRestoreReason | null }

/** SQLite state owned exclusively by biset-coordinator. The schema has no
 * identity, DID, SCID, domain, address, mailbox, or message-semantics field. */
export class SqliteVaultCoordinatorStore {
  private readonly limits: VaultCoordinatorStoreLimits

  constructor(private readonly database: Database, limits: VaultCoordinatorStoreLimits = DEFAULT_LIMITS) {
    this.limits = limits
    if (!Number.isSafeInteger(limits.deliveryTtlMs) || limits.deliveryTtlMs <= 0) throw new TypeError('deliveryTtlMs must be positive')
    installSchema(database)
  }

  static open(path: string, limits?: VaultCoordinatorStoreLimits): SqliteVaultCoordinatorStore {
    if (!path) throw new TypeError('Vault Coordinator database path is required')
    return new SqliteVaultCoordinatorStore(new Database(path), limits)
  }

  close(): void { this.database.close() }

  /** Returns the one owner-scoped stream. Existing v1 Vaults are adopted
   * lazily, preserving their id, sequence head, and latest checkpoint. */
  defaultStream(ownerSubject: string, generation: string): VaultStreamV2 {
    const transaction = this.database.transaction(() => {
      let stream = this.database.query<{ vault_id: VaultId; latest_seq: DeliverySeq; generation: string }, [string]>('SELECT vault_id, latest_seq, generation FROM vault_streams WHERE owner_subject=?').get(ownerSubject)
      if (!stream) {
        const legacy = this.database.query<{ vault_id: VaultId; latest_seq: DeliverySeq }, [string]>('SELECT vault_id, latest_seq FROM vaults WHERE owner_subject=? ORDER BY vault_id LIMIT 1').get(ownerSubject)
        const vaultId = legacy?.vault_id ?? (`vlt_${bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)))}` as VaultId)
        const latestSeq = legacy?.latest_seq ?? deliverySeq(0n)
        this.database.query('INSERT INTO vault_streams (vault_id, owner_subject, latest_seq, generation) VALUES (?, ?, ?, ?)').run(vaultId, ownerSubject, latestSeq, generation)
        stream = { vault_id: vaultId, latest_seq: latestSeq, generation }
      } else {
        this.assertOrAdvanceGeneration(stream.vault_id, ownerSubject, generation)
      }
      const checkpoint = this.streamCheckpointRow(stream.vault_id)
      return { version: 2 as const, vaultId: stream.vault_id, latestSeq: stream.latest_seq, ...(checkpoint ? { checkpointSeq: checkpoint.covered_seq } : {}) }
    })
    return transaction()
  }

  appendStream(input: VaultStreamAppendV2, ownerSubject: string, generation: string, now = new Date()): VaultStreamItemV2 {
    this.assertOrAdvanceGeneration(input.vaultId, ownerSubject, generation)
    if (input.payload.length === 0 || input.payload.length > this.limits.maxPayloadBytes) throw new VaultCoordinatorStoreError('stream payload size is invalid')
    if (!equalBytes(sha256Bytes(input.payload), input.payloadHash)) throw new VaultCoordinatorStoreError('payloadHash must equal SHA-256(payload)')
    const existing = this.database.query<{ seq: DeliverySeq; payload: Uint8Array; payload_hash: Uint8Array; created_at: string }, [string, string]>('SELECT seq, payload, payload_hash, created_at FROM vault_stream_entries WHERE vault_id=? AND append_id=?').get(input.vaultId, input.appendId)
    if (existing) {
      if (!equalBytes(bytes(existing.payload_hash), input.payloadHash)) throw new VaultCoordinatorConflictError('appendId is bound to another payload')
      return { version: 2, vaultId: input.vaultId, seq: existing.seq, payload: bytes(existing.payload), payloadHash: bytes(existing.payload_hash), createdAt: existing.created_at }
    }
    const createdAt = now.toISOString()
    const transaction = this.database.transaction(() => {
      const stream = this.stream(input.vaultId)
      const seq = deliverySeq(BigInt(stream.latest_seq) + 1n)
      this.database.query('UPDATE vault_streams SET latest_seq=? WHERE vault_id=?').run(seq, input.vaultId)
      this.database.query('INSERT INTO vault_stream_entries (vault_id, seq, append_id, payload, payload_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(input.vaultId, seq, input.appendId, input.payload, input.payloadHash, createdAt)
      return seq
    })
    const seq = transaction()
    return { version: 2, vaultId: input.vaultId, seq, payload: input.payload.slice(), payloadHash: input.payloadHash.slice(), createdAt }
  }

  pullStream(vaultId: VaultId, after: DeliverySeq, ownerSubject: string, generation: string): VaultStreamPullResultV2 {
    this.assertOrAdvanceGeneration(vaultId, ownerSubject, generation)
    const stream = this.stream(vaultId)
    const rows = this.database.query<{ seq: DeliverySeq; payload: Uint8Array; payload_hash: Uint8Array; created_at: string }, [string]>("SELECT seq, payload, payload_hash, created_at FROM vault_stream_entries WHERE vault_id=? AND length(payload)>0 ORDER BY length(seq), seq").all(vaultId)
    const items = rows.filter(row => BigInt(row.seq) > BigInt(after)).map(row => ({ version: 2 as const, vaultId, seq: row.seq, payload: bytes(row.payload), payloadHash: bytes(row.payload_hash), createdAt: row.created_at }))
    return { version: 2, items, nextCursor: items.at(-1)?.seq ?? after, latestSeq: stream.latest_seq }
  }

  putStreamCheckpoint(input: VaultStreamCheckpointPutV2, ownerSubject: string, generation: string, now = new Date()): void {
    this.assertOrAdvanceGeneration(input.vaultId, ownerSubject, generation)
    if (input.payload.length === 0 || input.payload.length > this.limits.maxCheckpointBytes) throw new VaultCoordinatorStoreError('checkpoint payload size is invalid')
    if (!equalBytes(sha256Bytes(input.payload), input.payloadHash)) throw new VaultCoordinatorStoreError('payloadHash must equal SHA-256(payload)')
    if (BigInt(input.coveredSeq) > BigInt(this.stream(input.vaultId).latest_seq)) throw new VaultCoordinatorStoreError('checkpoint cannot cover a future stream sequence')
    const current = this.database.query<{ covered_seq: DeliverySeq }, [string]>('SELECT covered_seq FROM vault_stream_checkpoints WHERE vault_id=?').get(input.vaultId)
    const baseline = this.streamCheckpointRow(input.vaultId)
    if (baseline && BigInt(input.coveredSeq) < BigInt(baseline.covered_seq)) throw new VaultCoordinatorConflictError('checkpoint sequence cannot move backwards')
    if (current && input.coveredSeq === current.covered_seq) return
    this.database.query(`INSERT INTO vault_stream_checkpoints (vault_id, covered_seq, payload, payload_hash, created_at)
      VALUES (?, ?, ?, ?, ?) ON CONFLICT(vault_id) DO UPDATE SET covered_seq=excluded.covered_seq,
      payload=excluded.payload, payload_hash=excluded.payload_hash, created_at=excluded.created_at`).run(input.vaultId, input.coveredSeq, input.payload, input.payloadHash, now.toISOString())
    this.database.query("UPDATE vault_stream_entries SET payload=x'' WHERE vault_id=? AND (length(seq)<length(?) OR (length(seq)=length(?) AND seq<=?))").run(input.vaultId, input.coveredSeq, input.coveredSeq, input.coveredSeq)
  }

  pullStreamCheckpoint(vaultId: VaultId, ownerSubject: string, generation: string): VaultStreamCheckpointV2 | null {
    this.assertOrAdvanceGeneration(vaultId, ownerSubject, generation)
    const row = this.streamCheckpointRow(vaultId)
    return row ? { version: 2, vaultId, coveredSeq: row.covered_seq, payload: bytes(row.payload), payloadHash: bytes(row.payload_hash), createdAt: row.created_at } : null
  }

  create(input: VaultGroupViewV1, ownerSubject: string): string {
    // The Biset Vault profile advances the freshly-created RFC 9420 group once
    // before publishing it.  ts-mls represents epoch 0 with an empty
    // confirmed transcript hash, while VaultGroupView deliberately requires a
    // real 32-byte transcript binding.  Therefore the first accepted view is
    // epoch 1, not the library's unpublished epoch 0 state.
    if (input.groupEpoch !== '1' || input.previousViewHash !== null || input.members.some(member => member.deliveryFloor !== '1')) {
      throw new VaultCoordinatorStoreError('genesis group view must use epoch 1, no previous hash, and delivery floor 1')
    }
    const installer = input.members.find(member => member.memberId === input.installerMemberId)!
    if (!ed25519.verify(input.signature, vaultGroupViewSigningBytes(input), installer.signaturePublicKey)) throw new VaultCoordinatorStoreError('genesis group view signature is invalid')
    const viewHash = vaultGroupViewHash(input)
    const transaction = this.database.transaction(() => {
      const existing = this.database.query<{ owner_subject: string; group_view_hash: string }, [string]>('SELECT owner_subject, group_view_hash FROM vaults WHERE vault_id = ?').get(input.vaultId)
      if (existing) {
        if (existing.owner_subject !== ownerSubject) throw new VaultCoordinatorConflictError('vaultId already exists')
        if (existing.group_view_hash === viewHash) return viewHash
        throw new VaultCoordinatorConflictError('vaultId already exists')
      }
      this.database.query('INSERT INTO vaults (vault_id, owner_subject, group_id, group_epoch, confirmed_transcript_hash, group_view_hash, latest_seq) VALUES (?, ?, ?, ?, ?, ?, ?)').run(input.vaultId, ownerSubject, input.groupId, input.groupEpoch, input.confirmedTranscriptHash, viewHash, '0')
      for (const member of input.members) this.database.query('INSERT INTO vault_members (vault_id, member_id, signature_public_key, delivery_floor, active) VALUES (?, ?, ?, ?, 1)').run(input.vaultId, member.memberId, member.signaturePublicKey, member.deliveryFloor)
      return viewHash
    })
    return transaction()
  }

  installGroupView(input: VaultGroupViewV1, ownerSubject: string): string {
    this.assertOwner(input.vaultId, ownerSubject)
    const vault = this.vault(input.vaultId)
    const viewHash = vaultGroupViewHash(input)
    if (viewHash === vault.group_view_hash) return viewHash
    if (input.previousViewHash !== vault.group_view_hash) throw new VaultCoordinatorConflictError('group view does not extend the accepted view hash')
    if (!equalBytes(input.groupId, bytes(vault.group_id))) throw new VaultCoordinatorConflictError('MLS groupId cannot change')
    if (BigInt(input.groupEpoch) !== BigInt(vault.group_epoch) + 1n) throw new VaultCoordinatorConflictError('group view epoch must advance by exactly one')
    const currentMembers = this.database.query<{ member_id: string; signature_public_key: Uint8Array; delivery_floor: string }, [string]>('SELECT member_id, signature_public_key, delivery_floor FROM vault_members WHERE vault_id = ? AND active = 1').all(input.vaultId)
    const installer = currentMembers.find(member => member.member_id === input.installerMemberId)
    if (!installer || !ed25519.verify(input.signature, vaultGroupViewSigningBytes(input), bytes(installer.signature_public_key))) throw new VaultCoordinatorStoreError('group view installer signature is invalid')
    const currentById = new Map(currentMembers.map(member => [member.member_id, member]))
    const firstNewSequence = deliverySeq(BigInt(vault.latest_seq) + 1n)
    for (const member of input.members) {
      const existing = currentById.get(member.memberId)
      if (existing && existing.delivery_floor !== member.deliveryFloor) throw new VaultCoordinatorStoreError('existing member delivery floor cannot change')
      if (!existing && member.deliveryFloor !== firstNewSequence) throw new VaultCoordinatorStoreError('new member delivery floor must start at the next sequence')
    }
    const nextIds = new Set(input.members.map(member => member.memberId))
    const removedIds = currentMembers.filter(member => !nextIds.has(member.member_id)).map(member => member.member_id)
    const transaction = this.database.transaction(() => {
      this.database.query('UPDATE vault_members SET active = 0 WHERE vault_id = ?').run(input.vaultId)
      for (const member of input.members) {
        this.database.query('INSERT INTO vault_members (vault_id, member_id, signature_public_key, delivery_floor, active) VALUES (?, ?, ?, ?, 1) ON CONFLICT(vault_id, member_id) DO UPDATE SET signature_public_key=excluded.signature_public_key, delivery_floor=excluded.delivery_floor, active=1').run(input.vaultId, member.memberId, member.signaturePublicKey, member.deliveryFloor)
      }
      for (const memberId of removedIds) {
        this.database.query("INSERT OR IGNORE INTO retired_recipients (vault_id, seq, member_id) SELECT vault_id, seq, member_id FROM recipients WHERE vault_id=? AND member_id=?").run(input.vaultId, memberId)
      }
      this.completeSatisfiedEntries(input.vaultId)
      this.database.query('UPDATE vaults SET group_epoch=?, confirmed_transcript_hash=?, group_view_hash=? WHERE vault_id=?').run(input.groupEpoch, input.confirmedTranscriptHash, viewHash, input.vaultId)
      return viewHash
    })
    return transaction()
  }

  append(input: VaultCoordinatorAppendV1, ownerSubject: string, now = new Date()): VaultCoordinatorItemV1 {
    this.assertOwner(input.vaultId, ownerSubject)
    if (!equalBytes(sha256Bytes(input.payload), input.payloadHash)) throw new VaultCoordinatorStoreError('payloadHash must equal SHA-256(payload)')
    if (input.payload.length > this.limits.maxPayloadBytes) throw new VaultCoordinatorStoreError('payload exceeds maxPayloadBytes')
    const existing = this.database.query<EntryRow, [string, string]>('SELECT * FROM entries WHERE vault_id = ? AND append_id = ?').get(input.vaultId, input.appendId)
    if (existing && existing.sender_member_id !== null && existing.sent_at !== null && existing.append_signature !== null) {
      if (!equalBytes(bytes(existing.payload_hash), input.payloadHash)) throw new VaultCoordinatorConflictError('appendId is bound to another payload')
      if (existing.sender_member_id !== input.senderMemberId || existing.group_epoch !== input.groupEpoch || existing.sent_at !== input.sentAt || !equalBytes(bytes(existing.append_signature), input.signature)) {
        throw new VaultCoordinatorConflictError('append retry does not match the accepted signed envelope')
      }
      return item(existing)
    }
    const senderKey = this.activeMemberKey(input.vaultId, input.senderMemberId)
    if (!ed25519.verify(input.signature, vaultCoordinatorAppendSigningBytes(input), senderKey)) throw new VaultCoordinatorStoreError('append member signature is invalid')
    const vault = this.vault(input.vaultId)
    if (vault.group_epoch !== input.groupEpoch) throw new VaultCoordinatorConflictError('append group epoch is not current')
    this.expire(now)
    if (existing) {
      if (!equalBytes(bytes(existing.payload_hash), input.payloadHash)) throw new VaultCoordinatorConflictError('appendId is bound to another payload')
      return item(existing)
    }
    const createdAt = now.toISOString()
    const expiresAt = new Date(now.getTime() + this.limits.deliveryTtlMs).toISOString()
    const append = this.database.transaction(() => {
      const current = this.vault(input.vaultId)
      const seq = deliverySeq(BigInt(current.latest_seq) + 1n)
      this.database.query('UPDATE vaults SET latest_seq = ? WHERE vault_id = ?').run(seq, input.vaultId)
      this.database.query('INSERT INTO entries (vault_id, seq, append_id, sender_member_id, group_epoch, sent_at, append_signature, payload, payload_hash, created_at, expires_at, state, gap_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)').run(input.vaultId, seq, input.appendId, input.senderMemberId, input.groupEpoch, input.sentAt, input.signature, input.payload, input.payloadHash, createdAt, expiresAt, 'pending')
      const recipients = this.database.query<{ member_id: string }, [string]>('SELECT member_id FROM vault_members WHERE vault_id = ? AND active = 1').all(input.vaultId)
      if (recipients.length === 0) throw new VaultCoordinatorStoreError('Vault has no active members')
      for (const recipient of recipients) this.database.query('INSERT INTO recipients (vault_id, seq, member_id) VALUES (?, ?, ?)').run(input.vaultId, seq, recipient.member_id)
      return seq
    })
    const seq = append()
    this.enforceQuota(input.vaultId)
    return { version: 1, vaultId: input.vaultId, seq, groupEpoch: input.groupEpoch, payload: input.payload.slice(), payloadHash: input.payloadHash.slice(), createdAt, expiresAt }
  }

  pull(input: VaultCoordinatorPullV1, ownerSubject: string, now = new Date()): VaultCoordinatorPullResult {
    this.assertOwner(input.vaultId, ownerSubject)
    const recipientKey = this.activeMemberKey(input.vaultId, input.recipientMemberId)
    if (!ed25519.verify(input.signature, vaultCoordinatorPullSigningBytes(input), recipientKey)) throw new VaultCoordinatorStoreError('pull member signature is invalid')
    this.expire(now)
    const member = this.database.query<{ delivery_floor: string }, [string, string]>('SELECT delivery_floor FROM vault_members WHERE vault_id = ? AND member_id = ? AND active = 1').get(input.vaultId, input.recipientMemberId)!
    const vault = this.vault(input.vaultId)
    const retainedFrom = this.retainedFrom(input.vaultId, vault.latest_seq)
    const requested = BigInt(input.after)
    if (requested < BigInt(member.delivery_floor) - 1n) return restore(input.after, retainedFrom, vault.latest_seq, 'new-member')
    if (requested < BigInt(retainedFrom) - 1n) return restore(input.after, retainedFrom, vault.latest_seq, this.gapReason(input.vaultId, deliverySeq(requested + 1n)))
    const rows = this.database.query<EntryRow, [string, string]>('SELECT e.* FROM entries e JOIN recipients r ON r.vault_id=e.vault_id AND r.seq=e.seq LEFT JOIN acknowledgements a ON a.vault_id=r.vault_id AND a.seq=r.seq AND a.member_id=r.member_id WHERE e.vault_id=? AND r.member_id=? AND e.state=\'pending\' AND a.member_id IS NULL ORDER BY length(e.seq), e.seq').all(input.vaultId, input.recipientMemberId)
    const items = rows.filter(row => BigInt(row.seq) > requested).map(item)
    return { kind: 'items', items, nextCursor: items.at(-1)?.seq ?? input.after, retainedFrom, latestSeq: vault.latest_seq }
  }

  acknowledge(input: VaultCoordinatorAckV1, ownerSubject: string, now = new Date()): void {
    this.assertOwner(input.vaultId, ownerSubject)
    const recipientKey = this.activeMemberKey(input.vaultId, input.recipientMemberId)
    if (!ed25519.verify(input.signature, vaultCoordinatorAckSigningBytes(input), recipientKey)) throw new VaultCoordinatorStoreError('ACK member signature is invalid')
    this.expire(now)
    const transaction = this.database.transaction(() => {
      const row = this.database.query<EntryRow, [string, string]>('SELECT * FROM entries WHERE vault_id = ? AND seq = ?').get(input.vaultId, input.seq)
      if (!row) throw new VaultCoordinatorNotFoundError('unknown delivery sequence')
      if (!equalBytes(bytes(row.payload_hash), input.payloadHash)) throw new VaultCoordinatorStoreError('ACK payload hash does not match')
      const recipient = this.database.query<{ member_id: string }, [string, string, string]>('SELECT member_id FROM recipients WHERE vault_id = ? AND seq = ? AND member_id = ?').get(input.vaultId, input.seq, input.recipientMemberId)
      if (!recipient) throw new VaultCoordinatorStoreError('member is not in the recipient snapshot')
      if (row.state === 'completed') return
      if (row.state !== 'pending') throw new VaultCoordinatorConflictError(`delivery is already ${row.state}`)
      this.database.query('INSERT OR IGNORE INTO acknowledgements (vault_id, seq, member_id) VALUES (?, ?, ?)').run(input.vaultId, input.seq, input.recipientMemberId)
      const pending = this.database.query<{ count: number }, [string, string]>('SELECT count(*) AS count FROM recipients r LEFT JOIN acknowledgements a ON a.vault_id=r.vault_id AND a.seq=r.seq AND a.member_id=r.member_id LEFT JOIN retired_recipients t ON t.vault_id=r.vault_id AND t.seq=r.seq AND t.member_id=r.member_id WHERE r.vault_id=? AND r.seq=? AND a.member_id IS NULL AND t.member_id IS NULL').get(input.vaultId, input.seq)!.count
      if (pending === 0) this.database.query("UPDATE entries SET state='completed', gap_reason=NULL WHERE vault_id=? AND seq=?").run(input.vaultId, input.seq)
    })
    transaction()
  }

  ownedVaults(ownerSubject: string): VaultCoordinatorOwnedVaultV1[] {
    return this.database.query<{ vault_id: VaultId; latest_seq: DeliverySeq; checkpoint_seq: DeliverySeq | null }, [string]>(`
      SELECT v.vault_id, v.latest_seq, c.covered_seq AS checkpoint_seq
      FROM vaults v LEFT JOIN vault_checkpoints c ON c.vault_id=v.vault_id
      WHERE v.owner_subject=? ORDER BY v.vault_id
    `).all(ownerSubject).map(row => ({ vaultId: row.vault_id, latestSeq: row.latest_seq, ...(row.checkpoint_seq === null ? {} : { checkpointSeq: row.checkpoint_seq }) }))
  }

  putCheckpoint(input: VaultCoordinatorCheckpointPutV1, ownerSubject: string): void {
    this.assertOwner(input.vaultId, ownerSubject)
    if (input.payload.length === 0 || input.payload.length > this.limits.maxCheckpointBytes) throw new VaultCoordinatorStoreError('checkpoint payload size is invalid')
    if (!equalBytes(sha256Bytes(input.payload), input.payloadHash)) throw new VaultCoordinatorStoreError('checkpoint payloadHash must equal SHA-256(payload)')
    const writerKey = this.activeMemberKey(input.vaultId, input.writerMemberId)
    if (!ed25519.verify(input.signature, vaultCoordinatorCheckpointSigningBytes(input), writerKey)) throw new VaultCoordinatorStoreError('checkpoint member signature is invalid')
    const vault = this.vault(input.vaultId)
    if (BigInt(input.coveredSeq) > BigInt(vault.latest_seq)) throw new VaultCoordinatorStoreError('checkpoint cannot cover a future delivery sequence')
    const existing = this.database.query<{ covered_seq: DeliverySeq; payload_hash: Uint8Array }, [string]>('SELECT covered_seq, payload_hash FROM vault_checkpoints WHERE vault_id=?').get(input.vaultId)
    if (existing) {
      if (BigInt(input.coveredSeq) < BigInt(existing.covered_seq)) throw new VaultCoordinatorConflictError('checkpoint sequence cannot move backwards')
      if (input.coveredSeq === existing.covered_seq) {
        // Several devices normally reach the same sequence together and use
        // fresh envelope nonces, so their opaque bytes differ even for the
        // same logical snapshot. First accepted checkpoint wins this
        // sequence; later same-sequence uploads are successful no-ops.
        return
      }
    }
    this.database.query(`
      INSERT INTO vault_checkpoints (vault_id, covered_seq, writer_member_id, payload, payload_hash, created_at, signature)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(vault_id) DO UPDATE SET covered_seq=excluded.covered_seq, writer_member_id=excluded.writer_member_id,
        payload=excluded.payload, payload_hash=excluded.payload_hash, created_at=excluded.created_at, signature=excluded.signature
    `).run(input.vaultId, input.coveredSeq, input.writerMemberId, input.payload, input.payloadHash, input.createdAt, input.signature)
    // Delivery bodies are retained until a complete encrypted checkpoint
    // durably supersedes them. ACK alone is not a backup boundary.
    const superseded = this.database.query<{ seq: DeliverySeq }, [string]>('SELECT seq FROM entries WHERE vault_id=? AND length(payload)>0').all(input.vaultId)
    for (const entry of superseded) {
      if (BigInt(entry.seq) <= BigInt(input.coveredSeq)) this.database.query("UPDATE entries SET payload=x'', state='completed', gap_reason='checkpointed' WHERE vault_id=? AND seq=?").run(input.vaultId, entry.seq)
    }
  }

  pullCheckpoint(vaultId: VaultId, ownerSubject: string): VaultCoordinatorCheckpointV1 | null {
    this.assertOwner(vaultId, ownerSubject)
    const row = this.database.query<{ covered_seq: DeliverySeq; writer_member_id: import('../protocol/ids.ts').VaultMemberId; payload: Uint8Array; payload_hash: Uint8Array; created_at: string }, [string]>('SELECT covered_seq, writer_member_id, payload, payload_hash, created_at FROM vault_checkpoints WHERE vault_id=?').get(vaultId)
    return row ? { version: 1, vaultId, writerMemberId: row.writer_member_id, coveredSeq: row.covered_seq, payload: bytes(row.payload), payloadHash: bytes(row.payload_hash), createdAt: row.created_at } : null
  }

  publishKeyPackage(input: VaultMlsKeyPackagePublishV1, ownerSubject: string): void {
    this.assertOwner(input.vaultId, ownerSubject)
    if (!ed25519.verify(input.signature, vaultMlsKeyPackageSigningBytes(input), input.signaturePublicKey)) throw new VaultCoordinatorStoreError('KeyPackage publisher signature is invalid')
    const active = this.database.query<{ member_id: string }, [string, string]>('SELECT member_id FROM vault_members WHERE vault_id=? AND member_id=? AND active=1').get(input.vaultId, input.memberId)
    if (active) throw new VaultCoordinatorConflictError('Vault member is already active')
    const encoded = encodeVaultMlsKeyPackage(input)
    const existing = this.database.query<{ package_json: string }, [string, string]>('SELECT package_json FROM mls_key_packages WHERE vault_id=? AND member_id=?').get(input.vaultId, input.memberId)
    if (existing) {
      if (existing.package_json === encoded) return
      throw new VaultCoordinatorConflictError('Vault member already has another pending KeyPackage')
    }
    this.database.query('INSERT INTO mls_key_packages (vault_id, member_id, signature_public_key, package_json, published_at) VALUES (?, ?, ?, ?, ?)').run(input.vaultId, input.memberId, input.signaturePublicKey, encoded, input.publishedAt)
  }

  pullKeyPackages(input: VaultMlsMemberRequestV1, ownerSubject: string): VaultMlsKeyPackagePublishV1[] {
    this.assertSignedMemberRequest(input, ownerSubject)
    return this.database.query<{ package_json: string }, [string]>('SELECT package_json FROM mls_key_packages WHERE vault_id=? ORDER BY published_at, member_id').all(input.vaultId).map(row => decodeVaultMlsKeyPackage(row.package_json))
  }

  installMlsTransition(input: VaultMlsTransitionV1, ownerSubject: string, now = new Date()): string {
    const vaultId = input.groupView.vaultId
    this.assertOwner(vaultId, ownerSubject)
    const fingerprint = transitionFingerprint(input)
    const existing = this.database.query<{ transition_hash: string }, [string, string]>('SELECT transition_hash FROM mls_transitions WHERE vault_id=? AND group_epoch=?').get(vaultId, input.groupView.groupEpoch)
    if (existing) {
      if (existing.transition_hash === fingerprint) return vaultGroupViewHash(input.groupView)
      throw new VaultCoordinatorConflictError('MLS epoch already has another transition')
    }
    const installerKey = this.activeMemberKey(vaultId, input.groupView.installerMemberId)
    if (!ed25519.verify(input.signature, vaultMlsTransitionSigningBytes(input), installerKey)) throw new VaultCoordinatorStoreError('MLS transition signature is invalid')
    const current = this.database.query<{ member_id: string }, [string]>('SELECT member_id FROM vault_members WHERE vault_id=? AND active=1').all(vaultId)
    const currentIds = new Set(current.map(row => row.member_id))
    const added = input.groupView.members.filter(member => !currentIds.has(member.memberId))
    if (added.length !== input.welcomes.length || added.some(member => !input.welcomes.some(welcome => welcome.memberId === member.memberId))) throw new VaultCoordinatorStoreError('MLS transition Welcome set must equal newly added members')
    for (const member of added) {
      const pending = this.database.query<{ signature_public_key: Uint8Array }, [string, string]>('SELECT signature_public_key FROM mls_key_packages WHERE vault_id=? AND member_id=?').get(vaultId, member.memberId)
      if (!pending || !equalBytes(bytes(pending.signature_public_key), member.signaturePublicKey)) throw new VaultCoordinatorStoreError('new member has no matching published KeyPackage')
    }
    const createdAt = now.toISOString()
    const transaction = this.database.transaction(() => {
      const hash = this.installGroupView(input.groupView, ownerSubject)
      this.database.query('INSERT INTO mls_transitions (vault_id, group_epoch, group_view_json, transition_hash, commit_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(vaultId, input.groupView.groupEpoch, encodeVaultGroupView(input.groupView), fingerprint, input.commit, createdAt)
      for (const welcome of input.welcomes) this.database.query('INSERT INTO mls_welcomes (vault_id, member_id, group_epoch, welcome_bytes, created_at) VALUES (?, ?, ?, ?, ?)').run(vaultId, welcome.memberId, input.groupView.groupEpoch, welcome.payload, createdAt)
      for (const member of added) this.database.query('DELETE FROM mls_key_packages WHERE vault_id=? AND member_id=?').run(vaultId, member.memberId)
      return hash
    })
    return transaction()
  }

  pullMlsTransitions(input: VaultMlsMemberRequestV1, ownerSubject: string): VaultMlsTransitionItemV1[] {
    this.assertSignedMemberRequest(input, ownerSubject)
    return this.database.query<{ group_view_json: string; commit_bytes: Uint8Array; created_at: string; group_epoch: string }, [string]>('SELECT group_view_json, commit_bytes, created_at, group_epoch FROM mls_transitions WHERE vault_id=? ORDER BY length(group_epoch), group_epoch').all(input.vaultId).filter(row => BigInt(row.group_epoch) > BigInt(input.afterEpoch)).map(row => ({ groupView: decodeVaultGroupView(row.group_view_json), commit: bytes(row.commit_bytes), createdAt: row.created_at }))
  }

  pullMlsWelcome(input: VaultMlsMemberRequestV1, ownerSubject: string): VaultMlsWelcomeDeliveryV1 | null {
    this.assertSignedMemberRequest(input, ownerSubject)
    const row = this.database.query<{ group_view_json: string; welcome_bytes: Uint8Array; created_at: string }, [string, string]>('SELECT t.group_view_json, w.welcome_bytes, w.created_at FROM mls_welcomes w JOIN mls_transitions t ON t.vault_id=w.vault_id AND t.group_epoch=w.group_epoch WHERE w.vault_id=? AND w.member_id=? ORDER BY length(w.group_epoch) DESC, w.group_epoch DESC LIMIT 1').get(input.vaultId, input.memberId)
    return row ? { groupView: decodeVaultGroupView(row.group_view_json), welcome: bytes(row.welcome_bytes), createdAt: row.created_at } : null
  }

  createMlsInvitation(input: VaultMlsMemberRequestV1, ownerSubject: string, now = new Date()): VaultMlsInvitationV1 {
    this.assertSignedMemberRequest(input, ownerSubject)
    this.database.query('DELETE FROM mls_invitations WHERE expires_at <= ? OR used_at IS NOT NULL').run(now.toISOString())
    // One live invitation per Vault keeps this unauthenticated-token table
    // bounded; issuing a replacement intentionally revokes the prior code.
    this.database.query('DELETE FROM mls_invitations WHERE vault_id=?').run(input.vaultId)
    const invitation = `vin_${bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)))}`
    const expiresAt = new Date(now.getTime() + 10 * 60 * 1000).toISOString()
    this.database.query('INSERT INTO mls_invitations (invitation_hash, vault_id, expires_at, used_at) VALUES (?, ?, ?, NULL)').run(invitationHash(invitation), input.vaultId, expiresAt)
    return { invitation, expiresAt }
  }

  redeemMlsInvitation(input: VaultMlsInvitationRedeemV1, ownerSubject: string, now = new Date()): { vaultId: VaultId } {
    const row = this.database.query<{ vault_id: VaultId; owner_subject: string; expires_at: string; used_at: string | null }, [string]>('SELECT i.vault_id, v.owner_subject, i.expires_at, i.used_at FROM mls_invitations i JOIN vaults v ON v.vault_id=i.vault_id WHERE i.invitation_hash=?').get(invitationHash(input.invitation))
    if (!row || row.owner_subject !== ownerSubject || row.used_at !== null || row.expires_at <= now.toISOString()) throw new VaultCoordinatorNotFoundError('Vault invitation not found')
    const updated = this.database.query('UPDATE mls_invitations SET used_at=? WHERE invitation_hash=? AND used_at IS NULL').run(now.toISOString(), invitationHash(input.invitation))
    if (updated.changes !== 1) throw new VaultCoordinatorNotFoundError('Vault invitation not found')
    return { vaultId: row.vault_id }
  }

  expire(now = new Date()): void {
    // A delivery may outlive its transport TTL until a durable checkpoint
    // supersedes it. Deleting the only complete copy merely because no
    // endpoint was online would violate Coordinator's persistence role.
    void now
  }

  private assertOwner(vaultId: VaultId, subject: string): void {
    const row = this.database.query<{ owner_subject: string }, [string]>('SELECT owner_subject FROM vaults WHERE vault_id = ?').get(vaultId)
    if (!row) throw new VaultCoordinatorNotFoundError('Vault not found')
    if (row.owner_subject !== subject) throw new VaultCoordinatorNotFoundError('Vault not found')
  }

  private assertOrAdvanceGeneration(vaultId: VaultId, subject: string, generation: string): void {
    const incoming = generationNumber(generation)
    const row = this.database.query<{ owner_subject: string; generation: string }, [string]>('SELECT owner_subject, generation FROM vault_streams WHERE vault_id=?').get(vaultId)
    if (!row || row.owner_subject !== subject) throw new VaultCoordinatorNotFoundError('Vault stream not found')
    if (row.generation === generation) return
    const current = row.generation ? generationNumber(row.generation) : 0n
    if (incoming <= current) throw new VaultCoordinatorGenerationError('Vault access generation is obsolete')
    const updated = this.database.query('UPDATE vault_streams SET generation=? WHERE vault_id=? AND generation=?').run(generation, vaultId, row.generation)
    if (updated.changes !== 1) return this.assertOrAdvanceGeneration(vaultId, subject, generation)
  }

  private stream(vaultId: VaultId): { latest_seq: DeliverySeq } {
    const row = this.database.query<{ latest_seq: DeliverySeq }, [string]>('SELECT latest_seq FROM vault_streams WHERE vault_id=?').get(vaultId)
    if (!row) throw new VaultCoordinatorNotFoundError('Vault stream not found')
    return row
  }

  private streamCheckpointRow(vaultId: VaultId): { covered_seq: DeliverySeq; payload: Uint8Array; payload_hash: Uint8Array; created_at: string } | null {
    const current = this.database.query<{ covered_seq: DeliverySeq; payload: Uint8Array; payload_hash: Uint8Array; created_at: string }, [string]>('SELECT covered_seq, payload, payload_hash, created_at FROM vault_stream_checkpoints WHERE vault_id=?').get(vaultId)
    if (current) return current
    const legacy = this.database.query<{ covered_seq: DeliverySeq; payload: Uint8Array; payload_hash: Uint8Array; created_at: string }, [string]>('SELECT covered_seq, payload, payload_hash, created_at FROM vault_checkpoints WHERE vault_id=?').get(vaultId)
    return legacy ?? null
  }

  private activeMemberKey(vaultId: VaultId, memberId: string): Uint8Array {
    const member = this.database.query<{ signature_public_key: Uint8Array }, [string, string]>('SELECT signature_public_key FROM vault_members WHERE vault_id = ? AND member_id = ? AND active = 1').get(vaultId, memberId)
    if (!member) throw new VaultCoordinatorStoreError('Vault member is not active')
    return bytes(member.signature_public_key)
  }

  private assertSignedMemberRequest(input: VaultMlsMemberRequestV1, ownerSubject: string): void {
    this.assertOwner(input.vaultId, ownerSubject)
    const key = this.activeMemberKey(input.vaultId, input.memberId)
    if (!ed25519.verify(input.signature, vaultMlsMemberRequestSigningBytes(input), key)) throw new VaultCoordinatorStoreError('MLS member request signature is invalid')
  }

  private vault(vaultId: VaultId): { group_id: Uint8Array; group_epoch: string; confirmed_transcript_hash: Uint8Array; group_view_hash: string; latest_seq: DeliverySeq } {
    const row = this.database.query<{ group_id: Uint8Array; group_epoch: string; confirmed_transcript_hash: Uint8Array; group_view_hash: string; latest_seq: DeliverySeq }, [string]>('SELECT group_id, group_epoch, confirmed_transcript_hash, group_view_hash, latest_seq FROM vaults WHERE vault_id = ?').get(vaultId)
    if (!row) throw new VaultCoordinatorNotFoundError('Vault not found')
    return row
  }

  private retainedFrom(vaultId: VaultId, latest: DeliverySeq): DeliverySeq {
    return this.database.query<{ seq: DeliverySeq }, [string]>("SELECT seq FROM entries WHERE vault_id=? AND state='pending' ORDER BY length(seq), seq LIMIT 1").get(vaultId)?.seq ?? deliverySeq(BigInt(latest) + 1n)
  }

  private gapReason(vaultId: VaultId, seq: DeliverySeq): VaultCoordinatorRestoreReason {
    return this.database.query<{ gap_reason: VaultCoordinatorRestoreReason | null }, [string, string]>('SELECT gap_reason FROM entries WHERE vault_id=? AND seq=?').get(vaultId, seq)?.gap_reason ?? 'retention-quota'
  }

  private enforceQuota(vaultId: VaultId): void {
    while (true) {
      const state = this.database.query<{ count: number; bytes: number }, [string]>("SELECT count(*) AS count, coalesce(sum(length(payload)),0) AS bytes FROM entries WHERE vault_id=? AND state='pending'").get(vaultId)!
      if (state.count <= this.limits.maxVaultPendingItems && state.bytes <= this.limits.maxVaultPayloadBytes) return
      const oldest = this.database.query<{ seq: string }, [string]>("SELECT seq FROM entries WHERE vault_id=? AND state='pending' ORDER BY length(seq), seq LIMIT 1").get(vaultId)
      if (!oldest) throw new VaultCoordinatorStoreError('cannot enforce Vault quota')
      const checkpoint = this.database.query<{ covered_seq: DeliverySeq }, [string]>('SELECT covered_seq FROM vault_checkpoints WHERE vault_id=?').get(vaultId)
      if (!checkpoint || BigInt(oldest.seq) > BigInt(checkpoint.covered_seq)) return
      this.database.query("UPDATE entries SET payload=x'', state='completed', gap_reason='checkpointed' WHERE vault_id=? AND seq=?").run(vaultId, oldest.seq)
    }
  }

  private completeSatisfiedEntries(vaultId: VaultId): void {
    const pending = this.database.query<{ seq: string }, [string]>("SELECT seq FROM entries WHERE vault_id=? AND state='pending'").all(vaultId)
    for (const entry of pending) {
      const outstanding = this.database.query<{ count: number }, [string, string]>('SELECT count(*) AS count FROM recipients r LEFT JOIN acknowledgements a ON a.vault_id=r.vault_id AND a.seq=r.seq AND a.member_id=r.member_id LEFT JOIN retired_recipients t ON t.vault_id=r.vault_id AND t.seq=r.seq AND t.member_id=r.member_id WHERE r.vault_id=? AND r.seq=? AND a.member_id IS NULL AND t.member_id IS NULL').get(vaultId, entry.seq)!.count
      if (outstanding === 0) this.database.query("UPDATE entries SET state='completed', gap_reason=NULL WHERE vault_id=? AND seq=?").run(vaultId, entry.seq)
    }
  }
}

function installSchema(database: Database): void {
  database.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS vaults (vault_id TEXT PRIMARY KEY, owner_subject TEXT NOT NULL, group_id BLOB NOT NULL, group_epoch TEXT NOT NULL, confirmed_transcript_hash BLOB NOT NULL, group_view_hash TEXT NOT NULL, latest_seq TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS vault_members (vault_id TEXT NOT NULL, member_id TEXT NOT NULL, signature_public_key BLOB NOT NULL, delivery_floor TEXT NOT NULL, active INTEGER NOT NULL, PRIMARY KEY(vault_id, member_id), FOREIGN KEY(vault_id) REFERENCES vaults(vault_id));
    CREATE TABLE IF NOT EXISTS entries (vault_id TEXT NOT NULL, seq TEXT NOT NULL, append_id TEXT NOT NULL, sender_member_id TEXT NOT NULL, group_epoch TEXT NOT NULL, sent_at TEXT NOT NULL, append_signature BLOB NOT NULL, payload BLOB NOT NULL, payload_hash BLOB NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, state TEXT NOT NULL, gap_reason TEXT, PRIMARY KEY(vault_id, seq), UNIQUE(vault_id, append_id), FOREIGN KEY(vault_id) REFERENCES vaults(vault_id));
    CREATE TABLE IF NOT EXISTS recipients (vault_id TEXT NOT NULL, seq TEXT NOT NULL, member_id TEXT NOT NULL, PRIMARY KEY(vault_id, seq, member_id), FOREIGN KEY(vault_id, seq) REFERENCES entries(vault_id, seq));
    CREATE TABLE IF NOT EXISTS acknowledgements (vault_id TEXT NOT NULL, seq TEXT NOT NULL, member_id TEXT NOT NULL, PRIMARY KEY(vault_id, seq, member_id), FOREIGN KEY(vault_id, seq, member_id) REFERENCES recipients(vault_id, seq, member_id));
    CREATE TABLE IF NOT EXISTS retired_recipients (vault_id TEXT NOT NULL, seq TEXT NOT NULL, member_id TEXT NOT NULL, PRIMARY KEY(vault_id, seq, member_id), FOREIGN KEY(vault_id, seq, member_id) REFERENCES recipients(vault_id, seq, member_id));
    CREATE TABLE IF NOT EXISTS mls_key_packages (vault_id TEXT NOT NULL, member_id TEXT NOT NULL, signature_public_key BLOB NOT NULL, package_json TEXT NOT NULL, published_at TEXT NOT NULL, PRIMARY KEY(vault_id, member_id), FOREIGN KEY(vault_id) REFERENCES vaults(vault_id));
    CREATE TABLE IF NOT EXISTS mls_transitions (vault_id TEXT NOT NULL, group_epoch TEXT NOT NULL, group_view_json TEXT NOT NULL, transition_hash TEXT NOT NULL, commit_bytes BLOB NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(vault_id, group_epoch), FOREIGN KEY(vault_id) REFERENCES vaults(vault_id));
    CREATE TABLE IF NOT EXISTS mls_welcomes (vault_id TEXT NOT NULL, member_id TEXT NOT NULL, group_epoch TEXT NOT NULL, welcome_bytes BLOB NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(vault_id, member_id, group_epoch), FOREIGN KEY(vault_id, group_epoch) REFERENCES mls_transitions(vault_id, group_epoch));
    CREATE TABLE IF NOT EXISTS mls_invitations (invitation_hash TEXT PRIMARY KEY, vault_id TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT, FOREIGN KEY(vault_id) REFERENCES vaults(vault_id));
    CREATE TABLE IF NOT EXISTS vault_checkpoints (vault_id TEXT PRIMARY KEY, covered_seq TEXT NOT NULL, writer_member_id TEXT NOT NULL, payload BLOB NOT NULL, payload_hash BLOB NOT NULL, created_at TEXT NOT NULL, signature BLOB NOT NULL, FOREIGN KEY(vault_id) REFERENCES vaults(vault_id));
    CREATE INDEX IF NOT EXISTS entries_pending ON entries(vault_id, state, seq);
    CREATE TABLE IF NOT EXISTS vault_streams (vault_id TEXT PRIMARY KEY, owner_subject TEXT NOT NULL UNIQUE, latest_seq TEXT NOT NULL, generation TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS vault_stream_entries (vault_id TEXT NOT NULL, seq TEXT NOT NULL, append_id TEXT NOT NULL, payload BLOB NOT NULL, payload_hash BLOB NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(vault_id, seq), UNIQUE(vault_id, append_id), FOREIGN KEY(vault_id) REFERENCES vault_streams(vault_id));
    CREATE TABLE IF NOT EXISTS vault_stream_checkpoints (vault_id TEXT PRIMARY KEY, covered_seq TEXT NOT NULL, payload BLOB NOT NULL, payload_hash BLOB NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(vault_id) REFERENCES vault_streams(vault_id));
  `)
  addColumnIfMissing(database, 'entries', 'sender_member_id', 'TEXT')
  addColumnIfMissing(database, 'entries', 'sent_at', 'TEXT')
  addColumnIfMissing(database, 'entries', 'append_signature', 'BLOB')
  addColumnIfMissing(database, 'vault_streams', 'generation', "TEXT NOT NULL DEFAULT ''")
}

function addColumnIfMissing(database: Database, table: string, column: string, type: string): void {
  const columns = database.query<{ name: string }, []>(`PRAGMA table_info(${table})`).all()
  if (!columns.some(value => value.name === column)) database.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`)
}

function item(row: EntryRow): VaultCoordinatorItemV1 {
  return { version: 1, vaultId: row.vault_id as VaultId, seq: row.seq, groupEpoch: row.group_epoch, payload: bytes(row.payload), payloadHash: bytes(row.payload_hash), createdAt: row.created_at, expiresAt: row.expires_at }
}
function bytes(value: Uint8Array): Uint8Array { return new Uint8Array(value) }
function restore(requestedCursor: DeliverySeq, retainedFrom: DeliverySeq, latestSeq: DeliverySeq, reason: VaultCoordinatorRestoreReason): VaultCoordinatorPullResult {
  return { kind: 'restoreRequired', requestedCursor, retainedFrom, latestSeq, reason }
}

function transitionFingerprint(value: VaultMlsTransitionV1): string {
  const signing = vaultMlsTransitionSigningBytes(value)
  const bytes = new Uint8Array(signing.length + value.signature.length)
  bytes.set(signing)
  bytes.set(value.signature, signing.length)
  return `sha256:${bytesToBase64url(sha256Bytes(bytes))}`
}
function invitationHash(value: string): string { return `sha256:${bytesToBase64url(sha256Bytes(new TextEncoder().encode(`biset/vault-invitation/v1\0${value}`)))}` }
function generationNumber(value: string): bigint {
  const match = value.match(/^([1-9][0-9]*)-[A-Za-z0-9_-]{20,200}$/)
  if (!match) throw new VaultCoordinatorGenerationError('Vault access generation is invalid')
  return BigInt(match[1]!)
}
