import type { IdentityId } from '../../../protocol/ids.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../projection/gateway.ts'
import { localJmapSnapshotFromProjection } from '../projection/gateway.ts'
import { projectionState, reduceLocalJmapProjection } from '../projection/reducer.ts'
import { decryptVaultMutationRecords } from './mutation-records.ts'
import type { VaultEventVerifier } from './events.ts'
import type { SegmentKeyResolver } from './segment-key-resolver.ts'
import type { VaultEventRecord, VaultObjectRecord, VaultProjectionMeta } from './store.ts'

export interface ProjectorStore {
  readVaultEvents(identityId: IdentityId): Promise<VaultEventRecord[]>
  readVaultObjects(identityId: IdentityId): Promise<VaultObjectRecord[]>
  readProjection(identityId: IdentityId): Promise<unknown | undefined>
  writeProjection(identityId: IdentityId, projection: unknown, jmapState: unknown): Promise<void>
  readProjectionMeta(identityId: IdentityId): Promise<VaultProjectionMeta>
  writeProjectionMeta(value: VaultProjectionMeta): Promise<void>
  readEventsForTarget(identityId: IdentityId, targetId: string): Promise<VaultEventRecord[]>
}

/** The only writer of the derived mail projection for replicated records. */
export class VaultProjector {
  constructor(private readonly store: ProjectorStore, private readonly resolver: SegmentKeyResolver, private readonly verifier: VaultEventVerifier) {}

  async recomputeEmails(identityId: IdentityId, emailIds: Iterable<string>): Promise<LocalJmapProjectionV1> {
    const requested = [...new Set(emailIds)]
    const currentValue = await this.store.readProjection(identityId)
    if (currentValue === undefined || requested.length > 200) return this.rebuildAll(identityId)
    const current = localJmapSnapshotFromProjection(currentValue, identityId)
    const [objects, meta] = await Promise.all([this.store.readVaultObjects(identityId), this.store.readProjectionMeta(identityId)])
    const emails = new Map(current.emails.map(email => [email.id, email]))
    const tombstones = new Set(meta.tombstones); const pending = new Set(meta.pending)
    for (const emailId of new Set([...requested, ...pending])) {
      const events = await this.store.readEventsForTarget(identityId, emailId)
      const records = []
      let materializable = true
      for (const event of events) {
        try { records.push(...await decryptVaultMutationRecords(identityId, [event], objects, this.resolver, this.verifier)) }
        catch { materializable = false }
        if (event.kind === 'message.tombstone') tombstones.add(emailId)
      }
      if (!materializable) pending.add(emailId); else pending.delete(emailId)
      try {
        const folded = reduceLocalJmapProjection(identityId, { mailboxes: current.mailboxes, emails: [] }, records)
        const replacement = folded.emails.find(email => email.id === emailId)
        if (replacement && !tombstones.has(emailId)) emails.set(emailId, replacement); else emails.delete(emailId)
      } catch { pending.add(emailId) }
    }
    const recounted = reduceLocalJmapProjection(identityId, { mailboxes: current.mailboxes, emails: [...emails.values()] }, [])
    const projection: LocalJmapProjectionV1 = { version: 1, identityId, ...recounted }
    await this.store.writeProjection(identityId, projection, { state: projection.state })
    await this.store.writeProjectionMeta({ identityId, tombstones: [...tombstones], pending: [...pending] })
    return projection
  }

  async rebuildAll(identityId: IdentityId): Promise<LocalJmapProjectionV1> {
    const [events, objects, current, previousMeta] = await Promise.all([
      this.store.readVaultEvents(identityId), this.store.readVaultObjects(identityId), this.store.readProjection(identityId), this.store.readProjectionMeta(identityId),
    ])
    const records = []
    const pending = new Set<string>()
    for (const event of events) {
      try { records.push(...await decryptVaultMutationRecords(identityId, [event], objects, this.resolver, this.verifier)) }
      catch { for (const target of event.targetIds) pending.add(target) }
    }
    const base: Omit<LocalJmapSnapshot, 'state'> = current === undefined
      ? { mailboxes: [], emails: [] }
      : { mailboxes: localJmapSnapshotFromProjection(current, identityId).mailboxes, emails: [] }
    const snapshot = reduceLocalJmapProjection(identityId, base, records)
    const tombstones = new Set(previousMeta.tombstones)
    for (const event of events) if (event.kind === 'message.tombstone') for (const target of event.targetIds) tombstones.add(target)
    const emails = snapshot.emails.filter(email => !tombstones.has(email.id))
    const projection: LocalJmapProjectionV1 = { version: 1, identityId, ...snapshot, emails, state: projectionState(identityId, snapshot.mailboxes, emails) }
    await this.store.writeProjection(identityId, projection, { state: projection.state })
    await this.store.writeProjectionMeta({ identityId, tombstones: [...tombstones], pending: [...pending] })
    return projection
  }
}
