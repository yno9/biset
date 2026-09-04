// The single assembly step every writer of shared vault state goes through:
// signed events + encrypted objects -> identity-scoped records, the JMAP
// projection, and the one shared-delivery outbox entry that carries the
// change to this identity's other devices.
//
// Six call sites (mail ingress, DIDComm ingress, DIDComm group chat, the two
// local-JMAP write paths, and the credential sink) used to hand-copy this
// tail, so a fix made in one left the other five wrong. What genuinely
// differs between them is only what is expressed as input here: which
// records fold into the projection (or none, for a credential write that
// must leave the read model untouched), how many objects there are, and
// where `createdAt` comes from.
//
// Deliberately NOT part of this step: the active-segment check and the
// record building itself. Those run before it, on inputs this function never
// sees, and the segment check is not uniform across call sites today (see
// local-jmap/vault-mutation-sink.ts) -- folding it in here would be a
// behaviour change, not a refactor.
import { sha256Bytes } from '../shared/protocol/canonical.ts'
import type { IdentityId } from '../shared/protocol/ids.ts'
import type { SegmentKeyWrapV1, VaultEventV1, VaultObjectV1 } from '../shared/protocol/vault.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import { reduceLocalJmapProjection, type DecryptedMutationRecord } from '../local-jmap/reducer.ts'
import { encodeVaultDeliveryPack } from './delivery-pack.ts'
import type { VaultDeliveryOutboxRecord, VaultEventRecord, VaultObjectRecord } from './store.ts'

export interface VaultCommitInput {
  identityId: IdentityId
  /** Not yet identity-scoped; this function stamps them. */
  objects: VaultObjectV1[]
  events: VaultEventV1[]
  /** The active segment's current-epoch wraps, as they go into the pack. */
  keyWraps: SegmentKeyWrapV1[]
  /** The delivery-outbox entry's timestamp. Its source is call-site specific
   * (an injected clock, the inbound message's own receivedAt, or the
   * credential record's createdAt), so it is never derived here. */
  createdAt: string
  /** The read model this commit starts from. */
  snapshot: LocalJmapSnapshot
  /**
   * Decrypted mutation records to fold into the projection. Omit to carry
   * the snapshot through verbatim -- INCLUDING its `state` -- which is what
   * a private-credential write wants: it changes shared vault state without
   * changing anything the user-visible JMAP read model reports.
   */
  reduce?: DecryptedMutationRecord[]
}

export interface VaultCommitParts {
  objects: VaultObjectRecord[]
  events: VaultEventRecord[]
  projection: LocalJmapProjectionV1
  jmapState: { state: string }
  deliveryOutbox: VaultDeliveryOutboxRecord
}

/**
 * Assembles one committable vault change. Pure: it performs no I/O and
 * mutates none of its inputs, so callers stay free to decide what to do with
 * the result (commit it, or return it for someone else to commit).
 */
export function buildVaultCommit(input: VaultCommitInput): VaultCommitParts {
  const { identityId } = input
  const objects: VaultObjectRecord[] = input.objects.map(object => ({ ...object, identityId }))
  const events: VaultEventRecord[] = input.events.map(event => ({ ...event, identityId }))
  const projection: LocalJmapProjectionV1 = input.reduce
    ? { version: 1, identityId, ...reduceLocalJmapProjection(identityId, { mailboxes: input.snapshot.mailboxes, emails: input.snapshot.emails }, input.reduce) }
    : { version: 1, identityId, state: input.snapshot.state, mailboxes: input.snapshot.mailboxes, emails: input.snapshot.emails }
  const payload = encodeVaultDeliveryPack({ version: 1, identityId, objects, events, keyWraps: input.keyWraps })
  return {
    objects,
    events,
    projection,
    jmapState: { state: projection.state },
    deliveryOutbox: {
      identityId,
      // The last event of the batch: every single-event caller's own
      // `event.id`, and the local-JMAP multi-intent path's chain head.
      entryId: events.at(-1)!.id,
      payload,
      payloadHash: sha256Bytes(payload),
      createdAt: input.createdAt,
      attempts: 0,
    },
  }
}
