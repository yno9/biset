// The single assembly step every writer of shared vault state goes through:
// events + encrypted objects -> identity-scoped records and the JMAP
// projection. Getting the change to this identity's other devices is Vault
// Sync's job (didcomm/vault-sync.ts), which reads the committed records.
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
import type { IdentityId } from '../../../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../../../protocol/vault.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../projection/gateway.ts'
import { reduceLocalJmapProjection, type DecryptedMutationRecord } from '../projection/reducer.ts'
import type { VaultEventRecord, VaultObjectRecord } from './store.ts'

export interface VaultCommitInput {
  identityId: IdentityId
  /** Not yet identity-scoped; this function stamps them. */
  objects: VaultObjectV1[]
  events: VaultEventV1[]
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
  return { objects, events, projection, jmapState: { state: projection.state } }
}
