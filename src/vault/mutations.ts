import { canonicalBytes } from '../protocol/canonical.ts'
import type { DeviceId, IdentityId, SegmentId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventKind, VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import type { VaultMutationIntent } from '../local-jmap/mutations.ts'
import { createVaultEvent, type VaultEventSigner } from './events.ts'
import { encryptVaultObject } from './objects.ts'

export interface VaultMutationBuildContext {
  identityId: IdentityId
  actorDeviceId: DeviceId
  actorSeq: number
  parents: VaultEventId[]
  segmentId: SegmentId
  segmentKey: Uint8Array
  createdAt: string
}

export interface VaultMutationRecord {
  object: VaultObjectV1
  event: VaultEventV1
}

/**
 * Converts a validated UI intent into the two immutable vault records that a
 * single durable transaction must append together. The reducer can recover
 * kind/targets from the signed event and the exact mutation value from the
 * encrypted canonical object.
 */
export async function buildVaultMutation(
  intent: VaultMutationIntent,
  context: VaultMutationBuildContext,
  signer: VaultEventSigner,
): Promise<VaultMutationRecord> {
  assertContext(context, signer)
  if (!intent.kind || intent.targetIds.length === 0 || intent.targetIds.some(id => !id)) throw new TypeError('vault mutation intent is invalid')
  const plaintext = canonicalBytes({
    version: 1,
    kind: intent.kind,
    targetIds: [...intent.targetIds],
    payload: intent.payload,
  })
  const object = await encryptVaultObject(context.segmentKey, {
    segmentId: context.segmentId,
    plaintext,
    aad: mutationObjectAad(context.identityId, context.segmentId, intent.kind, intent.targetIds),
  })
  const event = await createVaultEvent({
    identityId: context.identityId,
    actorDeviceId: context.actorDeviceId,
    actorSeq: context.actorSeq,
    kind: intent.kind,
    targetIds: [...intent.targetIds],
    objectRefs: [object.objectId],
    parents: [...context.parents],
    createdAt: context.createdAt,
  }, signer)
  return { object, event }
}

export function mutationObjectAad(
  identityId: IdentityId,
  segmentId: SegmentId,
  kind: VaultEventKind,
  targetIds: string[],
): Uint8Array {
  return canonicalBytes({
    label: 'biset/vault/mutation-object/aad/v1',
    identityId,
    segmentId,
    kind,
    targetIds: [...targetIds],
  })
}

function assertContext(context: VaultMutationBuildContext, signer: VaultEventSigner): void {
  if (!context.identityId || !context.actorDeviceId || !context.segmentId) throw new TypeError('vault mutation context has empty required fields')
  if (context.actorDeviceId !== signer.deviceId) throw new TypeError('vault mutation signer does not match actor device')
  if (!Number.isSafeInteger(context.actorSeq) || context.actorSeq < 0) throw new TypeError('vault mutation actor sequence is invalid')
  if (context.segmentKey.length !== 32) throw new TypeError('vault mutation SegmentKey must be 32 bytes')
  if (Number.isNaN(Date.parse(context.createdAt))) throw new TypeError('vault mutation createdAt must be an ISO date string')
}
