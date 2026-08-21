import { canonicalBytes, domainHash } from '../protocol/canonical.ts'
import type { DeviceId, IdentityId, VaultEventId, VaultObjectId } from '../protocol/ids.ts'
import type { VaultEventKind, VaultEventV1 } from '../protocol/vault.ts'

export interface VaultEventDraft {
  identityId: IdentityId
  actorDeviceId: DeviceId
  actorSeq: number
  kind: VaultEventKind
  targetIds: string[]
  objectRefs: VaultObjectId[]
  parents: VaultEventId[]
  createdAt: string
}

export interface VaultEventSigner {
  readonly deviceId: DeviceId
  sign(bytes: Uint8Array): Promise<Uint8Array>
  verify(deviceId: DeviceId, bytes: Uint8Array, signature: Uint8Array): Promise<boolean>
}

export interface VaultEventVerifier {
  verify(deviceId: DeviceId, bytes: Uint8Array, signature: Uint8Array): Promise<boolean>
}

export function vaultEventSigningBytes(draft: VaultEventDraft): Uint8Array {
  assertDraft(draft)
  return canonicalBytes({
    version: 1,
    identityId: draft.identityId,
    actorDeviceId: draft.actorDeviceId,
    actorSeq: draft.actorSeq,
    kind: draft.kind,
    targetIds: [...draft.targetIds],
    objectRefs: [...draft.objectRefs],
    parents: [...draft.parents],
    createdAt: draft.createdAt,
  })
}

export async function createVaultEvent(draft: VaultEventDraft, signer: VaultEventSigner): Promise<VaultEventV1> {
  if (draft.actorDeviceId !== signer.deviceId) throw new TypeError('event signer does not match actor device')
  const unsigned = vaultEventSigningBytes(draft)
  const signature = await signer.sign(unsigned)
  if (signature.length === 0) throw new TypeError('event signature must not be empty')
  return {
    version: 1,
    id: eventId(unsigned, signature),
    ...draft,
    targetIds: [...draft.targetIds],
    objectRefs: [...draft.objectRefs],
    parents: [...draft.parents],
    signature: signature.slice(),
  }
}

export async function verifyVaultEvent(event: VaultEventV1, signer: VaultEventVerifier): Promise<boolean> {
  const { id, signature, version, ...draft } = event
  if (version !== 1 || id !== eventId(vaultEventSigningBytes(draft), signature)) return false
  return signer.verify(event.actorDeviceId, vaultEventSigningBytes(draft), signature)
}

function eventId(unsigned: Uint8Array, signature: Uint8Array): VaultEventId {
  const body = new Uint8Array(4 + unsigned.length + signature.length)
  new DataView(body.buffer).setUint32(0, unsigned.length)
  body.set(unsigned, 4)
  body.set(signature, 4 + unsigned.length)
  return domainHash('biset/vault/event-id/v1', body)
}

function assertDraft(draft: VaultEventDraft): void {
  if (!draft.identityId || !draft.actorDeviceId || !draft.kind || !draft.createdAt) throw new TypeError('event draft has empty required fields')
  if (!Number.isSafeInteger(draft.actorSeq) || draft.actorSeq < 0) throw new TypeError('actorSeq must be a non-negative safe integer')
  if (Number.isNaN(Date.parse(draft.createdAt))) throw new TypeError('createdAt must be an ISO date string')
  for (const values of [draft.targetIds, draft.objectRefs, draft.parents]) {
    if (values.some((value) => value.length === 0)) throw new TypeError('event references must be non-empty')
  }
}
