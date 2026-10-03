import { canonicalBytes, domainHash } from '../../../protocol/canonical.ts'
import type { DeviceId, IdentityId, VaultEventId, VaultObjectId } from '../../../protocol/ids.ts'
import type { VaultEventKind, VaultEventV1 } from '../../../protocol/vault.ts'

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

/** Who writes a Vault event: this device. Nothing signs it -- a Vault event
 * reaches another device only inside DIDComm authcrypt from a key the
 * identity's DID document lists (Vault Sync), which is the authentication. */
export interface VaultEventAuthor {
  readonly deviceId: DeviceId
}

function vaultEventBytes(draft: VaultEventDraft): Uint8Array {
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

export async function createVaultEvent(draft: VaultEventDraft, author: VaultEventAuthor): Promise<VaultEventV1> {
  if (draft.actorDeviceId !== author.deviceId) throw new TypeError('event author does not match actor device')
  return {
    version: 1,
    id: eventId(vaultEventBytes(draft)),
    ...draft,
    targetIds: [...draft.targetIds],
    objectRefs: [...draft.objectRefs],
    parents: [...draft.parents],
  }
}

/** True when the event is well-formed and its id is the hash of its content
 * -- the integrity check a received event gets. */
export function verifyVaultEvent(event: VaultEventV1): boolean {
  const { id, version, ...draft } = event
  try { return version === 1 && id === eventId(vaultEventBytes(draft)) } catch { return false }
}

function eventId(content: Uint8Array): VaultEventId {
  return domainHash('biset/vault/event-id/v2', content)
}

function assertDraft(draft: VaultEventDraft): void {
  if (!draft.identityId || !draft.actorDeviceId || !draft.kind || !draft.createdAt) throw new TypeError('event draft has empty required fields')
  if (!Number.isSafeInteger(draft.actorSeq) || draft.actorSeq < 0) throw new TypeError('actorSeq must be a non-negative safe integer')
  if (Number.isNaN(Date.parse(draft.createdAt))) throw new TypeError('createdAt must be an ISO date string')
  for (const values of [draft.targetIds, draft.objectRefs, draft.parents]) {
    if (values.some((value) => value.length === 0)) throw new TypeError('event references must be non-empty')
  }
}
