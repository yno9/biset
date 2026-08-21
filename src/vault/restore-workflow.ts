import { restoreRequestSigningBytes } from '../protocol/signing.ts'
import type { DeliveryPullResult, RestoreRequestV1 } from '../protocol/vault.ts'
import type { DeviceId, IdentityId } from '../protocol/ids.ts'
import type { RestoreControlTransport } from './core-restore-control-transport.ts'
import type { VaultRestoreRequestStateRecord, VaultRestoreRequestStateStore } from './store.ts'

export interface RestoreControlSigner {
  readonly deviceId: DeviceId
  sign(bytes: Uint8Array): Promise<Uint8Array>
}

export interface RestoreWorkflowOptions {
  /** Default is 15 minutes: this is a control TTL, never a history retention TTL. */
  ttlMs?: number
  now?: () => Date
  newRequestId?: () => string
  knownManifestRoot?: string
}

export type RestoreRequestSubmission =
  | { kind: 'submitted'; request: RestoreRequestV1; reused: boolean }
  | { kind: 'pending'; request: RestoreRequestV1; error: unknown; reused: boolean }

/**
 * Makes a delivery gap durable before contacting the mediator. If a network
 * response is lost, the same client-generated request ID is retried, making
 * submission idempotent without asking the core to retain vault content.
 */
export async function requestRestoreForGap(
  store: VaultRestoreRequestStateStore,
  transport: Pick<RestoreControlTransport, 'request'>,
  signer: RestoreControlSigner,
  identityId: IdentityId,
  gap: Extract<DeliveryPullResult, { kind: 'restoreRequired' }>,
  options: RestoreWorkflowOptions = {},
): Promise<RestoreRequestSubmission> {
  if (!identityId || signer.deviceId.length === 0) throw new TypeError('restore identity and signer device are required')
  const now = options.now ?? (() => new Date())
  const current = now()
  const existing = await store.readRestoreRequestState(identityId, signer.deviceId)
  const active = existing !== undefined && Date.parse(existing.request.expiresAt) > current.getTime()
  if (active && existing.status === 'submitted') return { kind: 'submitted', request: existing.request, reused: true }
  const state = active ? existing : await createState(store, signer, identityId, gap, current, options)
  try {
    await transport.request(state.request)
    await store.markRestoreRequestSubmitted(identityId, signer.deviceId, now().toISOString())
    return { kind: 'submitted', request: state.request, reused: active }
  } catch (error) {
    await store.noteRestoreRequestAttempt(identityId, signer.deviceId, now().toISOString())
    return { kind: 'pending', request: state.request, error, reused: active }
  }
}

async function createState(
  store: VaultRestoreRequestStateStore,
  signer: RestoreControlSigner,
  identityId: IdentityId,
  gap: Extract<DeliveryPullResult, { kind: 'restoreRequired' }>,
  current: Date,
  options: RestoreWorkflowOptions,
): Promise<VaultRestoreRequestStateRecord> {
  const ttlMs = options.ttlMs ?? 15 * 60 * 1000
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new TypeError('restore control TTL must be a positive safe integer')
  const requestId = (options.newRequestId ?? (() => crypto.randomUUID()))()
  if (!requestId) throw new TypeError('restore request ID is required')
  const unsigned = {
    version: 1 as const,
    requestId,
    identityId,
    requesterDeviceId: signer.deviceId,
    reason: gap.reason,
    ...(options.knownManifestRoot === undefined ? {} : { knownManifestRoot: options.knownManifestRoot }),
    requestedAt: current.toISOString(),
    expiresAt: new Date(current.getTime() + ttlMs).toISOString(),
  }
  const signature = await signer.sign(restoreRequestSigningBytes(unsigned))
  if (signature.length === 0) throw new TypeError('restore request signature is empty')
  const state: VaultRestoreRequestStateRecord = { identityId, deviceId: signer.deviceId, request: { ...unsigned, signature }, gap: { ...gap }, status: 'pending', attempts: 0, createdAt: current.toISOString() }
  await store.writeRestoreRequestState(state)
  return state
}
