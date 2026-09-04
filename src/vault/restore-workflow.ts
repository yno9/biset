import { restoreControlPullSigningBytes, restoreOfferSigningBytes, restoreRequestSigningBytes } from '../shared/protocol/signing.ts'
import type { DeliveryPullResult, RestoreCancelV1, RestoreControlPullV1, RestoreOfferV1, RestoreRequestV1 } from '../shared/protocol/vault.ts'
import type { DeviceId, IdentityId } from '../shared/protocol/ids.ts'

/**
 * The signed restore control plane, as a contract rather than a deployment.
 * Lived in `core-restore-control-transport.ts` beside a `CoreRestoreControlTransport`
 * that posted to core's `/v1/restore/*`; core is retired and that class was
 * never constructed anywhere, so only the contract survives -- moved here,
 * next to its one consumer. NOTE: there is no implementation of this in the
 * tree today, so nothing calls the functions below outside their tests.
 */
export interface RestoreControlTransport {
  request(input: RestoreRequestV1): Promise<void>
  pullRequests(input: RestoreControlPullV1): Promise<RestoreRequestV1[]>
  offer(input: RestoreOfferV1): Promise<void>
  pullOffers(input: RestoreControlPullV1): Promise<RestoreOfferV1[]>
  cancel(input: RestoreCancelV1): Promise<void>
}
import type { VaultRestoreOfferOutboxRecord, VaultRestoreOfferOutboxStore, VaultRestoreRequestStateRecord, VaultRestoreRequestStateStore } from './store.ts'

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

export type RestoreOfferSubmission =
  | { kind: 'submitted'; offer: RestoreOfferV1; reused: boolean }
  | { kind: 'pending'; offer: RestoreOfferV1; error: unknown; reused: boolean }

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

/** Peer-side signed discovery. Receiving a request does not authorise transfer. */
export async function pollRestoreRequests(
  transport: Pick<RestoreControlTransport, 'pullRequests'>,
  signer: RestoreControlSigner,
  identityId: IdentityId,
  now: () => Date = () => new Date(),
): Promise<RestoreRequestV1[]> {
  const pull = await signedRestorePoll(signer, identityId, 'requests', now())
  return transport.pullRequests(pull)
}

/** Requester-side signed offer polling; it never creates a data-transfer channel itself. */
export async function pollRestoreOffers(
  transport: Pick<RestoreControlTransport, 'pullOffers'>,
  signer: RestoreControlSigner,
  identityId: IdentityId,
  now: () => Date = () => new Date(),
): Promise<RestoreOfferV1[]> {
  const pull = await signedRestorePoll(signer, identityId, 'offers', now())
  return transport.pullOffers(pull)
}

/**
 * Called only after the peer UI has approved a restore. The offer itself is
 * durable and idempotent; it is not an approval to upload vault content to
 * the mediator.
 */
export async function submitRestoreOffer(
  store: VaultRestoreOfferOutboxStore,
  transport: Pick<RestoreControlTransport, 'offer'>,
  signer: RestoreControlSigner,
  request: RestoreRequestV1,
  manifestRoot: string,
  options: Omit<RestoreWorkflowOptions, 'knownManifestRoot' | 'newRequestId'> = {},
): Promise<RestoreOfferSubmission> {
  if (!manifestRoot || signer.deviceId === request.requesterDeviceId) throw new TypeError('restore offer needs a peer device and manifest root')
  const now = options.now ?? (() => new Date())
  const current = now()
  const existing = await store.readRestoreOfferOutbox(request.identityId, request.requestId, signer.deviceId)
  const active = existing !== undefined && Date.parse(existing.offer.expiresAt) > current.getTime()
  if (active && existing.status === 'submitted') return { kind: 'submitted', offer: existing.offer, reused: true }
  const state = active ? existing : await createOfferState(store, signer, request, manifestRoot, current, options)
  try {
    await transport.offer(state.offer)
    await store.markRestoreOfferSubmitted(request.identityId, request.requestId, signer.deviceId, now().toISOString())
    return { kind: 'submitted', offer: state.offer, reused: active }
  } catch (error) {
    await store.noteRestoreOfferAttempt(request.identityId, request.requestId, signer.deviceId, now().toISOString())
    return { kind: 'pending', offer: state.offer, error, reused: active }
  }
}

async function signedRestorePoll(
  signer: RestoreControlSigner,
  identityId: IdentityId,
  kind: RestoreControlPullV1['kind'],
  current: Date,
): Promise<RestoreControlPullV1> {
  const unsigned = { version: 1 as const, identityId, deviceId: signer.deviceId, kind, requestedAt: current.toISOString() }
  const signature = await signer.sign(restoreControlPullSigningBytes(unsigned))
  if (signature.length === 0) throw new TypeError('restore control poll signature is empty')
  return { ...unsigned, signature }
}

async function createOfferState(
  store: VaultRestoreOfferOutboxStore,
  signer: RestoreControlSigner,
  request: RestoreRequestV1,
  manifestRoot: string,
  current: Date,
  options: Omit<RestoreWorkflowOptions, 'knownManifestRoot' | 'newRequestId'>,
): Promise<VaultRestoreOfferOutboxRecord> {
  const ttlMs = options.ttlMs ?? 10 * 60 * 1000
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new TypeError('restore offer TTL must be a positive safe integer')
  const expiry = new Date(Math.min(current.getTime() + ttlMs, Date.parse(request.expiresAt)))
  if (Number.isNaN(expiry.getTime()) || expiry.getTime() <= current.getTime()) throw new TypeError('restore request is already expired')
  const unsigned = { version: 1 as const, requestId: request.requestId, identityId: request.identityId, requesterDeviceId: request.requesterDeviceId, responderDeviceId: signer.deviceId, manifestRoot, offeredAt: current.toISOString(), expiresAt: expiry.toISOString() }
  const signature = await signer.sign(restoreOfferSigningBytes(unsigned))
  if (signature.length === 0) throw new TypeError('restore offer signature is empty')
  const state: VaultRestoreOfferOutboxRecord = { identityId: request.identityId, requestId: request.requestId, responderDeviceId: signer.deviceId, offer: { ...unsigned, signature }, status: 'pending', attempts: 0, createdAt: current.toISOString() }
  await store.writeRestoreOfferOutbox(state)
  return state
}
