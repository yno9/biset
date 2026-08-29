// DIDComm message-type URIs and payload shapes for the Mail Mediator wire
// (PLAN_biset-mail-mediator.md section 4 "Protocol-native authorization
// workflow"). Shared by the server (src/mail-mediator/server.ts) and the
// client library that will live under src/didcomm/mail-mediator-*.ts, same
// split-by-concern reasoning as didcomm/mediator-protocol.ts.
//
// Namespaced under biset.md, not didcomm.org -- these are biset-specific
// message types, not part of the DIDComm org's own protocol suite. Mirrors
// didcomm/relationship.ts's own https://biset.md/relationship/1.0/... choice.
import { base64urlToBytes, bytesToBase64url } from '../protocol/canonical.ts'

export const ROUTE_BIND = 'https://biset.md/mail-mediator/1.0/route-bind'
export const ROUTE_BIND_RESULT = 'https://biset.md/mail-mediator/1.0/route-bind-result'
export const PICKUP_REQUEST = 'https://biset.md/mail-mediator/1.0/pickup-request'
export const PICKUP = 'https://biset.md/mail-mediator/1.0/pickup'
export const MESSAGES_RECEIVED = 'https://biset.md/mail-mediator/1.0/messages-received'
export const SUBMIT = 'https://biset.md/mail-mediator/1.0/submit'
export const SUBMIT_STATUS_REQUEST = 'https://biset.md/mail-mediator/1.0/submit-status-request'
export const SUBMIT_RESULT = 'https://biset.md/mail-mediator/1.0/submit-result'

/**
 * Client -> Mediator. Sent authcrypt'd from the address's public mail
 * operational kid (the front-door key, published in the address's
 * did:webvh routing document) -- the mediator verifies the authcrypt
 * sender kid against that document before accepting the bind.
 *
 * `relationshipKid`/`pickupPublicKey` name a NEW key the client just
 * generated for this relationship: after a successful bind, every
 * subsequent pickup/submit must authcrypt from `relationshipKid`, never
 * from the front-door kid again (PLAN section 4, steps 4-5).
 */
export interface RouteBindBody {
  address: string
  relationshipKid: string
  pickupPublicKey: Uint8Array
  routeGeneration: string
  expiresAt: string
}

export interface RouteBindWireBody {
  address: string
  relationshipKid: string
  pickupPublicKey: string
  routeGeneration: string
  expiresAt: string
}

export function routeBindBodyToWire(body: RouteBindBody): RouteBindWireBody {
  return { ...body, pickupPublicKey: bytesToBase64url(body.pickupPublicKey) }
}

export function routeBindBodyOf(body: unknown): RouteBindBody | null {
  const value = asRecord(body)
  if (!value) return null
  const { address, relationshipKid, pickupPublicKey, routeGeneration, expiresAt } = value
  if (typeof address !== 'string' || !address) return null
  if (typeof relationshipKid !== 'string' || !relationshipKid) return null
  if (typeof pickupPublicKey !== 'string') return null
  if (typeof routeGeneration !== 'string' || !routeGeneration) return null
  if (typeof expiresAt !== 'string' || !expiresAt) return null
  try {
    const key = base64urlToBytes(pickupPublicKey)
    if (key.length !== 32) return null
    return { address, relationshipKid, pickupPublicKey: key, routeGeneration, expiresAt }
  } catch {
    return null
  }
}

/** Mediator -> Client, reply to route-bind. */
export interface RouteBindResultBody {
  address: string
  routeGeneration: string
  accepted: boolean
  reason?: string
}

/** Client -> Mediator, authcrypt'd from `relationshipKid` only. */
export interface PickupRequestBody {
  address: string
  limit?: number
}

/** One still-encrypted spool entry as handed back on pickup. Never
 * decrypted by the mediator -- `encryptedBody`/`bodyHash` are opaque bytes
 * from an accepted SMTP DATA (PLAN section 6/14). */
export interface PickupItem {
  spoolId: string
  semanticIngressId: string
  mailFrom: string
  encryptedBody: Uint8Array
  bodyHash: Uint8Array
  createdAt: string
}

export interface PickupItemWire {
  spoolId: string
  semanticIngressId: string
  mailFrom: string
  encryptedBody: string
  bodyHash: string
  createdAt: string
}

export interface PickupBody {
  address: string
  items: PickupItem[]
}

export function pickupItemToWire(item: PickupItem): PickupItemWire {
  return {
    ...item,
    encryptedBody: bytesToBase64url(item.encryptedBody),
    bodyHash: bytesToBase64url(item.bodyHash),
  }
}

export function pickupItemOf(value: PickupItemWire): PickupItem {
  return {
    ...value,
    encryptedBody: base64urlToBytes(value.encryptedBody),
    bodyHash: base64urlToBytes(value.bodyHash),
  }
}

/** Client -> Mediator: confirms durable local commit of the named spool
 * ids so the mediator may drop them (PLAN section 7 -- pickup is
 * non-destructive until this ACK). */
export interface MessagesReceivedBody {
  address: string
  spoolIds: string[]
}

/** Client -> Mediator, authcrypt'd from `relationshipKid`. Outbound
 * submission of an already-locally-committed message (PLAN section 12). */
export interface SubmitBody {
  idempotencyKey: string
  mailFrom: string
  rcptTo: string[]
  rawRfc5322: Uint8Array
}

export interface SubmitWireBody {
  idempotencyKey: string
  mailFrom: string
  rcptTo: string[]
  rawRfc5322: string
}

export function submitBodyToWire(body: SubmitBody): SubmitWireBody {
  return { ...body, rawRfc5322: bytesToBase64url(body.rawRfc5322) }
}

export function submitBodyOf(body: unknown): SubmitBody | null {
  const value = asRecord(body)
  if (!value) return null
  const { idempotencyKey, mailFrom, rcptTo, rawRfc5322 } = value
  if (typeof idempotencyKey !== 'string' || !idempotencyKey) return null
  if (typeof mailFrom !== 'string' || !mailFrom) return null
  if (!Array.isArray(rcptTo) || rcptTo.length === 0 || !rcptTo.every(r => typeof r === 'string' && r)) return null
  if (typeof rawRfc5322 !== 'string') return null
  try {
    return { idempotencyKey, mailFrom, rcptTo, rawRfc5322: base64urlToBytes(rawRfc5322) }
  } catch {
    return null
  }
}

export type RecipientSubmitStatus = 'accepted' | 'temporary-failure' | 'permanent-failure'

/** Client -> Mediator, authcrypt'd from `relationshipKid`: "is idempotencyKey
 * done yet". SMTP dialogue (MX resolve, STARTTLS, multi-recipient) can run
 * well past one DIDComm request/response round trip, so `submit` itself
 * only ever answers `state: 'in-flight'` -- the client polls this to learn
 * the actual per-recipient outcome (PLAN section 12, revised to an
 * async model: submit accepts immediately, submit-status-request answers
 * once dialogue completes). */
export interface SubmitStatusRequestBody {
  idempotencyKey: string
}

/** Mediator -> Client. `results` is present only once `state` is
 * `'completed'` -- an in-flight submission has no results yet, and
 * `submit`'s own immediate reply is always `in-flight` even when the
 * SAME idempotencyKey was already completed on a prior attempt (that
 * case still needs its results, which come back on the following
 * submit-status-request). */
export interface SubmitResultBody {
  idempotencyKey: string
  state: 'in-flight' | 'completed'
  results?: Array<{ recipient: string; status: RecipientSubmitStatus; detail?: string }>
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  return value as Record<string, unknown>
}
