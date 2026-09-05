import { base64urlToBytes, bytesToBase64url } from '../protocol/canonical.ts'
import { decodePeerDid2, publicKeyOf } from './peer.ts'

export const RELATIONSHIP_INIT = 'https://biset.md/relationship/1.0/init'
export const RELATIONSHIP_ACCEPT = 'https://biset.md/relationship/1.0/accept'

export interface RelationshipBody {
  /** X25519 kid of the sender's private, service-bearing did:peer identity. */
  relationshipKid: string
  /** X25519 public key repeated explicitly for simple cross-implementation parsing. */
  publicKey: Uint8Array
}

export interface RelationshipWireBody {
  relationshipKid: string
  publicKey: string
}

export interface RelationshipMediatorService {
  url: string
  routingKid: string
}

export function isRelationshipMessage(msg: { type?: string }): boolean {
  return msg.type === RELATIONSHIP_INIT || msg.type === RELATIONSHIP_ACCEPT
}

export function relationshipBodyToWire(body: RelationshipBody): RelationshipWireBody {
  assertRelationshipBody(body)
  return { relationshipKid: body.relationshipKid, publicKey: bytesToBase64url(body.publicKey) }
}

export function relationshipBodyOf(msg: { body?: unknown }): RelationshipBody | null {
  const body = msg.body
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return null
  const relationshipKid = (body as Record<string, unknown>).relationshipKid
  const publicKey = (body as Record<string, unknown>).publicKey
  if (typeof relationshipKid !== 'string' || typeof publicKey !== 'string') return null
  try {
    const result = { relationshipKid, publicKey: base64urlToBytes(publicKey) }
    assertRelationshipBody(result)
    return result
  } catch {
    return null
  }
}

/** Resolves the private mediator route carried inside a relationship DID. */
export function relationshipMediatorService(relationshipKid: string): RelationshipMediatorService {
  const did = relationshipKid.split('#', 1)[0]!
  if (!did.startsWith('did:peer:2.')) throw new TypeError('relationship kid is not did:peer:2')
  const doc = decodePeerDid2(did)
  if (!doc.keyAgreement.includes(relationshipKid)) throw new TypeError('relationship kid is not a keyAgreement method')
  if (doc.service.length !== 1) throw new TypeError('relationship DID must carry exactly one mediator service')
  const endpoint = doc.service[0]!.serviceEndpoint
  if (!endpoint.uri || endpoint.routing_keys.length !== 1 || !endpoint.routing_keys[0]) {
    throw new TypeError('relationship mediator service is invalid')
  }
  return { url: endpoint.uri, routingKid: endpoint.routing_keys[0] }
}

function assertRelationshipBody(body: RelationshipBody): void {
  if (body.publicKey.length !== 32) throw new TypeError('relationship public key must be 32 bytes')
  relationshipMediatorService(body.relationshipKid)
  const did = body.relationshipKid.split('#', 1)[0]!
  const embedded = publicKeyOf(decodePeerDid2(did), body.relationshipKid)
  if (embedded.length !== body.publicKey.length || embedded.some((value, index) => value !== body.publicKey[index])) {
    throw new TypeError('relationship kid does not match its public key')
  }
}
