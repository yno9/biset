// Minimal did:web reader for public DIDComm service agents.  User identities
// remain did:webvh and use the signed-log resolver; this is deliberately only
// for stable service DIDs such as did:web:smtp.did.md.
import { decodeX25519Multikey } from './multikey.ts'

export interface DidWebDocument {
  id: string
  verificationMethod?: Array<{ id: string; type: string; controller: string; publicKeyMultibase: string }>
  keyAgreement?: string[]
  service?: Array<{ id: string; type: string; serviceEndpoint: unknown }>
}

export function didWebDocumentUrl(did: string): string {
  if (!did.startsWith('did:web:')) throw new TypeError('not a did:web identifier')
  const parts = did.slice('did:web:'.length).split(':')
  const host = parts.shift()
  if (!host || !/^[a-z0-9.-]+$/i.test(host)) throw new TypeError('invalid did:web host')
  if (parts.length === 0) return `https://${host}/.well-known/did.json`
  if (parts.some(part => !part || part === '.' || part === '..' || /[^A-Za-z0-9._~-]/.test(part))) throw new TypeError('invalid did:web path')
  return `https://${host}/${parts.join('/')}/did.json`
}

export async function resolveDidWeb(did: string, fetchImpl: typeof fetch = fetch): Promise<DidWebDocument | null> {
  const response = await fetchImpl(didWebDocumentUrl(did))
  if (response.status === 404) return null
  if (!response.ok) throw new Error(`did:web resolve failed: HTTP ${response.status}`)
  const value: unknown = await response.json()
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('did:web document is not an object')
  const doc = value as Partial<DidWebDocument>
  if (doc.id !== did || (doc.verificationMethod !== undefined && !Array.isArray(doc.verificationMethod))) throw new TypeError('did:web document is invalid')
  return doc as DidWebDocument
}

export function didWebDidCommRoute(doc: DidWebDocument): { kid: string; publicKey: Uint8Array; uri: string; routingKeys: string[] } {
  const keyIds = new Set(doc.keyAgreement ?? [])
  const key = doc.verificationMethod?.find(value => keyIds.has(value.id) || keyIds.has(value.id.startsWith('#') ? `${doc.id}${value.id}` : value.id))
  const service = [...(doc.service ?? [])].reverse().find(value => value.type === 'DIDCommMessaging')
  const endpoint = service?.serviceEndpoint
  if (!key || !endpoint || typeof endpoint !== 'object' || Array.isArray(endpoint)) throw new Error(`${doc.id} has no DIDComm route`)
  const value = endpoint as { uri?: unknown; routingKeys?: unknown }
  if (typeof value.uri !== 'string' || !value.uri || (value.routingKeys !== undefined && (!Array.isArray(value.routingKeys) || value.routingKeys.some(key => typeof key !== 'string')))) throw new Error(`${doc.id} has an invalid DIDComm route`)
  return { kid: key.id.startsWith('#') ? `${doc.id}${key.id}` : key.id, publicKey: decodeX25519Multikey(key.publicKeyMultibase), uri: value.uri, routingKeys: (value.routingKeys ?? []) as string[] }
}
