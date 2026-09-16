import { base64urlToBytes, bytesToBase64url, canonicalBytes } from '../../protocol/canonical.ts'
import { VAULT_SYNC_STATE_REQUEST, VAULT_SYNC_STATE_RESPONSE, VAULT_SYNC_UPDATE } from '../../protocol/didcomm/vault-sync-protocol.ts'
import { deviceKidFragment } from '../../protocol/didcomm/devicekid.ts'
import { decodeX25519Multikey } from '../../protocol/didcomm/multikey.ts'
import type { DidCommSender } from '../../protocol/didcomm/mediator-transport.ts'
import type { IdentityId } from '../../protocol/ids.ts'
import type { SegmentKeyWrapV1 } from '../../protocol/vault.ts'
import { parseWebvhDid } from '../../protocol/webvh/identifier.ts'
import { resolveByDomain } from '../../protocol/webvh/resolver.ts'
import { decodeVaultDeliveryPack, encodeVaultDeliveryPack, type VaultDeliveryPackV1 } from '../store/vault/delivery-pack.ts'
import { verifyVaultEvent, type VaultEventVerifier } from '../store/vault/events.ts'
import { verifyVaultObjectIntegrity } from '../store/vault/objects.ts'
import type { IncomingVaultRecords, IncomingVaultRecordsResult, VaultEventRecord, VaultObjectRecord, VaultSyncRecordReader } from '../store/vault/store.ts'
import { VAULT_SYNC_CHUNK_BYTES } from '../store/vault/vault-sync-chunks.ts'
import { sendMediatedDidCommMessage } from './send-message.ts'

const AAD_LABEL = 'biset/vault-sync/v1'
export interface EncryptedVaultUpdate { version: 1; generation: string; nonce: string; ciphertext: string }
export type VaultSyncSummary = Record<string, { max: number; gaps: number[] }>
export type VaultSyncMessage =
  | { type: typeof VAULT_SYNC_UPDATE; body: EncryptedVaultUpdate }
  | { type: typeof VAULT_SYNC_STATE_REQUEST; body: { summary: VaultSyncSummary } }
  | { type: typeof VAULT_SYNC_STATE_RESPONSE; body: EncryptedVaultUpdate & { hasMore: boolean } }
export interface VaultSyncTransport { send(recipientKid: string, message: VaultSyncMessage): Promise<void> }
export interface VaultSyncMediatedRecipient { kid: string; publicKey: Uint8Array; mediatorUrl: string; routingKid: string }
export interface VaultSyncKeys { current(): Promise<{ generation: string; key: Uint8Array }>; forGeneration(generation: string): Promise<Uint8Array | undefined> }
export interface VaultSyncSiblingDevice { kid: string; publicKey: Uint8Array }
export interface VaultSyncStore extends VaultSyncRecordReader {
  commitIncomingRecords(input: IncomingVaultRecords): Promise<IncomingVaultRecordsResult>
  findDuplicateActorSequences(identityId: IdentityId): Promise<Array<{ actorDeviceId: string }>>
}
export interface VaultSyncApplyResult extends IncomingVaultRecordsResult { skippedEvents: number; skippedObjects: number; skippedKeyWraps: number; hasMore: boolean }

export async function resolveVaultSyncSiblingRoutes(identityDid: string, ownKid?: string): Promise<VaultSyncMediatedRecipient[]> {
  const document = await resolveByDomain(parseWebvhDid(identityDid).domain, undefined, { cache: 'no-store' })
  if (!document || document.id !== identityDid) throw new Error('Vault Sync identity DID does not resolve')
  const service = document.service?.find(candidate => candidate.id === '#didcomm' || candidate.id === `${identityDid}#didcomm`)
  if (!service || !service.serviceEndpoint || typeof service.serviceEndpoint !== 'object' || Array.isArray(service.serviceEndpoint)) throw new Error('Vault Sync DIDComm service is unavailable')
  const endpoint = service.serviceEndpoint as { uri?: unknown; routingKeys?: unknown }
  if (typeof endpoint.uri !== 'string' || !Array.isArray(endpoint.routingKeys) || endpoint.routingKeys.length !== 1 || typeof endpoint.routingKeys[0] !== 'string') throw new Error('Vault Sync DIDComm mediator route is invalid')
  const routingKeys = endpoint.routingKeys as string[]
  return vaultSyncSiblingDevices(document, ownKid).map(device => ({ ...device, mediatorUrl: endpoint.uri as string, routingKid: routingKeys[0]! }))
}
export function mediatedVaultSyncTransport(own: DidCommSender, recipient: (kid: string) => Promise<VaultSyncMediatedRecipient>, fetchImpl: typeof fetch = fetch): VaultSyncTransport {
  return { async send(kid, message) {
    const route = await recipient(kid)
    let error: unknown
    for (let attempt = 0; attempt < 6; attempt++) {
      try { await sendMediatedDidCommMessage(message.type, message.body, own, route, fetchImpl); return }
      catch (caught) { error = caught; if (attempt < 5) await delay(250 * 2 ** attempt) }
    }
    throw error
  } }
}
export function walletVaultSyncTransport(own: DidCommSender, fetchImpl: typeof fetch = fetch): VaultSyncTransport {
  return mediatedVaultSyncTransport(own, async kid => {
    const route = (await resolveVaultSyncSiblingRoutes(own.did, own.xKid)).find(value => value.kid === kid)
    if (!route) throw new Error(`Vault Sync sibling ${kid} is no longer published in the DID Document`)
    return route
  }, fetchImpl)
}
export function vaultSyncSiblingDevices(document: { id: string; verificationMethod?: Array<{ id: string; publicKeyMultibase: string }> }, ownKid?: string): VaultSyncSiblingDevice[] {
  const result: VaultSyncSiblingDevice[] = []
  for (const method of document.verificationMethod ?? []) {
    let publicKey: Uint8Array; try { publicKey = decodeX25519Multikey(method.publicKeyMultibase) } catch { continue }
    const fragment = method.id.startsWith('#') ? method.id : method.id.slice(document.id.length)
    if (fragment !== deviceKidFragment(publicKey)) continue
    const kid = `${document.id}${fragment}`; if (kid !== ownKid) result.push({ kid, publicKey })
  }
  return result
}

export class VaultSyncClient {
  constructor(private readonly identityId: IdentityId, private readonly records: VaultSyncStore, private readonly verifier: VaultEventVerifier, private readonly keys: VaultSyncKeys, private readonly transport: VaultSyncTransport, private readonly onApplied?: (result: VaultSyncApplyResult) => Promise<void>) {}
  async summary(): Promise<VaultSyncSummary> {
    const events = await this.records.readVaultEvents(this.identityId)
    const duplicates = new Set((await this.records.findDuplicateActorSequences(this.identityId)).map(value => value.actorDeviceId))
    const actors = new Map<string, number[]>()
    for (const event of events) actors.set(event.actorDeviceId, [...(actors.get(event.actorDeviceId) ?? []), event.actorSeq])
    const result: VaultSyncSummary = {}
    for (const [actor, sequences] of actors) {
      const values = [...new Set(sequences)].sort((a, b) => a - b); const max = duplicates.has(actor) ? 0 : (values.at(-1) ?? 0); const present = new Set(values)
      result[actor] = { max, gaps: max ? Array.from({ length: max }, (_, index) => index + 1).filter(seq => !present.has(seq)) : [] }
    }
    return result
  }
  async requestState(kid: string): Promise<void> { await this.transport.send(kid, { type: VAULT_SYNC_STATE_REQUEST, body: { summary: await this.summary() } }) }
  async pushToSiblings(kids: Iterable<string>, events: Iterable<{ id: string }>): Promise<void> { const ids = [...events].map(event => event.id); for (const kid of kids) await this.push(kid, ids, VAULT_SYNC_UPDATE, false) }
  async receive(message: VaultSyncMessage, replyToKid?: string): Promise<VaultSyncApplyResult | undefined> {
    if (message.type === VAULT_SYNC_STATE_REQUEST) {
      if (!replyToKid) throw new TypeError('Vault Sync state request has no authenticated sender')
      const missing = await this.missingEvents(message.body.summary); if (missing.events.length) await this.push(replyToKid, missing.events.map(event => event.id), VAULT_SYNC_STATE_RESPONSE, missing.hasMore); return
    }
    const key = await this.keys.forGeneration(message.body.generation)
    if (!key) throw new TypeError('Vault Sync update generation is unavailable; reconnect your did.md Wallet')
    let pack: VaultDeliveryPackV1; try { pack = decodeVaultDeliveryPack(await decryptUpdate(message.body, { generation: message.body.generation, key })) } finally { key.fill(0) }
    const result = await this.applyIncoming(pack, message.type === VAULT_SYNC_STATE_RESPONSE && message.body.hasMore); await this.onApplied?.(result)
    // PUSH is only a hint: immediately reconcile summaries so records that
    // predate this notification (or did not fit an earlier chunk) are pulled.
    if (replyToKid && (message.type === VAULT_SYNC_UPDATE || message.body.hasMore)) await this.requestState(replyToKid)
    return result
  }
  private async push(kid: string, ids: string[], type: typeof VAULT_SYNC_UPDATE | typeof VAULT_SYNC_STATE_RESPONSE, hasMore: boolean): Promise<void> {
    const pack = await this.packForEvents(new Set(ids)); if (!pack.events.length) return
    const chunks = splitPack(pack)
    const current = await this.keys.current(); try {
      for (let index = 0; index < chunks.length; index++) {
        const encrypted = await encryptUpdate(encodeVaultDeliveryPack(chunks[index]!), current)
        const more = hasMore || index < chunks.length - 1
        await this.transport.send(kid, type === VAULT_SYNC_UPDATE ? { type, body: encrypted } : { type, body: { ...encrypted, hasMore: more } })
      }
    } finally { current.key.fill(0) }
  }
  private async applyIncoming(pack: VaultDeliveryPackV1, hasMore: boolean): Promise<VaultSyncApplyResult> {
    if (pack.identityId !== this.identityId) throw new TypeError('Vault Sync records belong to another identity')
    const objects: VaultObjectRecord[] = []; const events: VaultEventRecord[] = []; const keyWraps: SegmentKeyWrapV1[] = []; let skippedObjects = 0; let skippedEvents = 0; let skippedKeyWraps = 0
    for (const object of pack.objects) { if (await verifyVaultObjectIntegrity(object)) objects.push(object); else skippedObjects++ }
    for (const event of pack.events) { if (await verifyVaultEvent(event, this.verifier)) events.push(event); else skippedEvents++ }
    for (const wrap of pack.keyWraps) { if (wrap.identityId === this.identityId && wrap.segmentId && wrap.recipientEpoch && wrap.wrappedSegmentKey.length) keyWraps.push(wrap); else skippedKeyWraps++ }
    const committed = await this.records.commitIncomingRecords({ identityId: this.identityId, objects, events, keyWraps })
    // An object-only continuation can unblock an event that was deliberately
    // committed by an earlier chunk. Surface those targets to the projector
    // even though this chunk itself contains no event rows.
    const objectIds = new Set(objects.map(object => object.objectId))
    const unblockedTargets = objectIds.size ? (await this.records.readVaultEvents(this.identityId)).filter(event => event.objectRefs.some(id => objectIds.has(id))).flatMap(event => event.targetIds) : []
    return { ...committed, targetIds: [...new Set([...committed.targetIds, ...unblockedTargets])], skippedObjects, skippedEvents, skippedKeyWraps, hasMore }
  }
  private async packForEvents(ids: Set<string>): Promise<VaultDeliveryPackV1> {
    const [allEvents, allObjects, allWraps] = await Promise.all([this.records.readVaultEvents(this.identityId), this.records.readVaultObjects(this.identityId), this.records.readSegmentKeyWraps(this.identityId)])
    const events = allEvents.filter(event => ids.has(event.id)); const objectIds = new Set(events.flatMap(event => event.objectRefs)); const objects = allObjects.filter(object => objectIds.has(object.objectId)); const segments = new Set(objects.map(object => object.segmentId))
    return { version: 1, identityId: this.identityId, events, objects, keyWraps: allWraps.filter(wrap => segments.has(wrap.segmentId)) }
  }
  private async missingEvents(summary: VaultSyncSummary): Promise<{ events: VaultEventRecord[]; hasMore: boolean }> {
    const missing = (await this.records.readVaultEvents(this.identityId)).filter(event => { const remote = summary[event.actorDeviceId]; return !remote || event.actorSeq > remote.max || remote.gaps.includes(event.actorSeq) }).sort((a, b) => b.createdAt.localeCompare(a.createdAt) || b.id.localeCompare(a.id)); const events: VaultEventRecord[] = []
    for (const event of missing) { if (encodeVaultDeliveryPack(await this.packForEvents(new Set([...events.map(value => value.id), event.id]))).length > VAULT_SYNC_CHUNK_BYTES) break; events.push(event) }
    return { events, hasMore: events.length < missing.length }
  }
}

function splitPack(pack: VaultDeliveryPackV1): VaultDeliveryPackV1[] {
  const empty = (): VaultDeliveryPackV1 => ({ version: 1, identityId: pack.identityId, events: [], objects: [], keyWraps: [] })
  const chunks: VaultDeliveryPackV1[] = []; let current = empty()
  const append = <K extends 'events' | 'objects' | 'keyWraps'>(key: K, record: VaultDeliveryPackV1[K][number]): void => {
    const candidate = { ...current, [key]: [...current[key], record] } as VaultDeliveryPackV1
    if (encodeVaultDeliveryPack(candidate).length <= VAULT_SYNC_CHUNK_BYTES) { current = candidate; return }
    if (current.events.length || current.objects.length || current.keyWraps.length) chunks.push(current)
    current = { ...empty(), [key]: [record] } as VaultDeliveryPackV1
    if (encodeVaultDeliveryPack(current).length > VAULT_SYNC_CHUNK_BYTES) throw new RangeError(`Vault Sync ${key.slice(0, -1)} exceeds one chunk`)
  }
  for (const event of pack.events) append('events', event)
  for (const object of pack.objects) append('objects', object)
  for (const wrap of pack.keyWraps) append('keyWraps', wrap)
  if (current.events.length || current.objects.length || current.keyWraps.length) chunks.push(current)
  return chunks
}

export async function encryptUpdate(plaintext: Uint8Array, input: { generation: string; key: Uint8Array }): Promise<EncryptedVaultUpdate> {
  assertKey(input.key); if (!/^(0|[1-9][0-9]{0,19})$/.test(input.generation) || plaintext.length > VAULT_SYNC_CHUNK_BYTES) throw new TypeError('Vault Sync update is invalid')
  const nonce = crypto.getRandomValues(new Uint8Array(12)); const aad = canonicalBytes({ label: AAD_LABEL, generation: input.generation }); const key = await crypto.subtle.importKey('raw', copy(input.key), 'AES-GCM', false, ['encrypt']); const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: copy(nonce), additionalData: copy(aad) }, key, copy(plaintext)))
  return { version: 1, generation: input.generation, nonce: bytesToBase64url(nonce), ciphertext: bytesToBase64url(ciphertext) }
}
export async function decryptUpdate(input: EncryptedVaultUpdate, current: { generation: string; key: Uint8Array }): Promise<Uint8Array> {
  if (!input || input.version !== 1 || input.generation !== current.generation) throw new TypeError('Vault Sync update generation is unavailable; reconnect your did.md Wallet')
  const nonce = base64urlToBytes(input.nonce); const ciphertext = base64urlToBytes(input.ciphertext); const aad = canonicalBytes({ label: AAD_LABEL, generation: input.generation })
  try { const key = await crypto.subtle.importKey('raw', copy(current.key), 'AES-GCM', false, ['decrypt']); return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: copy(nonce), additionalData: copy(aad) }, key, copy(ciphertext))) } catch { throw new Error('Vault Sync ciphertext could not be decrypted') }
}
function assertKey(key: Uint8Array): void { if (key.length !== 32) throw new TypeError('Vault Content Key is invalid') }
function copy(bytes: Uint8Array): ArrayBuffer { const result = new Uint8Array(bytes.length); result.set(bytes); return result.buffer }
function delay(milliseconds: number): Promise<void> { return new Promise(resolve => setTimeout(resolve, milliseconds)) }
