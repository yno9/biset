// Vault Sync: keeping this identity's devices' Vaults in step, over DIDComm
// only. Every message goes to this identity's OWN DID, encrypted to every
// device key its DID document lists (multiplexed encryption) and Forwarded
// once to the mediator, which copies it into each device's inbox -- so one
// send reaches every sibling, and a device removed from the DID document can
// neither read new sync traffic nor send any (its key no longer resolves).
// The sending device receives its own copy too and ignores it.
//
// A message carries a delivery pack (store/vault/delivery-pack.ts):
// events, their encrypted objects, and the SegmentKeys those objects need.
// DIDComm authcrypt is the only encryption the pack needs.
import { base64urlToBytes, bytesToBase64url } from '../../protocol/canonical.ts'
import { VAULT_SYNC_STATE_REQUEST, VAULT_SYNC_STATE_RESPONSE, VAULT_SYNC_UPDATE } from '../../protocol/didcomm/vault-sync-protocol.ts'
import type { DidCommSender } from '../../protocol/didcomm/mediator-transport.ts'
import type { IdentityId } from '../../protocol/ids.ts'
import { parseWebvhDid } from '../../protocol/webvh/identifier.ts'
import { resolveByDomain } from '../../protocol/webvh/resolver.ts'
import { keyAgreementRecipients } from '../../protocol/didcomm/webvh-route.ts'
import { decodeVaultDeliveryPack, encodeVaultDeliveryPack, type VaultDeliveryPackV1 } from '../store/vault/delivery-pack.ts'
import { verifyVaultEvent } from '../store/vault/events.ts'
import { verifyVaultObjectIntegrity } from '../store/vault/objects.ts'
import type { IncomingVaultRecords, IncomingVaultRecordsResult, VaultEventRecord, VaultObjectRecord, VaultSegmentKey, VaultSyncRecordReader } from '../store/vault/store.ts'
import { sendFrontDoorMessage } from './front-door-send.ts'

/** The most one Vault Sync message carries, from the mediator's disclosed
 * `max_receive_bytes` (Discover Features). A pack grows about 3.2x on the
 * wire (base64url, then the DIDComm JWE and Forward around it); one eighth
 * of the limit keeps well inside it -- 128 KB for the default 1 MB, which
 * is also what an undisclosed limit gets. */
export function vaultSyncChunkBytes(maxReceiveBytes?: number): number {
  if (maxReceiveBytes === undefined) return 128 * 1024
  return Math.max(16 * 1024, Math.floor(maxReceiveBytes / 8))
}

export type VaultSyncSummary = Record<string, { max: number; gaps: number[] }>
/** One chunk of records, as a base64url canonical delivery pack. */
interface VaultSyncPackBody { pack: string }
export type VaultSyncMessage =
  | { type: typeof VAULT_SYNC_UPDATE; body: VaultSyncPackBody }
  | { type: typeof VAULT_SYNC_STATE_REQUEST; body: { summary: VaultSyncSummary } }
  | { type: typeof VAULT_SYNC_STATE_RESPONSE; body: VaultSyncPackBody & { hasMore: boolean } }
/** Sends to every device of this identity, including the sender itself. */
export interface VaultSyncTransport { send(message: VaultSyncMessage): Promise<void> }
export interface VaultSyncStore extends VaultSyncRecordReader {
  commitIncomingRecords(input: IncomingVaultRecords): Promise<IncomingVaultRecordsResult>
  findDuplicateActorSequences(identityId: IdentityId): Promise<Array<{ actorDeviceId: string }>>
}
export interface VaultSyncApplyResult extends IncomingVaultRecordsResult { skippedEvents: number; skippedObjects: number; hasMore: boolean }

/** This identity's device keys, as its DID document lists them right now. */
export async function resolveOwnDeviceKids(identityDid: string): Promise<string[]> {
  const document = await resolveByDomain(parseWebvhDid(identityDid).domain, undefined, { cache: 'no-store' })
  if (!document || document.id !== identityDid) throw new Error('this identity\'s DID does not resolve')
  return keyAgreementRecipients(document).map(recipient => recipient.kid)
}

/** Vault Sync over this device's own front door: authcrypt from this
 * device's key to every device key of the identity's DID. */
export function walletVaultSyncTransport(own: DidCommSender, fetchImpl?: typeof fetch): VaultSyncTransport {
  return { async send(message) {
    let error: unknown
    for (let attempt = 0; attempt < 6; attempt++) {
      const sent = await sendFrontDoorMessage(own.did, message.type, message.body, { fromKid: own.xKid, x25519PrivateKey: own.xPriv, ...(fetchImpl ? { fetch: fetchImpl } : {}) })
      if (sent.ok) return
      error = new Error(sent.error)
      if (attempt < 5) await delay(250 * 2 ** attempt)
    }
    throw error
  } }
}

export class VaultSyncClient {
  constructor(
    private readonly identityId: IdentityId,
    private readonly ownKid: string,
    private readonly records: VaultSyncStore,
    private readonly transport: VaultSyncTransport,
    private readonly onApplied?: (result: VaultSyncApplyResult) => Promise<void>,
    private readonly chunkBytes: number = vaultSyncChunkBytes(),
  ) {}

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

  /** Asks every sibling for what this device is missing. */
  async requestState(): Promise<void> { await this.transport.send({ type: VAULT_SYNC_STATE_REQUEST, body: { summary: await this.summary() } }) }

  /** Hands newly committed events to every sibling, in one send per chunk. */
  async push(events: Iterable<{ id: string }>): Promise<void> { await this.send([...events].map(event => event.id), VAULT_SYNC_UPDATE, false) }

  /** Handles a Vault Sync message `senderKid` sent. Only this identity's own
   * devices may send one; this device's own copy is ignored. */
  async receive(message: VaultSyncMessage, senderKid: string): Promise<VaultSyncApplyResult | undefined> {
    if (!senderKid.startsWith(`${this.identityId}#`)) throw new TypeError('Vault Sync message is not from one of this identity\'s devices')
    if (senderKid === this.ownKid) return undefined
    if (message.type === VAULT_SYNC_STATE_REQUEST) {
      const missing = await this.missingEvents(message.body.summary)
      if (missing.events.length) await this.send(missing.events.map(event => event.id), VAULT_SYNC_STATE_RESPONSE, missing.hasMore)
      return undefined
    }
    const pack = decodeVaultDeliveryPack(base64urlToBytes(message.body.pack))
    const result = await this.applyIncoming(pack, message.type === VAULT_SYNC_STATE_RESPONSE && message.body.hasMore)
    await this.onApplied?.(result)
    // An update is only a hint: reconcile summaries so records it did not
    // carry (or that did not fit an earlier chunk) are pulled too.
    if (message.type === VAULT_SYNC_UPDATE || message.body.hasMore) await this.requestState()
    return result
  }

  private async send(ids: string[], type: typeof VAULT_SYNC_UPDATE | typeof VAULT_SYNC_STATE_RESPONSE, hasMore: boolean): Promise<void> {
    const pack = await this.packForEvents(new Set(ids)); if (!pack.events.length) return
    const chunks = splitPack(pack, this.chunkBytes)
    for (let index = 0; index < chunks.length; index++) {
      const body: VaultSyncPackBody = { pack: bytesToBase64url(encodeVaultDeliveryPack(chunks[index]!)) }
      const more = hasMore || index < chunks.length - 1
      await this.transport.send(type === VAULT_SYNC_UPDATE ? { type, body } : { type, body: { ...body, hasMore: more } })
    }
  }

  private async applyIncoming(pack: VaultDeliveryPackV1, hasMore: boolean): Promise<VaultSyncApplyResult> {
    if (pack.identityId !== this.identityId) throw new TypeError('Vault Sync records belong to another identity')
    const objects: VaultObjectRecord[] = []; const events: VaultEventRecord[] = []; let skippedObjects = 0; let skippedEvents = 0
    for (const object of pack.objects) { if (await verifyVaultObjectIntegrity(object)) objects.push(object); else skippedObjects++ }
    for (const event of pack.events) { if (verifyVaultEvent(event)) events.push(event); else skippedEvents++ }
    const committed = await this.records.commitIncomingRecords({ identityId: this.identityId, objects, events, segmentKeys: pack.segmentKeys })
    // An object-only continuation can unblock an event an earlier chunk
    // committed; surface those targets to the projector too.
    const objectIds = new Set(objects.map(object => object.objectId))
    const unblockedTargets = objectIds.size ? (await this.records.readVaultEvents(this.identityId)).filter(event => event.objectRefs.some(id => objectIds.has(id))).flatMap(event => event.targetIds) : []
    return { ...committed, targetIds: [...new Set([...committed.targetIds, ...unblockedTargets])], skippedObjects, skippedEvents, hasMore }
  }

  private async packForEvents(ids: Set<string>): Promise<VaultDeliveryPackV1> {
    const [allEvents, allObjects, allKeys] = await Promise.all([this.records.readVaultEvents(this.identityId), this.records.readVaultObjects(this.identityId), this.records.readSegmentKeys(this.identityId)])
    const events = allEvents.filter(event => ids.has(event.id)); const objectIds = new Set(events.flatMap(event => event.objectRefs)); const objects = allObjects.filter(object => objectIds.has(object.objectId)); const segments = new Set(objects.map(object => object.segmentId))
    return { version: 1, identityId: this.identityId, events, objects, segmentKeys: allKeys.filter(value => segments.has(value.segmentId)) }
  }

  private async missingEvents(summary: VaultSyncSummary): Promise<{ events: VaultEventRecord[]; hasMore: boolean }> {
    const missing = (await this.records.readVaultEvents(this.identityId)).filter(event => { const remote = summary[event.actorDeviceId]; return !remote || event.actorSeq > remote.max || remote.gaps.includes(event.actorSeq) }).sort((a, b) => b.createdAt.localeCompare(a.createdAt) || b.id.localeCompare(a.id)); const events: VaultEventRecord[] = []
    for (const event of missing) { if (encodeVaultDeliveryPack(await this.packForEvents(new Set([...events.map(value => value.id), event.id]))).length > this.chunkBytes) break; events.push(event) }
    return { events, hasMore: events.length < missing.length }
  }
}

function splitPack(pack: VaultDeliveryPackV1, chunkBytes: number): VaultDeliveryPackV1[] {
  const empty = (): VaultDeliveryPackV1 => ({ version: 1, identityId: pack.identityId, events: [], objects: [], segmentKeys: [] })
  const chunks: VaultDeliveryPackV1[] = []; let current = empty()
  const nonEmpty = (value: VaultDeliveryPackV1) => value.events.length || value.objects.length || value.segmentKeys.length
  const append = <K extends 'events' | 'objects' | 'segmentKeys'>(key: K, record: VaultDeliveryPackV1[K][number]): void => {
    const candidate = { ...current, [key]: [...current[key], record] } as VaultDeliveryPackV1
    if (encodeVaultDeliveryPack(candidate).length <= chunkBytes) { current = candidate; return }
    if (nonEmpty(current)) chunks.push(current)
    current = { ...empty(), [key]: [record] } as VaultDeliveryPackV1
    if (encodeVaultDeliveryPack(current).length > chunkBytes) throw new RangeError(`Vault Sync ${key} entry exceeds one chunk`)
  }
  // Keys first, so a chunk carrying an object never precedes the key it needs.
  for (const value of pack.segmentKeys) append('segmentKeys', value as VaultSegmentKey)
  for (const event of pack.events) append('events', event)
  for (const object of pack.objects) append('objects', object)
  if (nonEmpty(current)) chunks.push(current)
  return chunks
}

function delay(milliseconds: number): Promise<void> { return new Promise(resolve => setTimeout(resolve, milliseconds)) }
