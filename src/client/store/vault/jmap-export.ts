import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes } from '../../../protocol/canonical.ts'
import type { VaultEventV1 } from '../../../protocol/vault.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../../../protocol/ids.ts'
import type { LocalJmapEmail, LocalJmapMailbox, LocalJmapSnapshot } from '../projection/gateway.ts'
import type { ActiveVaultSegment } from './active-segment.ts'
import type { VaultEventSigner } from './events.ts'
import { buildMailMessageAdd, buildMailMessageEdit } from './mail-message.ts'
import { buildVaultMutation } from './mutations.ts'
import type { IncomingVaultRecordsResult } from './store.ts'
import type { IncomingVaultRecords } from './store.ts'

export const JMAP_STATE_RANK = 'https://biset.md/jmap/ns:stateRank' as const
interface JmapStateRank { keywords: string; mailboxIds: string; content: string }
type ExportedJmapEmail = LocalJmapEmail & { [JMAP_STATE_RANK]?: JmapStateRank }
export interface JmapExportV1 {
  version: 1; kind: 'biset.jmap-export'; identityId: string; exportedAt: string
  mailboxes: LocalJmapMailbox[]; emails: ExportedJmapEmail[]; blobs: Record<string, string>
}
export interface JmapExportEnvelopeV1 { version: 1; kind: 'biset.jmap-export-encrypted'; identityId: string; generation: string; exportedAt: string; nonce: string; ciphertext: string }
interface JmapImportSummary { added: number; skipped: number; excluded: number; missingBodies: number; events: VaultEventV1[] }

export async function importJmapExport(file: JmapExportV1, input: {
  identityId: IdentityId; actorDeviceId: DeviceId; snapshot: LocalJmapSnapshot; events: VaultEventV1[]
  nextActorSeq(): Promise<number>; initialParents(): Promise<VaultEventId[]>; activeSegment(): Promise<ActiveVaultSegment>
  signer: VaultEventSigner; commit(records: IncomingVaultRecords): Promise<IncomingVaultRecordsResult>
}): Promise<JmapImportSummary> {
  assertExport(file)
  if (file.identityId !== input.identityId) throw new TypeError('JMAP export identity does not match the current identity')
  const segment = await input.activeSegment(); let parents = await input.initialParents()
  const objects: IncomingVaultRecords['objects'] = []; const events: VaultEventV1[] = []
  const current = new Map(input.snapshot.emails.map(email => [email.id, email])); let added = 0; let skipped = 0; let excluded = 0; let missingBodies = 0
  const buildContext = async (createdAt: string) => ({ identityId: input.identityId, actorDeviceId: input.actorDeviceId, actorSeq: await input.nextActorSeq(), parents, segmentId: segment.segmentId, segmentKey: segment.segmentKey, createdAt })
  for (const exported of file.emails) {
    const existing = current.get(exported.id); const rank = ranks(exported, file.exportedAt); const body = exported.blobId ? file.blobs[exported.blobId] : undefined
    if (!existing) {
      if (!body) { missingBodies++; excluded++; continue }
      const { [JMAP_STATE_RANK]: _rank, blobId: _blobId, ...email } = exported
      const record = await buildMailMessageAdd({ email, rawRfc5322: base64urlToBytes(body) }, await buildContext(rankDate(rank.content, exported.receivedAt)), input.signer)
      objects.push({ ...record.metadataObject, identityId: input.identityId }, { ...record.rawRfc5322Object, identityId: input.identityId }); events.push(record.event); parents = [record.event.id]; current.set(exported.id, exported); added++; continue
    }
    if (existing.threadId !== exported.threadId || existing.receivedAt !== exported.receivedAt) { excluded++; continue }
    let changed = false
    if (!sameMap(existing.keywords, exported.keywords) && rank.keywords > currentRank(input.events, exported.id, ['message.add', 'keyword.set'])) {
      const record = await buildVaultMutation({ kind: 'keyword.set', targetIds: [exported.id], payload: { emailId: exported.id, keywords: exported.keywords } }, await buildContext(rankDate(rank.keywords, file.exportedAt)), input.signer)
      objects.push({ ...record.object, identityId: input.identityId }); events.push(record.event); parents = [record.event.id]; changed = true
    }
    if (!sameMap(existing.mailboxIds, exported.mailboxIds) && rank.mailboxIds > currentRank(input.events, exported.id, ['message.add', 'mailbox.set'])) {
      const record = await buildVaultMutation({ kind: 'mailbox.set', targetIds: [exported.id], payload: { emailId: exported.id, mailboxIds: exported.mailboxIds } }, await buildContext(rankDate(rank.mailboxIds, file.exportedAt)), input.signer)
      objects.push({ ...record.object, identityId: input.identityId }); events.push(record.event); parents = [record.event.id]; changed = true
    }
    if ((existing.blobId !== exported.blobId || existing.subject !== exported.subject) && rank.content > currentRank(input.events, exported.id, ['message.add', 'message.edit'])) {
      if (!body) missingBodies++
      else { const record = await buildMailMessageEdit({ emailId: exported.id, rawRfc5322: base64urlToBytes(body), subject: exported.subject }, await buildContext(rankDate(rank.content, file.exportedAt)), input.signer); objects.push({ ...record.metadataObject, identityId: input.identityId }, { ...record.rawRfc5322Object, identityId: input.identityId }); events.push(record.event); parents = [record.event.id]; changed = true }
    }
    if (!changed) skipped++
  }
  if (events.length) await input.commit({ identityId: input.identityId, objects, events: events.map(event => ({ ...event, identityId: input.identityId })), keyWraps: segment.keyWraps })
  return { added, skipped, excluded, missingBodies, events }
}

export async function encryptJmapExport(file: JmapExportV1, generation: string, key: Uint8Array): Promise<JmapExportEnvelopeV1> {
  if (key.length !== 32) throw new TypeError('JMAP export key is invalid')
  const nonce = crypto.getRandomValues(new Uint8Array(12)); const aad = canonicalBytes({ label: 'biset/jmap-export/aad/v1', identityId: file.identityId, generation, exportedAt: file.exportedAt })
  const cryptoKey = await crypto.subtle.importKey('raw', buffer(key), 'AES-GCM', false, ['encrypt'])
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: buffer(nonce), additionalData: buffer(aad) }, cryptoKey, buffer(encodeJmapExport(file))))
  return { version: 1, kind: 'biset.jmap-export-encrypted', identityId: file.identityId, generation, exportedAt: file.exportedAt, nonce: bytesToBase64url(nonce), ciphertext: bytesToBase64url(ciphertext) }
}
export async function decryptJmapExport(envelope: JmapExportEnvelopeV1, key: Uint8Array): Promise<JmapExportV1> {
  if (key.length !== 32 || envelope.kind !== 'biset.jmap-export-encrypted') throw new TypeError('JMAP export envelope is invalid')
  const aad = canonicalBytes({ label: 'biset/jmap-export/aad/v1', identityId: envelope.identityId, generation: envelope.generation, exportedAt: envelope.exportedAt })
  try {
    const cryptoKey = await crypto.subtle.importKey('raw', buffer(key), 'AES-GCM', false, ['decrypt'])
    const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buffer(base64urlToBytes(envelope.nonce)), additionalData: buffer(aad) }, cryptoKey, buffer(base64urlToBytes(envelope.ciphertext))))
    const file = decodeJmapExport(plaintext); if (file.identityId !== envelope.identityId || file.exportedAt !== envelope.exportedAt) throw new TypeError('JMAP export envelope metadata does not match')
    return file
  } catch (error) { if (error instanceof TypeError) throw error; throw new TypeError('JMAP export cannot be decrypted') }
}

export function eventStateRank(event: Pick<VaultEventV1, 'createdAt' | 'actorDeviceId' | 'actorSeq' | 'id'>): string {
  if (!Number.isSafeInteger(event.actorSeq) || event.actorSeq < 0 || event.actorSeq > 99_999_999_999_999_999_999) throw new TypeError('state rank actor sequence is invalid')
  return `${event.createdAt}|${event.actorDeviceId}|${String(event.actorSeq).padStart(20, '0')}|${event.id}`
}

export async function createJmapExport(input: {
  identityId: string; snapshot: LocalJmapSnapshot; events: VaultEventV1[]; download(blobId: string): Promise<Uint8Array>
  exportedAt?: string; since?: string; until?: string
}): Promise<JmapExportV1> {
  const exportedAt = input.exportedAt ?? new Date().toISOString()
  const emails = input.snapshot.emails.filter(email => (!input.since || email.receivedAt >= input.since) && (!input.until || email.receivedAt <= input.until))
  const blobs: Record<string, string> = {}
  const output: ExportedJmapEmail[] = []
  for (const email of emails) {
    if (email.blobId) blobs[email.blobId] = bytesToBase64url(await input.download(email.blobId))
    const related = input.events.filter(event => event.targetIds.includes(email.id))
    const latest = (kinds: string[]) => related.filter(event => kinds.includes(event.kind)).sort(compareEvents).at(-1)
    const add = latest(['message.add'])
    const fallback = `${exportedAt}|||`
    output.push({ ...copyEmail(email), [JMAP_STATE_RANK]: {
      keywords: latest(['message.add', 'keyword.set']) ? eventStateRank(latest(['message.add', 'keyword.set'])!) : fallback,
      mailboxIds: latest(['message.add', 'mailbox.set']) ? eventStateRank(latest(['message.add', 'mailbox.set'])!) : fallback,
      content: latest(['message.add', 'message.edit']) ? eventStateRank(latest(['message.add', 'message.edit'])!) : (add ? eventStateRank(add) : fallback),
    } })
  }
  return { version: 1, kind: 'biset.jmap-export', identityId: input.identityId, exportedAt, mailboxes: input.snapshot.mailboxes.map(value => ({ ...value })), emails: output.sort((a, b) => a.id.localeCompare(b.id)), blobs }
}

/** Join-semilattice merge used before import: union immutable mail plus LWW
 * per independently mutable field group. */
export function mergeJmapExports(exports: JmapExportV1[]): JmapExportV1 {
  if (!exports.length) throw new TypeError('no JMAP exports to merge')
  const identityId = exports[0]!.identityId
  if (exports.some(value => value.identityId !== identityId)) throw new TypeError('JMAP export identity does not match')
  const emails = new Map<string, ExportedJmapEmail>(); const blobs: Record<string, string> = {}; const mailboxes = new Map<string, LocalJmapMailbox>()
  for (const file of [...exports].sort((a, b) => a.exportedAt.localeCompare(b.exportedAt))) {
    for (const mailbox of file.mailboxes) mailboxes.set(mailbox.id, { ...mailbox })
    Object.assign(blobs, file.blobs)
    for (const candidate of file.emails) {
      const incomingRank = ranks(candidate, file.exportedAt); const current = emails.get(candidate.id)
      if (!current) { emails.set(candidate.id, { ...copyEmail(candidate), [JMAP_STATE_RANK]: incomingRank }); continue }
      const currentRank = ranks(current, file.exportedAt); const merged = copyEmail(current)
      if (incomingRank.keywords > currentRank.keywords) merged.keywords = { ...candidate.keywords }
      if (incomingRank.mailboxIds > currentRank.mailboxIds) merged.mailboxIds = { ...candidate.mailboxIds }
      if (incomingRank.content > currentRank.content) { merged.blobId = candidate.blobId; merged.subject = candidate.subject }
      merged[JMAP_STATE_RANK] = { keywords: max(currentRank.keywords, incomingRank.keywords), mailboxIds: max(currentRank.mailboxIds, incomingRank.mailboxIds), content: max(currentRank.content, incomingRank.content) }
      emails.set(candidate.id, merged)
    }
  }
  return { version: 1, kind: 'biset.jmap-export', identityId, exportedAt: exports.map(value => value.exportedAt).sort().at(-1)!, mailboxes: [...mailboxes.values()].sort((a, b) => a.id.localeCompare(b.id)), emails: [...emails.values()].sort((a, b) => a.id.localeCompare(b.id)), blobs }
}

export function encodeJmapExport(value: JmapExportV1): Uint8Array { assertExport(value); return canonicalBytes(JSON.parse(JSON.stringify(value)) as never) }
export function decodeJmapExport(bytes: Uint8Array): JmapExportV1 {
  let value: unknown; try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) } catch { throw new TypeError('JMAP export is not JSON') }
  assertExport(value); if (!equalBytes(bytes, canonicalBytes(value as never))) throw new TypeError('JMAP export is not canonical')
  const file = value as JmapExportV1
  for (const encoded of Object.values(file.blobs)) base64urlToBytes(encoded)
  return file
}
function assertExport(value: unknown): asserts value is JmapExportV1 { const v = value as Partial<JmapExportV1>; if (!v || v.version !== 1 || v.kind !== 'biset.jmap-export' || !v.identityId || Number.isNaN(Date.parse(v.exportedAt ?? '')) || !Array.isArray(v.mailboxes) || !Array.isArray(v.emails) || !v.blobs || typeof v.blobs !== 'object') throw new TypeError('JMAP export is invalid') }
function ranks(email: ExportedJmapEmail, fallback: string): JmapStateRank { return email[JMAP_STATE_RANK] ?? { keywords: fallback, mailboxIds: fallback, content: fallback } }
function currentRank(events: VaultEventV1[], emailId: string, kinds: string[]): string { const event = events.filter(value => value.targetIds.includes(emailId) && kinds.includes(value.kind)).sort(compareEvents).at(-1); return event ? eventStateRank(event) : '' }
function rankDate(rank: string, fallback: string): string { const value = rank.split('|', 1)[0]!; return Number.isNaN(Date.parse(value)) ? fallback : value }
function sameMap(a: Record<string, true>, b: Record<string, true>): boolean { return JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort()) }
function max(a: string, b: string): string { return a > b ? a : b }
function compareEvents(a: VaultEventV1, b: VaultEventV1): number { return a.createdAt.localeCompare(b.createdAt) || a.actorDeviceId.localeCompare(b.actorDeviceId) || a.actorSeq - b.actorSeq || a.id.localeCompare(b.id) }
function copyEmail<T extends LocalJmapEmail>(email: T): T { return { ...email, mailboxIds: { ...email.mailboxIds }, keywords: { ...email.keywords }, from: email.from?.map(value => ({ ...value })), to: email.to?.map(value => ({ ...value })), reactions: email.reactions && { ...email.reactions } } }
function buffer(bytes: Uint8Array): ArrayBuffer { const copy = bytes.slice(); return copy.buffer }
