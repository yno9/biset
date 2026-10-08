import { base64urlToBytes, bytesToBase64url, canonicalBytes, canonicalJson, equalBytes, type CanonicalValue } from '../../../protocol/canonical.ts'
import type { VaultEventV1 } from '../../../protocol/vault.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../../../protocol/ids.ts'
import type { LocalJmapEmail, LocalJmapMailbox, LocalJmapSnapshot } from '../projection/gateway.ts'
import type { ActiveVaultSegment } from './active-segment.ts'
import type { VaultEventAuthor } from './events.ts'
import { buildMailMessageAdd, buildMailMessageEdit } from './mail-message.ts'
import { buildVaultMutation } from './mutations.ts'
import type { IncomingVaultRecordsResult } from './store.ts'
import type { IncomingVaultRecords } from './store.ts'
import { assertContactCard, contactSetIntent, contactTargetId, creatingPatch, DEFAULT_ADDRESS_BOOK, DIDCOMM_CONTACT_PROPERTY, pointerToken, type ContactPatch, type LocalJmapAddressBook, type LocalJmapContactCard } from '../projection/contacts.ts'

export const JMAP_STATE_RANK = 'https://biset.md/jmap/ns:stateRank' as const
/** JMAP keyword on every message a JMAP export file added to the Vault. */
export const IMPORTED_KEYWORD = '$imported'
interface JmapStateRank { keywords: string; mailboxIds: string; content: string }
type ExportedJmapEmail = LocalJmapEmail & { [JMAP_STATE_RANK]?: JmapStateRank }
export interface JmapExportV1 {
  version: 1; kind: 'biset.jmap-export'; identityId: string; exportedAt: string
  mailboxes: LocalJmapMailbox[]; emails: ExportedJmapEmail[]; blobs: Record<string, string>
  /** JMAP for Contacts (RFC 9610). Absent in a file with no contacts. */
  addressBooks?: LocalJmapAddressBook[]; contactCards?: LocalJmapContactCard[]
  /** Each card's state rank (the latest contact.set's eventStateRank), kept
   * beside the cards rather than in them so a card stays a plain JSContact Card. */
  contactCardStateRanks?: Record<string, string>
}
interface JmapImportSummary { added: number; skipped: number; excluded: number; missingBodies: number; contactsAdded: number; contactsUpdated: number; events: VaultEventV1[] }

export async function importJmapExport(file: JmapExportV1, input: {
  identityId: IdentityId; actorDeviceId: DeviceId; snapshot: LocalJmapSnapshot; events: VaultEventV1[]
  nextActorSeq(): Promise<number>; initialParents(): Promise<VaultEventId[]>; activeSegment(): Promise<ActiveVaultSegment>
  signer: VaultEventAuthor; commit(records: IncomingVaultRecords): Promise<IncomingVaultRecordsResult>
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
      // A file is plain JSON anyone could have edited, so a message that
      // enters the Vault from one says so: it is shown as imported, never as
      // something this account received.
      email.keywords = { ...email.keywords, [IMPORTED_KEYWORD]: true }
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
  // Contacts: a card newer in the file than in the Vault (or absent from
  // it, destroy included) is written as one patch dated at the file's rank.
  // Its DIDComm routing state is dropped: the file is plain JSON anyone
  // could have edited, and "this did:peer is Bob" must come only from a
  // verified DID Rotation (contacts.ts).
  let contactsAdded = 0; let contactsUpdated = 0
  const cards = new Map(input.snapshot.contactCards.map(card => [card.id, card]))
  for (const value of file.contactCards ?? []) {
    let card: LocalJmapContactCard
    try { card = assertContactCard(JSON.parse(JSON.stringify(value))) } catch { excluded++; continue }
    const { [DIDCOMM_CONTACT_PROPERTY]: _routing, ...plain } = card
    const rank = file.contactCardStateRanks?.[card.id] ?? `${file.exportedAt}|||`
    if (rank <= currentRank(input.events, contactTargetId(card.id), ['contact.set'])) { skipped++; continue }
    const existing = cards.get(card.id)
    const patch: ContactPatch = existing ? cardDifference(existing, plain as LocalJmapContactCard) : creatingPatch(plain as LocalJmapContactCard)
    if (Object.keys(patch).length === 0) { skipped++; continue }
    const record = await buildVaultMutation(contactSetIntent({ cardId: card.id, patch }), await buildContext(rankDate(rank, file.exportedAt)), input.signer)
    objects.push({ ...record.object, identityId: input.identityId }); events.push(record.event); parents = [record.event.id]
    if (existing) contactsUpdated++; else contactsAdded++
  }
  if (events.length) await input.commit({ identityId: input.identityId, objects, events: events.map(event => ({ ...event, identityId: input.identityId })), segmentKeys: [] })
  return { added, skipped, excluded, missingBodies, contactsAdded, contactsUpdated, events }
}

/** The patch that turns `current` into `wanted`, top-level property by
 * property, leaving the card's identity and its DIDComm routing state alone. */
function cardDifference(current: LocalJmapContactCard, wanted: LocalJmapContactCard): ContactPatch {
  const fixed = new Set(['id', 'uid', '@type', DIDCOMM_CONTACT_PROPERTY])
  const patch: ContactPatch = {}
  for (const [key, value] of Object.entries(wanted)) {
    if (!fixed.has(key) && canonicalJson(value) !== canonicalJson(current[key] ?? null)) patch[pointerToken(key)] = value as CanonicalValue
  }
  for (const key of Object.keys(current)) if (!fixed.has(key) && !(key in wanted)) patch[pointerToken(key)] = null
  return patch
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
  const contactCards = input.snapshot.contactCards.map(card => JSON.parse(JSON.stringify(card)) as LocalJmapContactCard)
  const contactCardStateRanks = Object.fromEntries(contactCards.flatMap(card => {
    const latest = input.events.filter(event => event.kind === 'contact.set' && event.targetIds.includes(contactTargetId(card.id))).sort(compareEvents).at(-1)
    return latest ? [[card.id, eventStateRank(latest)]] : []
  }))
  return {
    version: 1, kind: 'biset.jmap-export', identityId: input.identityId, exportedAt, mailboxes: input.snapshot.mailboxes.map(value => ({ ...value })), emails: output.sort((a, b) => a.id.localeCompare(b.id)), blobs,
    ...(contactCards.length ? { addressBooks: [JSON.parse(JSON.stringify(DEFAULT_ADDRESS_BOOK)) as LocalJmapAddressBook], contactCards, contactCardStateRanks } : {}),
  }
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
  // Contacts: the whole card with the higher rank wins.
  const cards = new Map<string, { card: LocalJmapContactCard; rank: string }>()
  for (const file of exports) {
    for (const card of file.contactCards ?? []) {
      const rank = file.contactCardStateRanks?.[card.id] ?? `${file.exportedAt}|||`
      const current = cards.get(card.id)
      if (!current || rank > current.rank) cards.set(card.id, { card: JSON.parse(JSON.stringify(card)) as LocalJmapContactCard, rank })
    }
  }
  const mergedCards = [...cards.values()].sort((a, b) => a.card.id.localeCompare(b.card.id))
  return {
    version: 1, kind: 'biset.jmap-export', identityId, exportedAt: exports.map(value => value.exportedAt).sort().at(-1)!, mailboxes: [...mailboxes.values()].sort((a, b) => a.id.localeCompare(b.id)), emails: [...emails.values()].sort((a, b) => a.id.localeCompare(b.id)), blobs,
    ...(mergedCards.length ? { addressBooks: [JSON.parse(JSON.stringify(DEFAULT_ADDRESS_BOOK)) as LocalJmapAddressBook], contactCards: mergedCards.map(value => value.card), contactCardStateRanks: Object.fromEntries(mergedCards.map(value => [value.card.id, value.rank])) } : {}),
  }
}

export function encodeJmapExport(value: JmapExportV1): Uint8Array { assertExport(value); return canonicalBytes(JSON.parse(JSON.stringify(value)) as never) }
export function decodeJmapExport(bytes: Uint8Array): JmapExportV1 {
  let value: unknown; try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) } catch { throw new TypeError('JMAP export is not JSON') }
  assertExport(value); if (!equalBytes(bytes, canonicalBytes(value as never))) throw new TypeError('JMAP export is not canonical')
  const file = value as JmapExportV1
  for (const encoded of Object.values(file.blobs)) base64urlToBytes(encoded)
  return file
}
function assertExport(value: unknown): asserts value is JmapExportV1 { const v = value as Partial<JmapExportV1>; if (!v || v.version !== 1 || v.kind !== 'biset.jmap-export' || !v.identityId || Number.isNaN(Date.parse(v.exportedAt ?? '')) || !Array.isArray(v.mailboxes) || !Array.isArray(v.emails) || !v.blobs || typeof v.blobs !== 'object'
  || (v.contactCards !== undefined && !Array.isArray(v.contactCards)) || (v.addressBooks !== undefined && !Array.isArray(v.addressBooks))
  || (v.contactCardStateRanks !== undefined && (typeof v.contactCardStateRanks !== 'object' || v.contactCardStateRanks === null || Object.values(v.contactCardStateRanks).some(rank => typeof rank !== 'string')))) throw new TypeError('JMAP export is invalid') }
function ranks(email: ExportedJmapEmail, fallback: string): JmapStateRank { return email[JMAP_STATE_RANK] ?? { keywords: fallback, mailboxIds: fallback, content: fallback } }
function currentRank(events: VaultEventV1[], emailId: string, kinds: string[]): string { const event = events.filter(value => value.targetIds.includes(emailId) && kinds.includes(value.kind)).sort(compareEvents).at(-1); return event ? eventStateRank(event) : '' }
function rankDate(rank: string, fallback: string): string { const value = rank.split('|', 1)[0]!; return Number.isNaN(Date.parse(value)) ? fallback : value }
function sameMap(a: Record<string, true>, b: Record<string, true>): boolean { return JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort()) }
function max(a: string, b: string): string { return a > b ? a : b }
function compareEvents(a: VaultEventV1, b: VaultEventV1): number { return a.createdAt.localeCompare(b.createdAt) || a.actorDeviceId.localeCompare(b.actorDeviceId) || a.actorSeq - b.actorSeq || a.id.localeCompare(b.id) }
function copyEmail<T extends LocalJmapEmail>(email: T): T { return { ...email, mailboxIds: { ...email.mailboxIds }, keywords: { ...email.keywords }, from: email.from?.map(value => ({ ...value })), to: email.to?.map(value => ({ ...value })), reactions: email.reactions && { ...email.reactions } } }
