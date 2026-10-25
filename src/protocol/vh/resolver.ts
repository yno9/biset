// did:vh resolution: the whole log is verified, every entry, in order (VH-Log: Read (Resolve); didvh-spec:
// Resolution Algorithm and Resolver Validation Checklist). The resolver is handed a log; it never looks for one.
//
// Stricter than the specification where it leaves room, like dito's packages/vh (the two are checked against the same
// vectors, test/fixtures/did-vh-vectors.json): an invalid entry anywhere fails the whole log, every proof of an entry
// must verify, unknown members of an entry or of `parameters` are refused, and a log that configures witnesses is
// refused (`featureNotSupported`) rather than accepted without the approvals it needs.
import { entryVersionNumber, isVersionTimeNotTooFarInFuture, verifyEntryHash, type LogEntry } from './log.ts'
import { verifyScid } from './scid.ts'
import { verifyProof } from './proof.ts'
import { decodeMultikey } from './multikey.ts'
import { multikeyHashBase58 } from './hash.ts'
import type { DidDocument } from './document.ts'
import { VH_METHOD, isScid, parseVhDid } from './identifier.ts'

type VhErrorCode = 'invalidDid' | 'invalidOptions' | 'invalidLog' | 'notFound' | 'featureNotSupported'

class VhResolutionError extends Error {
  readonly code: VhErrorCode
  constructor(code: VhErrorCode, message: string) {
    super(message)
    this.name = 'VhResolutionError'
    this.code = code
  }
}

const invalid = (message: string) => new VhResolutionError('invalidLog', message)

/** The parameters in force after an entry. */
interface ActiveParameters {
  method: string
  updateKeys: string[]
  nextKeyHashes: string[]
  witness: Record<string, unknown>
  watchers: string[]
  deactivated: boolean
  ttl: number
}

const ENTRY_MEMBERS = ['versionId', 'versionTime', 'parameters', 'state', 'proof']
const PARAMETER_MEMBERS = ['method', 'scid', 'updateKeys', 'nextKeyHashes', 'witness', 'watchers', 'deactivated', 'ttl']

function stringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || !value.every(item => typeof item === 'string' && item)) throw invalid(`parameters.${name} must be an array of strings.`)
  return value as string[]
}

function isEd25519Multikey(value: string): boolean {
  try { decodeMultikey(value); return true } catch { return false }
}

/** Folds an entry's `parameters` into the active ones (VH-Log: Parameters; didvh-spec: Parameters). */
function applyParameters(previous: ActiveParameters | undefined, parameters: unknown, first: boolean): ActiveParameters {
  if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) throw invalid('parameters must be an object.')
  const given = parameters as Record<string, unknown>
  for (const name of Object.keys(given)) {
    if (name === 'portable') throw invalid('parameters.portable is not a did:vh parameter.')
    if (name === 'logVersion') throw invalid('parameters.logVersion must not be used in a did:vh log; use method.')
    if (!PARAMETER_MEMBERS.includes(name)) throw invalid(`parameters.${name} is not a did:vh parameter.`)
    if (given[name] === null) throw invalid(`parameters.${name} must not be null.`)
  }
  if (first) {
    if (!isScid(given.scid)) throw invalid('The first entry must carry parameters.scid.')
    if (given.method === undefined) throw invalid('The first entry must carry parameters.method.')
    if (given.updateKeys === undefined) throw invalid('The first entry must carry parameters.updateKeys.')
  } else if (given.scid !== undefined) throw invalid('parameters.scid may only appear in the first entry.')

  const method = (given.method ?? previous?.method) as string | undefined
  if (method !== VH_METHOD) throw invalid(`Unsupported method ${JSON.stringify(method)}.`)

  const updateKeys = given.updateKeys === undefined ? previous!.updateKeys : stringArray(given.updateKeys, 'updateKeys')
  for (const key of updateKeys) if (!isEd25519Multikey(key)) throw invalid('parameters.updateKeys must hold Ed25519 multikeys.')
  if (first && !updateKeys.length) throw invalid('The first entry must authorise at least one key.')

  const nextKeyHashes = given.nextKeyHashes === undefined ? previous?.nextKeyHashes ?? [] : stringArray(given.nextKeyHashes, 'nextKeyHashes')

  let witness = previous?.witness ?? {}
  if (given.witness !== undefined) {
    if (typeof given.witness !== 'object' || Array.isArray(given.witness)) throw invalid('parameters.witness must be an object.')
    witness = given.witness as Record<string, unknown>
  }
  if (Object.keys(witness).length) throw new VhResolutionError('featureNotSupported', 'This log uses witnesses, which this resolver does not support yet.')

  let watchers = previous?.watchers ?? []
  if (given.watchers !== undefined) {
    watchers = stringArray(given.watchers, 'watchers')
    for (const url of watchers) {
      let parsed: URL
      try { parsed = new URL(url) } catch { throw invalid('parameters.watchers must hold URLs.') }
      if (parsed.protocol !== 'https:') throw invalid('parameters.watchers must hold https URLs.')
    }
  }

  let deactivated = previous?.deactivated ?? false
  if (given.deactivated !== undefined) {
    if (typeof given.deactivated !== 'boolean') throw invalid('parameters.deactivated must be a boolean.')
    deactivated = given.deactivated
  }

  let ttl = previous?.ttl ?? 3600
  if (given.ttl !== undefined) {
    if (!Number.isInteger(given.ttl) || (given.ttl as number) < 0 || (given.ttl as number) > 2 ** 31) throw invalid('parameters.ttl must be an integer from 0 to 2^31.')
    ttl = given.ttl as number
  }
  return { method, updateKeys, nextKeyHashes, witness, watchers, deactivated, ttl }
}

export interface VhResolveOptions {
  /** At most one of these selects a version; none selects the latest. */
  versionId?: string
  versionTime?: string
  versionNumber?: number
  /** The current time in ms, for the future-time check. */
  now?: number
}

export interface VhResolution {
  did: string
  /** The document of the selected version; null when the DID is deactivated and its latest version was asked for. */
  doc: DidDocument | null
  versionId: string
  versionNumber: number
  /** The newest version of the whole log, whichever was selected. */
  latestVersionId: string
  latestVersionNumber: number
  deactivated: boolean
}

const VERSION_ID = /^([1-9]\d*)-([1-9A-HJ-NP-Za-km-z]+)$/
const VERSION_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|\+00:00)$/

/** Verifies a whole did:vh log for `did` and returns the selected version (didvh-spec: Resolution Algorithm). */
export function resolveVhEntries(did: string, log: readonly LogEntry[], options: VhResolveOptions = {}): VhResolution {
  let scid: string
  try { scid = parseVhDid(did).scid } catch { throw new VhResolutionError('invalidDid', 'Not a did:vh DID.') }

  const selectors = [options.versionId, options.versionTime, options.versionNumber].filter(value => value !== undefined)
  if (selectors.length > 1) throw new VhResolutionError('invalidOptions', 'At most one of versionId, versionTime and versionNumber may be given.')
  if (options.versionNumber !== undefined && (!Number.isInteger(options.versionNumber) || options.versionNumber < 1)) throw new VhResolutionError('invalidOptions', 'versionNumber must be a positive integer.')
  let requestedTime: number | undefined
  if (options.versionTime !== undefined) {
    requestedTime = Date.parse(options.versionTime)
    if (Number.isNaN(requestedTime)) throw new VhResolutionError('invalidOptions', 'versionTime must be an ISO 8601 time.')
  }
  if (!Array.isArray(log) || !log.length) throw invalid('The DID log is empty.')

  const now = options.now ?? Date.now()
  const states: Array<{ active: ActiveParameters; time: number }> = []
  let active: ActiveParameters | undefined
  let previousVersionId = ''
  let previousTime = -Infinity

  for (let index = 0; index < log.length; index += 1) {
    const entry = log[index] as LogEntry
    const label = `Entry ${index + 1}`
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw invalid(`${label} is not an object.`)
    for (const name of Object.keys(entry)) if (!ENTRY_MEMBERS.includes(name)) throw invalid(`${label} has an unknown member ${JSON.stringify(name)}.`)
    if (active?.deactivated) throw invalid(`${label} follows the entry that deactivated the DID.`)

    const previous = active
    active = applyParameters(previous, entry.parameters, index === 0)

    if (index === 0) {
      if (entry.parameters.scid !== scid) throw invalid('The SCID in the log is not the SCID of the DID.')
      if (!verifyScid(entry)) throw invalid('The SCID does not match the first entry.')
      previousVersionId = scid
    }

    const version = typeof entry.versionId === 'string' ? VERSION_ID.exec(entry.versionId) : null
    if (!version) throw invalid(`${label} has an invalid versionId.`)
    if (Number(version[1]) !== index + 1) throw invalid(`${label} has version number ${version[1]}.`)
    if (!verifyEntryHash(entry, previousVersionId)) throw invalid(`${label} has an entry hash that does not match its content.`)

    if (typeof entry.versionTime !== 'string' || !VERSION_TIME.test(entry.versionTime) || Number.isNaN(Date.parse(entry.versionTime))) throw invalid(`${label}: versionTime must be UTC, in whole seconds.`)
    const time = Date.parse(entry.versionTime)
    if (time <= previousTime) throw invalid(`${label} is not later than the entry before it.`)
    if (!isVersionTimeNotTooFarInFuture(entry.versionTime, now)) throw invalid(`${label} is dated in the future.`)

    const state = entry.state as { id?: unknown } | undefined
    if (!state || typeof state !== 'object' || Array.isArray(state)) throw invalid(`${label} has no DID Document.`)
    if (state.id !== did) throw invalid(`${label}: the document id must be exactly ${did}.`)

    // Which keys may sign this entry (VH-Log: Authorized Keys).
    let signers: string[]
    if (index === 0) signers = active.updateKeys
    else if (previous!.nextKeyHashes.length) {
      // Pre-rotation: the entry restates both lists, and every key it authorises was committed by the entry before.
      if (entry.parameters.updateKeys === undefined) throw invalid(`${label} must restate updateKeys: pre-rotation is active.`)
      if (entry.parameters.nextKeyHashes === undefined) throw invalid(`${label} must restate nextKeyHashes: pre-rotation is active.`)
      const committed = new Set(previous!.nextKeyHashes)
      for (const key of active.updateKeys) if (!committed.has(multikeyHashBase58(key))) throw invalid(`${label} authorises a key that the entry before did not commit to.`)
      signers = active.updateKeys
    } else signers = previous!.updateKeys

    const { proof, ...unsigned } = entry
    if (!Array.isArray(proof) || !proof.length) throw invalid(`${label} has no proof.`)
    for (const one of proof) {
      const key = one && typeof one === 'object' ? signers.find(candidate => one.verificationMethod === `did:key:${candidate}#${candidate}`) : undefined
      let verified = false
      if (key && one.proofPurpose === 'assertionMethod') {
        try { verified = verifyProof(unsigned, one, decodeMultikey(key)) } catch { verified = false }
      }
      if (!verified) throw invalid(`${label} has a proof that is not a valid eddsa-jcs-2022 signature by an authorised key.`)
    }

    states.push({ active, time })
    previousVersionId = entry.versionId
    previousTime = time
  }

  let selected = log.length - 1
  if (options.versionId !== undefined) selected = log.findIndex(entry => entry.versionId === options.versionId)
  else if (options.versionNumber !== undefined) selected = options.versionNumber <= log.length ? options.versionNumber - 1 : -1
  else if (requestedTime !== undefined) {
    selected = -1
    states.forEach((state, index) => { if (state.time <= requestedTime!) selected = index })
  }
  if (selected < 0) throw new VhResolutionError('notFound', 'No entry of the log matches the requested version.')

  const last = states[states.length - 1]!.active
  const entry = log[selected]!
  const state = entry.state as Partial<DidDocument> & { id: string }
  const latest = log[log.length - 1]!
  return {
    did,
    doc: last.deactivated && selected === log.length - 1 ? null : {
      '@context': state['@context'] ?? [],
      id: state.id,
      verificationMethod: state.verificationMethod ?? [],
      authentication: state.authentication ?? [],
      ...(state.keyAgreement ? { keyAgreement: state.keyAgreement } : {}),
      service: state.service ?? [],
      alsoKnownAs: state.alsoKnownAs ?? [],
      ...(state.name ? { name: state.name } : {}),
    },
    versionId: entry.versionId,
    versionNumber: entryVersionNumber(entry.versionId),
    latestVersionId: latest.versionId,
    latestVersionNumber: entryVersionNumber(latest.versionId),
    deactivated: last.deactivated,
  }
}
