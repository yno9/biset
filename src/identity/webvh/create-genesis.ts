// Creates a brand-new did:webvh identity: builds the genesis log entry
// (placeholder SCID -> real SCID -> real DID), signs it, and PUTs it to the
// URL the resulting DID's domain segment names.
//
// Deliberately minimal relative to src.bak/did/webvh/publish.ts's
// createGenesis: no routing.json write (relay/DIDComm/mail service data —
// Vault Core's identity generation does not publish any of that; mail/DIDComm
// adapters can add it later when they exist), no username-specific path
// convention (the caller supplies whatever pathSegments it wants). The
// signed state itself is `buildMinimalWebvhState`'s id/#key-1/authentication
// only, matching what the read-only resolver (resolver.ts) already expects
// to find with no routing.json merge.
import { buildWebvhDid, didToHttpsUrl } from './identifier.ts'
import { generateScid, SCID_PLACEHOLDER } from './scid.ts'
import { generateEntryHash, serializeLog, type LogEntry, type LogParameters } from './log.ts'
import { buildProof } from './proof.ts'
import { encodeMultikey } from './multikey.ts'
import { buildMinimalWebvhState, type SignedWebvhState } from './document.ts'

export interface CreateGenesisOptions {
  domain: string
  pathSegments?: string[]
  rootPrivateKey: Uint8Array
  rootPublicKey: Uint8Array
  /** did:webvh v1.0 permits setting this only in the genesis entry. Defaults
   * to portable so a later domain move can use the log's own portability
   * mechanism instead of a bare rotation. */
  portable?: boolean
  fetch?: typeof fetch
}

export async function createGenesis(opts: CreateGenesisOptions): Promise<{ did: string; scid: string }> {
  const updateKey = encodeMultikey(opts.rootPublicKey)
  const versionTime = new Date().toISOString()
  const placeholderDid = buildWebvhDid({ scid: SCID_PLACEHOLDER, domain: opts.domain, pathSegments: opts.pathSegments })

  const parameters: LogParameters = {
    method: 'did:webvh:1.0',
    scid: SCID_PLACEHOLDER,
    updateKeys: [updateKey],
    nextKeyHashes: [],
    portable: opts.portable ?? true,
    witness: {},
    watchers: [],
    deactivated: false,
    ttl: 3600,
  }
  const state = buildMinimalWebvhState(placeholderDid, opts.rootPublicKey)
  const preliminary = { versionId: SCID_PLACEHOLDER, versionTime, parameters, state }

  const scid = generateScid(preliminary)
  const did = buildWebvhDid({ scid, domain: opts.domain, pathSegments: opts.pathSegments })
  // Substitute the placeholder everywhere it landed (parameters.scid,
  // state.id, state's verificationMethod/authentication ids) via one
  // whole-document string replace, the same approach scid.ts's verifyScid
  // uses to check it.
  const real = JSON.parse(JSON.stringify({ parameters, state }).split(SCID_PLACEHOLDER).join(scid)) as {
    parameters: LogParameters
    state: SignedWebvhState
  }

  const entryHash = generateEntryHash(scid, versionTime, real.parameters, real.state)
  const versionId = `1-${entryHash}`
  const unsigned = { versionId, versionTime, parameters: real.parameters, state: real.state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${updateKey}#${updateKey}`, privateKey: opts.rootPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  const fetchValue = opts.fetch ?? fetch
  const response = await fetchValue(didToHttpsUrl(did), {
    method: 'PUT',
    headers: { 'Content-Type': 'text/jsonl' },
    body: serializeLog([entry]),
  })
  if (!response.ok) throw new Error(`createGenesis: PUT failed with HTTP ${response.status} ${await response.text().catch(() => '')}`)

  return { did, scid }
}
