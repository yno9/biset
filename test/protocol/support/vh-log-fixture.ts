// Test-only helper for building a hand-signed did:vh log: built from the same
// primitives (JCS, multihash, Ed25519 data-integrity proofs), not from the resolver under test. A genesis entry and
// appended entries signed by the key the entry before authorised (no pre-rotation), whole-second UTC times.
import { encodeX25519Multikey } from '../../../src/protocol/didcomm/multikey.ts'
import { generateEntryHash } from '../../../src/protocol/vh/log.ts'
import type { LogEntry, LogParameters } from '../../../src/protocol/vh/log.ts'
import { encodeMultikey, jcsMultihashBase58, signProof } from './did-log-fixture.ts'

type Document = Record<string, any>

export interface VhDidCommOptions {
  rootPrivateKey: Uint8Array
  rootPublicKey: Uint8Array
  keyAgreementKeys?: Array<{ fragment: string; x25519PublicKey: Uint8Array }>
  endpointUri?: string
  /** An alias the document names (the did:web DID of the place it is published at). */
  alsoKnownAs?: string[]
  versionTime?: string
}

/** A single-entry did:vh log: the root key at #key-1 (authentication, and the key that signs the log), the keyAgreement keys, a DIDComm service. */
export function buildVhDidCommLog(opts: VhDidCommOptions): { did: string; log: LogEntry[] } {
  const updateKey = encodeMultikey(opts.rootPublicKey)
  const versionTime = opts.versionTime ?? '2026-08-23T00:00:00Z'
  const placeholder = 'did:vh:{SCID}'
  const parameters: LogParameters = { method: 'did:vh:1.0', scid: '{SCID}', updateKeys: [updateKey] }
  const state: Document = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: placeholder,
    verificationMethod: [
      { id: `${placeholder}#key-1`, type: 'Multikey', controller: placeholder, publicKeyMultibase: updateKey },
      ...(opts.keyAgreementKeys ?? []).map(key => ({ id: `${placeholder}#${key.fragment}`, type: 'Multikey', controller: placeholder, publicKeyMultibase: encodeX25519Multikey(key.x25519PublicKey) })),
    ],
    authentication: [`${placeholder}#key-1`],
    ...(opts.keyAgreementKeys?.length ? { keyAgreement: opts.keyAgreementKeys.map(key => `${placeholder}#${key.fragment}`) } : {}),
    service: opts.endpointUri ? [{ id: `${placeholder}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: opts.endpointUri, accept: ['didcomm/v2'], routingKeys: [] } }] : [],
    alsoKnownAs: opts.alsoKnownAs ?? [],
  }
  const scid = jcsMultihashBase58({ versionId: '{SCID}', versionTime, parameters, state })
  const real = JSON.parse(JSON.stringify({ parameters, state }).split('{SCID}').join(scid)) as { parameters: LogParameters; state: Document }
  const versionId = `1-${generateEntryHash(scid, versionTime, real.parameters, real.state)}`
  const unsigned = { versionId, versionTime, parameters: real.parameters, state: real.state }
  return { did: `did:vh:${scid}`, log: [{ ...unsigned, proof: [signProof(unsigned, `did:key:${updateKey}#${updateKey}`, opts.rootPrivateKey, versionTime)] }] }
}

/** The log with one more entry: `change` edits a copy of the latest document; signed by the root key (the one the log authorises). */
export function extendVhLog(log: LogEntry[], rootPrivateKey: Uint8Array, rootPublicKey: Uint8Array, change: (state: Document) => void, versionTime: string): LogEntry[] {
  const last = log[log.length - 1]!
  const updateKey = encodeMultikey(rootPublicKey)
  const state = JSON.parse(JSON.stringify(last.state)) as Document
  change(state)
  const number = Number(last.versionId.split('-', 1)[0]) + 1
  const unsigned = { versionId: `${number}-${generateEntryHash(last.versionId, versionTime, {}, state)}`, versionTime, parameters: {} as LogParameters, state }
  return [...log, { ...unsigned, proof: [signProof(unsigned, `did:key:${updateKey}#${updateKey}`, rootPrivateKey, versionTime)] }]
}

/** An x25519 keyAgreement entry for `extendVhLog`: the key added to the document, listed under keyAgreement. */
export function addKeyAgreement(state: Document, fragment: string, x25519PublicKey: Uint8Array): void {
  const id = `${state.id}#${fragment}`
  state.verificationMethod.push({ id, type: 'Multikey', controller: state.id, publicKeyMultibase: encodeX25519Multikey(x25519PublicKey) })
  state.keyAgreement = [...(state.keyAgreement ?? []), id]
}
