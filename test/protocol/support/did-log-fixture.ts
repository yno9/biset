// Test-only helper for building a hand-signed did:vh log, shared by every
// test that needs a resolvable DID document without an anchor server. This
// builds just enough of a genesis entry to
// produce a log resolveEntries() accepts; it is deliberately not a second
// implementation of that flow — only genesis, only what verification needs.
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base58 } from '@scure/base'
import { canonicalize } from '../../../src/protocol/vh/jcs.ts'
import { multihashSha256 } from '../../../src/protocol/vh/multihash.ts'
import { encodeX25519Multikey } from '../../../src/protocol/didcomm/multikey.ts'
import type { LogEntry, LogParameters } from '../../../src/protocol/vh/log.ts'
import { rememberVhLocation } from '../../../src/protocol/did-resolve.ts'

/** Where each fixture log is "published" (for a test watcher to forward to). */
export const fixtureDomains = new Map<string, string>()

export function jcsMultihashBase58(value: unknown): string {
  return base58.encode(multihashSha256(new TextEncoder().encode(canonicalize(value))))
}

export function encodeMultikey(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(34)
  prefixed[0] = 0xed
  prefixed[1] = 0x01
  prefixed.set(publicKey, 2)
  return 'z' + base58.encode(prefixed)
}

export function signProof(document: object, verificationMethod: string, privateKey: Uint8Array, created: string) {
  const config = { type: 'DataIntegrityProof' as const, cryptosuite: 'eddsa-jcs-2022' as const, created, proofPurpose: 'assertionMethod', verificationMethod }
  const configHash = sha256(new TextEncoder().encode(canonicalize(config)))
  const docHash = sha256(new TextEncoder().encode(canonicalize(document)))
  const signingInput = new Uint8Array([...configHash, ...docHash])
  const signature = ed25519.sign(signingInput, privateKey)
  return { ...config, proofValue: 'z' + base58.encode(signature) }
}

/** Builds a single-entry signed did:vh log: the root key at #key-1 plus every extra verification method the caller
 * supplies (device signing keys, MLS leaf signature keys, etc). `domain` is the place it is published at: the document
 * names `did:web:<domain>` as an alias. */
export function buildGenesisLog(rootPrivateKey: Uint8Array, rootPublicKey: Uint8Array, extraVerificationMethods: Array<{ fragment: string; publicKey: Uint8Array }>, domain = 'test.example', didComm?: DidCommStateExtras): { did: string; log: LogEntry[] } {
  const updateKey = encodeMultikey(rootPublicKey)
  const versionTime = '2026-08-23T00:00:00Z'
  const placeholderDid = 'did:vh:{SCID}'
  const parameters: LogParameters = { method: 'did:vh:1.0', scid: '{SCID}', updateKeys: [updateKey], ...(didComm?.nextKeyHashes?.length ? { nextKeyHashes: didComm.nextKeyHashes } : {}) }
  const rootKeyId = `${placeholderDid}#key-1`
  const state = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: placeholderDid,
    verificationMethod: [
      { id: rootKeyId, type: 'Multikey' as const, controller: placeholderDid, publicKeyMultibase: updateKey },
      ...extraVerificationMethods.map(vm => ({ id: `${placeholderDid}#${vm.fragment}`, type: 'Multikey' as const, controller: placeholderDid, publicKeyMultibase: encodeMultikey(vm.publicKey) })),
    ],
    authentication: [rootKeyId, ...(didComm?.authenticationFragments ?? []).map(fragment => `${placeholderDid}#${fragment}`)],
    ...(didComm?.keyAgreementKeys?.length ? { keyAgreement: didComm.keyAgreementKeys.map(k => `${placeholderDid}#${k.fragment}`) } : {}),
    service: (didComm?.services ?? (didComm?.endpointUri ? [{ id: didComm.serviceId ?? '#didcomm', uri: didComm.endpointUri, routingKeys: didComm.routingKeys }] : []))
      .map(entry => ({
        id: `${placeholderDid}${entry.id}`,
        type: 'DIDCommMessaging',
        serviceEndpoint: 'serviceEndpoints' in entry
          ? entry.serviceEndpoints.map(e => ({ uri: e.uri, accept: ['didcomm/v2'], ...(e.routingKeys === null ? {} : { routingKeys: e.routingKeys ?? [] }) }))
          : { uri: entry.uri, accept: ['didcomm/v2'], routingKeys: entry.routingKeys ?? [] },
      })),
    alsoKnownAs: [`did:web:${domain}`],
  }
  for (const key of didComm?.keyAgreementKeys ?? []) {
    state.verificationMethod.push({ id: `${placeholderDid}#${key.fragment}`, type: 'Multikey' as const, controller: placeholderDid, publicKeyMultibase: encodeX25519Multikey(key.x25519PublicKey) })
  }
  for (const vm of didComm?.rawVerificationMethods ?? []) {
    state.verificationMethod.push({ id: `${placeholderDid}#${vm.fragment}`, type: 'Multikey' as const, controller: placeholderDid, publicKeyMultibase: vm.publicKeyMultibase })
  }
  const scid = jcsMultihashBase58({ versionId: '{SCID}', versionTime, parameters, state })
  const did = placeholderDid.replace('{SCID}', scid)
  const real = JSON.parse(JSON.stringify({ parameters, state }).split('{SCID}').join(scid)) as { parameters: LogParameters; state: object }
  const entryHash = jcsMultihashBase58({ versionId: scid, versionTime, parameters: real.parameters, state: real.state })
  const unsigned = { versionId: `1-${entryHash}`, versionTime, parameters: real.parameters, state: real.state }
  const proof = signProof(unsigned, `did:key:${updateKey}#${updateKey}`, rootPrivateKey, versionTime)
  // A did:vh names no host: the fixture says where the log is published, as a contact's address would.
  rememberVhLocation(did, domain)
  fixtureDomains.set(did, domain)
  return { did, log: [{ ...unsigned, proof: [proof] }] }
}

/** A minimal in-memory stand-in for the anchor's did.jsonl endpoint: GET
 * returns whatever was last stored (404 if nothing was), PUT replaces it
 * whole, POST appends (matching log-io.ts's putLog, which POSTs new entries
 * alone and falls back to a whole-log PUT only on 404/405). */
export function fakeAnchor(): { fetch: typeof fetch } {
  const store = new Map<string, string>()
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input.toString()
    if (init?.method === 'PUT') {
      store.set(url, String(init.body))
      return new Response('', { status: 200 })
    }
    if (init?.method === 'POST') {
      const existing = store.get(url)
      if (existing === undefined) return new Response('', { status: 404 })
      store.set(url, existing + String(init.body))
      return new Response('', { status: 200 })
    }
    const body = store.get(url)
    return body === undefined ? new Response('', { status: 404 }) : new Response(body, { status: 200 })
  }) as typeof fetch
  return { fetch: fetchImpl }
}

/** Swaps `globalThis.fetch` for one that serves `log` as the DID's did.jsonl
 * (or a 404 when `log` is null) for the duration of `run`. */
export function withFetch(log: LogEntry[] | null, run: () => Promise<void>): Promise<void> {
  const realFetch = globalThis.fetch
  globalThis.fetch = (async () => {
    if (log === null) return new Response('', { status: 404 })
    return new Response(log.map(e => JSON.stringify(e)).join('\n') + '\n', { status: 200 })
  }) as typeof fetch
  return run().finally(() => { globalThis.fetch = realFetch })
}

/** The `keyAgreement`/`#didcomm` service half of a did.md-published
 * document, as `urn:did-core:document-edit:v1` writes it in production. Must
 * be folded into the genesis state BEFORE the SCID is computed -- the SCID
 * covers the whole state, so editing it afterwards fails SCID verification.
 *
 * Field shapes are copied from a live `cb81.did.md/.well-known/did.jsonl`:
 * `keyAgreement` holds `#k_<id>` fragment references resolving to X25519
 * `Multikey` verification methods, and `serviceEndpoint` is
 * `{uri, accept, routingKeys}`. `serviceId` defaults to the current
 * `#didcomm`; pass the older `#didcomm-biset-<suffix>` form to exercise
 * suffix-bound route selection. */
export interface DidCommStateExtras {
  keyAgreementKeys?: Array<{ fragment: string; x25519PublicKey: Uint8Array }>
  /** Extra verification methods, already multibase-encoded, that are not
   * referenced from `keyAgreement`. */
  rawVerificationMethods?: Array<{ fragment: string; publicKeyMultibase: string }>
  /** Fragments of verification methods (from `rawVerificationMethods`, say)
   * that `authentication` references too, after the root key. */
  authenticationFragments?: string[]
  endpointUri?: string
  routingKeys?: string[]
  serviceId?: string
  /** Several DIDCommMessaging services at once, in document order (oldest
   * first) -- what a multi-device identity publishes. Supersedes the
   * `endpointUri`/`serviceId`/`routingKeys` single-service shorthand. An
   * entry may instead give `serviceEndpoints` directly (PLAN-tor.md D-4's
   * clearnet+onion array), bypassing the `{uri, accept, routingKeys}` map
   * shorthand entirely. */
  services?: Array<{ id: string; uri: string; routingKeys?: string[] } | { id: string; serviceEndpoints: Array<{ uri: string; routingKeys?: string[] | null }> }>
  /** A Spare Key commitment (pre-rotation) in the genesis parameters. */
  nextKeyHashes?: string[]
}

/** A DIDComm-capable single-entry log -- what replaced every
 * `/.well-known/routing.json` fixture when routing.json was retired
 * (2026-09-16). */
export function buildDidCommLog(opts: DidCommStateExtras & {
  rootPrivateKey: Uint8Array
  rootPublicKey: Uint8Array
  extraVerificationMethods?: Array<{ fragment: string; publicKey: Uint8Array }>
  domain?: string
}): { did: string; log: LogEntry[] } {
  return buildGenesisLog(opts.rootPrivateKey, opts.rootPublicKey, opts.extraVerificationMethods ?? [], opts.domain, opts)
}
