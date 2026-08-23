// Test-only helper for building a hand-signed did:webvh log, shared by every
// test that needs a resolvable DID document without an anchor server. This
// mirrors src.bak/did/webvh/publish.ts's createGenesis just enough to
// produce a log resolveEntries() accepts; it is deliberately not a second
// implementation of that flow — only genesis, only what verification needs.
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base58 } from '@scure/base'
import { canonicalize } from '../../../src/identity/webvh/jcs.ts'
import { multihashSha256 } from '../../../src/identity/webvh/multihash.ts'
import type { LogEntry, LogParameters } from '../../../src/identity/webvh/log.ts'

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

/** Builds a single-entry signed log for `did:webvh:{scid}:test.example`, with
 * `verificationMethod` carrying the root key at #key-1 plus every extra
 * verification method the caller supplies (device signing keys, MLS leaf
 * signature keys, etc). */
export function buildGenesisLog(rootPrivateKey: Uint8Array, rootPublicKey: Uint8Array, extraVerificationMethods: Array<{ fragment: string; publicKey: Uint8Array }>): { did: string; log: LogEntry[] } {
  const updateKey = encodeMultikey(rootPublicKey)
  const versionTime = '2026-08-23T00:00:00.000Z'
  const placeholderDid = 'did:webvh:{SCID}:test.example'
  const parameters: LogParameters = { method: 'did:webvh:1.0', scid: '{SCID}', updateKeys: [updateKey], nextKeyHashes: [], portable: false, witness: {}, watchers: [], deactivated: false, ttl: 3600 }
  const rootKeyId = `${placeholderDid}#key-1`
  const state = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: placeholderDid,
    verificationMethod: [
      { id: rootKeyId, type: 'Multikey' as const, controller: placeholderDid, publicKeyMultibase: updateKey },
      ...extraVerificationMethods.map(vm => ({ id: `${placeholderDid}#${vm.fragment}`, type: 'Multikey' as const, controller: placeholderDid, publicKeyMultibase: encodeMultikey(vm.publicKey) })),
    ],
    authentication: [rootKeyId],
    service: [],
    alsoKnownAs: [],
  }
  const preliminary = { versionId: '{SCID}', versionTime, parameters, state }
  const scid = jcsMultihashBase58(preliminary)
  const did = placeholderDid.replace('{SCID}', scid)
  const real = JSON.parse(JSON.stringify({ parameters, state }).split('{SCID}').join(scid)) as { parameters: LogParameters; state: object }
  const entryHash = jcsMultihashBase58({ versionId: scid, versionTime, parameters: real.parameters, state: real.state })
  const versionId = `1-${entryHash}`
  const unsigned = { versionId, versionTime, parameters: real.parameters, state: real.state }
  const proof = signProof(unsigned, `did:key:${updateKey}#${updateKey}`, rootPrivateKey, versionTime)
  return { did, log: [{ ...unsigned, proof: [proof] }] }
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
