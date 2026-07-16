// Continuation chaining: one logical DID document across several BEP44
// records.
//
// A BEP44 value is capped at 1000 bytes (bittorrent.org/beps/bep_0044.html:
// "Storing nodes MAY reject put requests where the bencoded form of v is
// longer than 1000 bytes"), which caps a did:dht document at roughly 4
// relays once _k1 + a DIDCommMessaging service are present. Past that, the
// signer throws and the identity silently stops republishing — it falls out
// of the DHT within ~2h and becomes unresolvable.
//
// This module lifts that cap by spilling the overflow into further did:dht
// records, each with its own key (keys.ts's deriveContinuationKey, derived
// from the root private key so the 24-word phrase still restores everything)
// and each named by the previous record's `ext=` field.
//
// Why chained records rather than the alternatives considered (PLAN.md):
//   - BEP44 salt would also work and is what BEP44 itself suggests for
//     "publish any number of items under one key" — but Pkarr's relay
//     protocol (the ONLY way a browser reaches the DHT, since it can't speak
//     UDP) has no salt field: it hardcodes the empty-salt canonical form
//     `3:seqi<seq>e1:v<len>:<bytes>`. Salt would mean extending both the
//     did:dht spec AND Pkarr's relay protocol, and the extended records
//     would only be readable through biset's own gateways.
//   - An external storage server would trade the DHT commons (nobody funds
//     it, nobody can kill it — ARC.md's "joint production" note) for a
//     service someone must keep alive.
//   Chained did:dht records need NEITHER: every record is an ordinary
//   empty-salt did:dht record, readable through any public Pkarr gateway.
//
// Trust: the root document is signed by the root key and names the
// continuation's DID; the continuation's content is signed by that
// continuation's own key, which its own DID names. So the chain is
// self-certifying end to end — a gateway can withhold a link, never forge
// one.
//
// Compatibility: a document that fits in one record is published byte-for-
// byte as it is today — no `ext=`, no continuation, nothing to notice. Only
// overflow triggers chaining, and a generic did:dht resolver that ignores
// `ext=` still gets a valid document with the first N services (graceful
// degradation, same stance as biset's other root-record extensions).
import { deriveContinuationKey, didFromRootPublicKey } from './keys.ts'
import { buildSignedPayload } from './packet.ts'
import type { DidDocument, DidService } from './document.ts'
import { suffixOf } from './document.ts'

// Max links to follow/emit. Bounds both a malicious/looping chain on the
// read side and a runaway document on the write side; 32 links is ~220
// services, far past any real identity.
export const MAX_CHAIN = 32

export interface ChainLink { did: string; privateKey: Uint8Array; doc: DidDocument }

function fits(doc: DidDocument, privateKey: Uint8Array): boolean {
  try {
    buildSignedPayload(privateKey, doc)
    return true
  } catch {
    return false // only ever throws for the size cap
  }
}

/** Splits one logical document into the chain of records that will actually
 * be published. Returns a single link (the document unchanged) whenever it
 * already fits — the overwhelmingly common case. */
export function splitIntoChain(rootPrivateKey: Uint8Array, doc: DidDocument): ChainLink[] {
  if (fits(doc, rootPrivateKey)) return [{ did: doc.id, privateKey: rootPrivateKey, doc }]

  // Greedily fill each record with as many services as fit, leaving room for
  // the `ext=` pointer to the next one. The essentials (identity key, _k1,
  // alsoKnownAs, name) always stay in the root record: they're what a
  // resolver needs even if it ignores the chain entirely.
  const links: ChainLink[] = []
  const remaining = [...doc.service]

  // Link i>0 uses continuation key i-1, so the root needs no key of its own
  // here and the indices stay contiguous from the first continuation.
  const linkKey = (i: number) => (i === 0
    ? { privateKey: rootPrivateKey, did: doc.id }
    : (() => {
        const kp = deriveContinuationKey(rootPrivateKey, i - 1)
        return { privateKey: kp.privateKey, did: didFromRootPublicKey(kp.publicKey) }
      })())

  while (remaining.length > 0) {
    const i = links.length
    if (i >= MAX_CHAIN) throw new Error(`splitIntoChain: document needs more than ${MAX_CHAIN} records`)
    const { privateKey, did } = linkKey(i)

    const base: DidDocument = i === 0
      ? { ...doc, service: [] }
      // A continuation carries only the overflow: its own identity key (the
      // record has to be a valid did:dht document to be parsed at all) plus
      // services. Never _k1/aka/name — those belong to the root identity,
      // and duplicating them would waste the space this exists to save.
      : { id: did, identityKey: deriveContinuationKey(rootPrivateKey, i - 1).publicKey, alsoKnownAs: [], service: [] }

    // Reserve room for a pointer while packing, then drop it if this turns
    // out to be the last link (measure with a placeholder of the exact size
    // a real suffix takes, so removing it can only ever free bytes).
    const placeholder = suffixOf(linkKey(i + 1).did)
    const packed: DidService[] = []
    while (remaining.length > 0) {
      const candidate: DidDocument = { ...base, service: [...packed, remaining[0]!], ext: placeholder }
      if (!fits(candidate, privateKey)) break
      packed.push(remaining.shift()!)
    }
    if (packed.length === 0) throw new Error('splitIntoChain: a single service does not fit in one record')

    links.push({ did, privateKey, doc: { ...base, service: packed } })
  }

  // Wire the pointers now that the layout is known; the last link has none.
  for (let i = 0; i < links.length - 1; i++) links[i]!.doc.ext = suffixOf(links[i + 1]!.did)
  return links
}

/** Merges a resolved chain back into the one logical document callers expect:
 * the root document, with every continuation's services appended in order. */
export function mergeChain(root: DidDocument, continuations: DidDocument[]): DidDocument {
  const service = [...root.service]
  for (const c of continuations) service.push(...c.service)
  const merged: DidDocument = { ...root, service }
  delete merged.ext // an implementation detail of transport, not of the identity
  return merged
}
