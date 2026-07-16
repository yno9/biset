// DID resolution + publication over Pkarr-relay-format gateways (DID.md: "the
// only method-abstraction — every caller goes through resolve()"). Browsers
// can't speak the DHT directly, so all reads/writes go through an HTTP gateway
// (biset uses its own account's relays as gateways — see DID.md Roles). The
// gateway can withhold or serve a stale record, never forge one: the payload
// signature is verified against the identity key the DID itself names.
import { zbase32Decode } from './zbase32.ts'
import { parseSignedPayload, buildSignedPayload, type ParsedPayload } from './packet.ts'
import { suffixOf, type DidDocument } from './document.ts'
import { splitIntoChain, mergeChain, MAX_CHAIN } from './chain.ts'
import { noteSeq } from './freshness.ts'

export type { DidDocument, DidService } from './document.ts'

const ED25519_PUBKEY_LEN = 32

// Public Pkarr relays as a last-resort fallback when an identity's own relays
// are unreachable (DID.md: hardcoded fallback only, never the primary path —
// resolving through a stranger's relay leaks who-looks-up-whom). Callers append
// these after the account's own relay gateways.
export const PUBLIC_PKARR_FALLBACKS = [
  'https://relay.pkarr.org',
  'https://pkarr.pubky.org',
]

// The identity public key is the DID suffix itself (z-base-32 of the pubkey), so
// it needs no network to recover — and it's exactly what the payload signature
// must verify against.
export function identityKeyFromDid(did: string): Uint8Array {
  return zbase32Decode(suffixOf(did), ED25519_PUBKEY_LEN)
}

function trim(u: string): string { return u.replace(/\/$/, '') }

// Resolve a DID across all gateways and keep the highest-seq signature-valid
// payload — a lagging gateway must not win over a fresher one. Signature is
// verified against the key the DID itself names, so a gateway cannot forge; the
// worst it can do is withhold or serve stale, which max-seq + freshness defeat.
export async function resolveVia(did: string, gatewayUrls: string[]): Promise<ParsedPayload | null> {
  const pubkey = identityKeyFromDid(did)
  const suffix = suffixOf(did)
  let best: ParsedPayload | null = null
  for (const gw of gatewayUrls) {
    try {
      const resp = await fetch(`${trim(gw)}/${suffix}`, { headers: { Accept: 'application/octet-stream' } })
      if (!resp.ok) continue
      const payload = new Uint8Array(await resp.arrayBuffer())
      const parsed = parseSignedPayload(pubkey, payload) // throws on bad signature → skipped
      if (!best || parsed.seq > best.seq) best = parsed
    } catch { /* try the next gateway */ }
  }
  return best
}

// Resolve with rollback protection: rejects a record whose seq is lower than the
// highest previously trusted for this DID (DID.md monotonicity check).
//
// Follows continuation records (chain.ts) transparently, so callers always
// get one logical document however many BEP44 records it actually spans.
// Each link is verified against the key its own DID names, exactly like the
// root — a gateway can withhold a link, never forge one. A missing/corrupt
// link degrades to the services resolved so far rather than failing the
// whole resolve: a partial relay list still beats an unresolvable identity.
export async function resolve(did: string, gatewayUrls: string[]): Promise<DidDocument | null> {
  const r = await resolveVia(did, gatewayUrls)
  if (!r) return null
  if (!noteSeq(did, r.seq)) return null // rollback attempt — refuse the stale record
  if (!r.document.ext) return r.document

  const continuations: DidDocument[] = []
  const seen = new Set<string>([suffixOf(did)])
  let next: string | undefined = r.document.ext
  while (next && continuations.length < MAX_CHAIN) {
    if (seen.has(next)) break // a chain that points back at itself — stop rather than loop
    seen.add(next)
    const link: ParsedPayload | null = await resolveVia(`did:dht:${next}`, gatewayUrls)
    if (!link) break // withheld or expired link — keep what we have
    continuations.push(link.document)
    next = link.document.ext
  }
  return mergeChain(r.document, continuations)
}

// Publish a signed document to a gateway (PUT /{suffix} with the raw payload).
// Returns true on 2xx. Callers publish to every gateway (their relays) so the
// record is redundantly kept alive — see DID.md republish rules.
export async function publishTo(gatewayUrl: string, did: string, payload: Uint8Array): Promise<boolean> {
  try {
    const resp = await fetch(`${trim(gatewayUrl)}/${suffixOf(did)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: payload as BodyInit,
    })
    return resp.ok
  } catch { return false }
}

// Convenience: build + sign a document and publish it to every gateway. Fired
// in parallel — a DHT PUT takes several seconds per gateway (mainline DHT
// traversal latency, not something we control), so publishing to N gateways
// sequentially took N times as long for no benefit (each PUT is independent).
//
// Splits into continuation records (chain.ts) when the document outgrows
// BEP44's 1000-byte cap; a document that fits publishes exactly as before,
// as a single record. Returns how many gateways accepted the ROOT record —
// the root is what makes the identity resolvable at all, so a link that
// failed everywhere is reported by throwing rather than by a lower count
// (silently publishing a root whose chain is broken would advertise relays
// nobody can reach).
export async function publishDocument(rootPrivateKey: Uint8Array, doc: DidDocument, gatewayUrls: string[]): Promise<number> {
  const links = splitIntoChain(rootPrivateKey, doc)

  // Continuations first: the root's `ext=` pointer must never be live before
  // the record it points at is.
  for (const link of links.slice(1).reverse()) {
    const payload = buildSignedPayload(link.privateKey, link.doc)
    const accepted = await Promise.all(gatewayUrls.map(gw => publishTo(gw, link.did, payload)))
    if (!accepted.some(Boolean)) throw new Error(`publishDocument: no gateway accepted continuation record ${link.did}`)
  }

  const root = links[0]!
  const payload = buildSignedPayload(root.privateKey, root.doc)
  const results = await Promise.all(gatewayUrls.map(gw => publishTo(gw, root.did, payload)))
  return results.filter(Boolean).length
}
