// DID resolution + publication over Pkarr-relay-format gateways (DID.md: "the
// only method-abstraction — every caller goes through resolve()"). Browsers
// can't speak the DHT directly, so all reads/writes go through an HTTP gateway
// (biset uses its own account's relays as gateways — see DID.md Roles). The
// gateway can withhold or serve a stale record, never forge one: the payload
// signature is verified against the identity key the DID itself names.
import { zbase32Decode } from './zbase32.ts'
import { parseSignedPayload, buildSignedPayload, type ParsedPayload } from './packet.ts'
import { suffixOf, type DidDocument } from './document.ts'

export type { DidDocument, DidService } from './document.ts'

const ED25519_PUBKEY_LEN = 32

// The identity public key is the DID suffix itself (z-base-32 of the pubkey), so
// it needs no network to recover — and it's exactly what the payload signature
// must verify against.
export function identityKeyFromDid(did: string): Uint8Array {
  return zbase32Decode(suffixOf(did), ED25519_PUBKEY_LEN)
}

function trim(u: string): string { return u.replace(/\/$/, '') }

// Resolve a DID by trying each gateway in turn; the first that returns a
// signature-valid payload wins. Freshness across gateways (rejecting a lower
// seq than one already seen) is enforced by the caller via the returned seq —
// see DID.md's monotonicity check — not here, so this stays a pure lookup.
export async function resolveVia(did: string, gatewayUrls: string[]): Promise<ParsedPayload | null> {
  const pubkey = identityKeyFromDid(did)
  const suffix = suffixOf(did)
  for (const gw of gatewayUrls) {
    try {
      const resp = await fetch(`${trim(gw)}/${suffix}`, { headers: { Accept: 'application/octet-stream' } })
      if (!resp.ok) continue
      const payload = new Uint8Array(await resp.arrayBuffer())
      return parseSignedPayload(pubkey, payload) // throws on bad signature → treated as a miss below
    } catch { /* try the next gateway */ }
  }
  return null
}

export async function resolve(did: string, gatewayUrls: string[]): Promise<DidDocument | null> {
  const r = await resolveVia(did, gatewayUrls)
  return r ? r.document : null
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

// Convenience: build + sign a document and publish it to every gateway.
export async function publishDocument(rootPrivateKey: Uint8Array, doc: DidDocument, gatewayUrls: string[]): Promise<number> {
  const payload = buildSignedPayload(rootPrivateKey, doc)
  let ok = 0
  for (const gw of gatewayUrls) if (await publishTo(gw, doc.id, payload)) ok++
  return ok
}
