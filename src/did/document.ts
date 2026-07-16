// did:dht DID document <-> DNS resource records mapping (the "thin did:dht
// layer" from DID.md). Spec: https://did-dht.com (decentralized-identity/did-dht).
// Verified against the spec's official test vectors — see did/document.spec.ts.
//
// Scope note: biset only ever *builds* a minimal document — the Ed25519 identity
// key at _k0, plus its service (relay) list and alsoKnownAs (address). The
// *parser* is tolerant of the fuller shape other did:dht documents may carry
// (extra keys, controllers, types, previous), extracting just what biset needs
// (identity key, services, aka); unknown records are ignored, not an error.

// Key type index (registry/index.html#key-type-index). biset uses 0 (Ed25519
// identity key) and 3 (X25519 keyAgreement key, PLAN.md "Key material").
const KEY_TYPE_ED25519 = 0
const KEY_TYPE_X25519 = 3

export interface DidService {
  id: string // fragment only, e.g. "mail" (not the full did#mail)
  type: string
  serviceEndpoint: string[]
  // biset extension (did:dht additional properties): the transport this relay
  // bridges and the identity's address ON this relay. This is what links a
  // relay endpoint to its own address + protocol — so AP and SMTP endpoints of
  // one DID can carry DIFFERENT addresses (they no longer must match; the DID
  // binds them). Unknown to generic did:dht resolvers, which ignore extra props.
  protocol?: string // e.g. 'mail' | 'activitypub'
  address?: string  // this endpoint's address, e.g. y@biset.md
  // DIDCommMessaging service extension (PLAN.md "DID Document encoding"):
  // `accept`/`routingKeys` are W3C-standard DIDCommMessaging serviceEndpoint
  // fields with no did:dht wire encoding of their own — biset proposes `ac=`/
  // `rk=` to the did:dht Additional Properties Registry (same pattern as the
  // already-registered `sig`/`enc`), and adopts it ahead of any PR merge
  // (works identically either way; a merge only helps OTHER did:dht
  // implementations interpret it too).
  accept?: string[]
  routingKeys?: string[] // DID URLs, e.g. "did:dht:xxx#k1" (a mediator's kid)
}

export interface DidDocument {
  id: string // did:dht:...
  identityKey: Uint8Array // raw Ed25519 public key (the _k0 key)
  keyAgreementKey?: Uint8Array // raw X25519 public key (the _k1 key, DIDComm)
  alsoKnownAs: string[]
  service: DidService[]
  // biset extension (did:dht additional property, same pattern as service's
  // protocol/address): a self-asserted display name — purely a UX label
  // (e.g. shown instead of the raw did:dht string), not verified by anyone.
  // Same trust level as any social profile's display name.
  name?: string
}

export interface DnsRecord {
  name: string
  type: 'TXT' | 'NS'
  ttl: number
  rdata: string[] // RFC1035 character-strings; logical value = concatenation
}

const TTL = 7200
const CHUNK = 255 // RFC1035 max character-string length

// ── base64url (unpadded) ─────────────────────────────────────────────────────
function b64urlEncode(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function b64urlDecode(s: string): Uint8Array {
  const pad = (4 - (s.length % 4)) % 4
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// A TXT logical value may exceed 255 bytes; split into ≤255-byte chunks.
function toChunks(value: string): string[] {
  if (value.length <= CHUNK) return [value]
  const out: string[] = []
  for (let i = 0; i < value.length; i += CHUNK) out.push(value.slice(i, i + CHUNK))
  return out
}

// ── build: DID document → DNS records ────────────────────────────────────────
export function documentToRecords(doc: DidDocument): DnsRecord[] {
  const records: DnsRecord[] = []

  // Identity key at _k0 (t=0 Ed25519; id and alg omitted — identity key uses the
  // default of both, per spec).
  records.push({
    name: '_k0._did.',
    type: 'TXT',
    ttl: TTL,
    rdata: [`t=${KEY_TYPE_ED25519};k=${b64urlEncode(doc.identityKey)}`],
  })

  // keyAgreement key at _k1 (t=3 X25519), if present — DIDComm's direct
  // did:dht path (PLAN.md "DIDComm transport identity").
  if (doc.keyAgreementKey) {
    records.push({
      name: '_k1._did.',
      type: 'TXT',
      ttl: TTL,
      rdata: [`t=${KEY_TYPE_X25519};k=${b64urlEncode(doc.keyAgreementKey)}`],
    })
  }

  // Services at _sN, collecting their ids for the root record's svc= list.
  const svcIds: string[] = []
  doc.service.forEach((svc, i) => {
    svcIds.push(`s${i}`)
    let value = `id=${svc.id};t=${svc.type};se=${svc.serviceEndpoint.join(',')}`
    if (svc.protocol) value += `;proto=${svc.protocol}`
    if (svc.address) value += `;addr=${svc.address}`
    if (svc.accept?.length) value += `;ac=${svc.accept.join(',')}`
    if (svc.routingKeys?.length) value += `;rk=${svc.routingKeys.join(',')}`
    records.push({ name: `_s${i}._did.`, type: 'TXT', ttl: TTL, rdata: toChunks(value) })
  })

  if (doc.alsoKnownAs.length) {
    records.push({ name: '_aka._did.', type: 'TXT', ttl: TTL, rdata: [doc.alsoKnownAs.join(',')] })
  }

  // Root record. The identity key (k0) carries the standard relationships an
  // identity key must have (auth, asm, inv, del — spec Create step 2b). k1
  // (if present) is keyAgreement-only (agm=) — never authentication, per
  // did-dht spec's own worked example (spec.md: "vm=k0,k1;...;agm=k1;...").
  const vm = doc.keyAgreementKey ? 'k0,k1' : 'k0'
  const parts = ['v=0', `vm=${vm}`, 'auth=k0', 'asm=k0']
  if (doc.keyAgreementKey) parts.push('agm=k1') // same field order as did-dht spec.md's own worked example
  parts.push('inv=k0', 'del=k0')
  if (svcIds.length) parts.push(`svc=${svcIds.join(',')}`)
  // base64url-encoded (not raw text) so an arbitrary display name — which
  // could contain ';' or ',' — can never collide with the field separators
  // parseFields()/service-endpoint-list splitting relies on.
  if (doc.name) parts.push(`name=${b64urlEncode(new TextEncoder().encode(doc.name))}`)
  const id = suffixOf(doc.id)
  records.push({ name: `_did.${id}.`, type: 'TXT', ttl: TTL, rdata: toChunks(parts.join(';')) })

  return records
}

// ── parse: DNS records → DID document ────────────────────────────────────────
export function recordsToDocument(did: string, records: DnsRecord[]): DidDocument {
  const byName = new Map<string, string>()
  for (const r of records) {
    if (r.type !== 'TXT') continue // NS = gateway designation, not doc content
    // Strip the trailing "<id>." on the root record name so both forms key as "_did".
    const key = r.name.replace(/\.$/, '').replace(new RegExp(`^_did\\.${suffixOf(did)}$`), '_did')
    byName.set(key, r.rdata.join(''))
  }

  // Identity key from _k0.
  const k0 = byName.get('_k0._did')
  if (!k0) throw new Error('did:dht document missing _k0 identity key')
  const k0Fields = parseFields(k0)
  if (!k0Fields.k) throw new Error('_k0 record missing k=')
  const identityKey = b64urlDecode(k0Fields.k)

  // keyAgreement key from _k1, if present.
  const k1 = byName.get('_k1._did')
  const keyAgreementKey = k1 ? b64urlDecode(parseFields(k1).k ?? '') : undefined

  // Services + name from the root record's svc=/name= fields.
  const root = byName.get('_did')
  const rootFields = root ? parseFields(root) : {}
  const service: DidService[] = []
  const svcList = rootFields.svc ? rootFields.svc.split(',') : []
  for (const sid of svcList) {
    const raw = byName.get(`_${sid}._did`)
    if (!raw) continue
    const f = parseFields(raw)
    if (f.id && f.t && f.se) {
      service.push({
        id: f.id, type: f.t, serviceEndpoint: f.se.split(','), protocol: f.proto, address: f.addr,
        accept: f.ac ? f.ac.split(',') : undefined,
        routingKeys: f.rk ? f.rk.split(',') : undefined,
      })
    }
  }
  const name = rootFields.name ? new TextDecoder().decode(b64urlDecode(rootFields.name)) : undefined

  const akaRaw = byName.get('_aka._did')
  const alsoKnownAs = akaRaw ? akaRaw.split(',') : []

  return { id: did, identityKey, keyAgreementKey, alsoKnownAs, service, name }
}

// ── helpers ──────────────────────────────────────────────────────────────────
// "id=x;t=0;k=y" → { id:"x", t:"0", k:"y" }. Note "se=" values themselves never
// contain ';' (URIs are comma-joined within one field), so a plain ';' split is
// safe for the fields biset reads.
function parseFields(rdata: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const pair of rdata.split(';')) {
    const eq = pair.indexOf('=')
    if (eq > 0) out[pair.slice(0, eq)] = pair.slice(eq + 1)
  }
  return out
}

export function suffixOf(did: string): string {
  return did.replace(/^did:dht:/, '')
}

// Builds the biset DID document: identity key + one service per relay serving
// this identity + its address(es) as alsoKnownAs. This is what discovery reads —
// resolve(did).service is the relay list that solves cross-relay identity (b),
// and alsoKnownAs[0] is the current/primary address a contact should deliver to
// (solves (a): after a move, the new address is listed here, primary-first).
export function buildBisetDocument(
  did: string,
  identityKey: Uint8Array,
  relays: Array<{ id: string; serverUrl: string; protocol?: string; address?: string }>,
  addresses: string | string[],
  name?: string,
): DidDocument {
  const addrs = (Array.isArray(addresses) ? addresses : [addresses]).filter(Boolean)
  return {
    id: did,
    identityKey,
    alsoKnownAs: addrs.map(a => `mailto:${a}`),
    service: relays.map(r => ({
      id: r.id, type: 'JMAPRelay', serviceEndpoint: [r.serverUrl.replace(/\/$/, '')],
      protocol: r.protocol, address: r.address,
    })),
    name,
  }
}
