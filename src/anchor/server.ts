// The anchor's HTTP surface. Ported from go-didanchor's main.go, whose route
// shapes, status codes and error strings this matched exactly — so the deployed
// relays could keep working against it unmodified while it was swapped in
// (ANCHOR.md decision 5). **That constraint is spent.** The migration finished,
// go-didanchor is retired, and the routes below have since moved on: naming a
// DID requires proving it, the two read routes are gone, and (2026-08-11) every
// relay-facing/internal route moved under `/_anchor/*` so a did:webvh username
// can never collide with one (RESERVED_USERNAME's own note; shorter DIDs —
// no more `dids/` path segment — was the actual motivation).
//
//   POST   /_anchor/identity/<localpart>   {"domain":…,"did":…,"did_sig":…,…} → 201/200/409
//   DELETE /_anchor/identity/<localpart>?domain=<domain>                    → 204
//   GET    /_anchor/alias-target/<localpart>?domain=<domain>                → 200/404 (jmapserver::anchor::current_alias)
//   GET    /<username>/did.jsonl                      → did:webvh log | 404
//   PUT    /<username>/did.jsonl  body = JSONL         → 204 | 400/409
//   POST   /_anchor/devices/vouch   {"did":…,"device_pub_key":…,"label":…,…} → 200 | 400/401
//
// **The claim registry (/_anchor/identity/*) is for this anchor's own relays
// only** — naming a DID requires proving it (a relay_token Bearer). It has no
// read routes at all: address→DID discovery does not need one, since biset's
// own DID.md convention commits to a did:webvh identifier's trailing path
// segment always naming the SAME localpart the mail address at that domain
// uses — `user@domain`'s DID is always at `https://domain/user/did.jsonl`
// (did/discovery.ts). A DNS TXT anchor and, briefly, a WebFinger endpoint
// both used to answer this question separately (2026-08-17: removed, see
// discovery.ts's own history) before it was clear the convention alone
// always could. The mediator is the other thing here the world may talk to.
import type { ClaimStore } from './store.ts'
import { verifyDIDBinding, verifyDeviceVouch, rootKeyResolver } from './didbind.ts'
import type { MediatorHandler } from './mediator/server.ts'
import type { WebvhLogStore } from './webvh-store.ts'
import { parseWebvhDid, bisetWebvhUsername } from '../did/webvh/identifier.ts'
import { scidToLocalpart } from '../did/webvh/scid-localpart.ts'
import { resolveWebvhDocument } from './webvh-resolve.ts'
import { createWebvhHandler } from '../webvh-server/core.ts'
import { parseLog, resolveParameters, type LogParameters } from '../did/webvh/log.ts'
import { verifyProof, type DataIntegrityProof } from '../did/webvh/proof.ts'
import { decodeMultikey } from '../did/webvh/multikey.ts'

import { createHash, timingSafeEqual } from 'node:crypto'

const MAX_BODY = 1 << 12 // matches Go's io.LimitReader(r.Body, 1<<12)

// The one name a username/localpart may never be: every internal route below
// (`/_anchor/identity/*`, `/_anchor/devices/vouch`) lives
// under this prefix specifically so a did:webvh path (`/<username>/did.jsonl`,
// no `dids/` prefix any more — 2026-08-11, shorter DIDs) can never collide
// with one of them EXCEPT if a username were literally this string. Checked
// at claim time (POST /identity, below) so an account can never be CREATED
// under this name — handleWebvh's own check is a second, redundant guard on
// the read/write side, not the primary enforcement.
const RESERVED_USERNAME = '_anchor'

// Mirrors go-jmapserver's WrapCORS, with one deliberate difference: DELETE is
// included. The Go original lists only "GET, POST, PUT, OPTIONS" while the
// anchor's own release path *is* DELETE — a latent bug there, harmless only
// because every caller is a relay (server-to-server, where CORS never
// applies). Fixed rather than faithfully reproduced.
const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json' } })
const text = (body: string, status: number) =>
  new Response(body + '\n', { status, headers: { ...CORS, 'Content-Type': 'text/plain; charset=utf-8' } })
const notFound = () => text('404 page not found', 404)

export interface AnchorOptions {
  claims: ClaimStore
  port: number
  hostname?: string
  /** Absent when no `mediator_url` is configured — the anchor then answers
   * nothing on `/` and `/.well-known/did.json`, exactly as before it could
   * mediate at all. */
  mediator?: MediatorHandler
  /** did:webvh log storage (PLANWEBVH.md §2.1/§2.3). Absent means the webvh route
   * 404s — same "off by omission" shape as `mediator`. */
  webvh?: WebvhLogStore
  /** The secret this anchor's own relays present. Not optional: see index.ts. */
  relayToken: string
}

export function startAnchor({ claims, port, hostname, mediator, webvh, relayToken }: AnchorOptions) {
  const expected = createHash('sha256').update(relayToken).digest()
  const resolveRootKey = rootKeyResolver(webvh)

  /** True when the caller is one of this anchor's own relays.
   *
   * Digests are compared, not the tokens: timingSafeEqual throws on a length
   * mismatch, so comparing raw would either leak the length or need a branch
   * that leaks it anyway. Hashing first makes every comparison the same 32
   * bytes.
   *
   * A claim tells the anchor who owns an address; only its relays have any
   * business saying so, and before this the answer was "anyone who can reach
   * it" — which is everyone, because the mediator has to be reachable. This
   * gated writing and left reads open, on the grounds that an address is meant
   * to be discoverable from its DID. True, but it was answering a question
   * nobody asked here: the read routes had no callers at all, and are gone. */
  function fromOwnRelay(req: Request): boolean {
    const m = /^Bearer (.+)$/.exec(req.headers.get('authorization') ?? '')
    if (!m) return false
    return timingSafeEqual(createHash('sha256').update(m[1]!).digest(), expected)
  }

  // 403, not 401: 401 already means "the DID binding proof you sent was
  // rejected", which a relay reports to its user as their problem. This is the
  // relay itself being turned away and no user can do anything about it —
  // collapsing the two would have relays telling people their signature failed
  // when it was never looked at.
  const forbidden = () => text('this anchor does not serve that relay', 403)
  // GET/PUT/POST /<username>/did.jsonl — did:webvh log storage (PLANWEBVH.md
  // §2.1/§2.3), delegated to webvh-server/core.ts's standalone handler (the
  // did:webvh v1.0 hosting contract with no biset-specific opinions — see
  // its file header). This anchor only supplies what makes it biset's own
  // anchor rather than a bare one: the reserved-name guard and the
  // x-biset-domain resolution below.
  //
  // No `dids/` prefix any more (2026-08-11, user-requested — shorter DIDs):
  // the path is now just `/<username>/did.jsonl`, which means a username
  // MUST NOT be able to collide with any of this anchor's own reserved
  // top-level names (`_anchor`, the prefix every other internal route below
  // now lives under) — passed to core.ts as reservedFirstSegments.
  //
  // x-biset-domain, not Host, is the real signal: biset.md/t.biset.md's
  // Caddy proxies `/*/did.jsonl` to this anchor over `reverse_proxy
  // https://anchor.biset.md` with `header_up Host anchor.biset.md` (needed so
  // v2's own Caddy/Cloudflare-Tunnel vhost match succeeds — see the anchor.
  // biset.md block) — so by the time a request lands here, Host names the
  // ANCHOR, not the domain the client actually wrote to.
  //
  // x-forwarded-host does NOT survive this: this is a TWO-hop proxy (v1's
  // Caddy → v2's Caddy's `anchor.biset.md` block → this process), and Caddy's
  // reverse_proxy recomputes x-forwarded-host from whatever Host IT received
  // at each hop — so v2's Caddy overwrites hop 1's x-forwarded-host:biset.md
  // with its own x-forwarded-host:anchor.biset.md (it received Host:
  // anchor.biset.md, because hop 1 rewrote that too). A custom header set on
  // hop 1 and never touched by hop 2 is the only thing that survives — v1's
  // Caddyfile sets `header_up X-Biset-Domain {host}` in the same block that
  // rewrites Host, and hop 2 has no reason to touch a header it doesn't know
  // about. Falling back to Host (core.ts's default) keeps direct-to-anchor
  // callers (tests, curl against anchor.biset.md itself) working unchanged.
  //
  // Both GET and write are open to anyone — no relay_token gate — same
  // "gateway holds zero authority" stance the anchor already takes (core.ts's
  // own note has the full reasoning: a did:webvh log is self-certifying, so
  // this store cannot forge one, only withhold it).
  const handleWebvh = webvh
    ? createWebvhHandler(webvh, { domainHeader: 'x-biset-domain', reservedFirstSegments: [RESERVED_USERNAME] })
    : async () => notFound()

  // GET/PUT /<username>/routing.json — did/webvh/routing.ts's sibling
  // resource, biset-specific (unlike did.jsonl this isn't part of did:webvh
  // v1.0 itself, so it stays out of webvh-server/core.ts's protocol-generic
  // handler). Same domain/reserved-name resolution as handleWebvh above.
  //
  // Unlike a did:webvh log entry, routing.json's own bytes carry no
  // self-certifying structure — no SCID, no hash chain — so a PUT here is
  // verified against the identity's CURRENT updateKeys (read straight off
  // the did.jsonl this same store already holds for that domain+name) using
  // the exact same DataIntegrityProof a log entry signs with. This protects
  // against a third party overwriting someone else's routing.json; it does
  // NOT add anything past what did.jsonl already trusts this anchor process
  // with (the same host that could withhold/MITM did.jsonl could also just
  // not verify this correctly) — a scope call this design already made when
  // deciding connectivity metadata doesn't need did.jsonl's full guarantees.
  const MAX_ROUTING_BODY = 1 << 14 // generous for a handful of service entries
  function currentUpdateKeys(domain: string, name: string): string[] | null {
    const jsonl = webvh?.read(domain, name)
    if (!jsonl) return null
    try {
      let parameters: LogParameters = {}
      for (const entry of parseLog(jsonl)) parameters = resolveParameters(parameters, entry.parameters)
      return parameters.updateKeys ?? null
    } catch {
      return null
    }
  }
  const handleRouting = webvh
    ? async (req: Request, url: URL): Promise<Response> => {
      const m = /^\/([^/]+)\/routing\.json$/.exec(url.pathname)
      if (!m) return notFound()
      const name = m[1]!
      if (name === RESERVED_USERNAME) return notFound()
      const domain = ((req.headers.get('x-biset-domain')) ?? req.headers.get('host') ?? '').split(':')[0]
      if (!domain) return text('missing host', 400)

      switch (req.method) {
        case 'GET': {
          const stored = webvh.readRouting(domain, name)
          if (!stored) return notFound()
          return new Response(stored, { status: 200, headers: { ...CORS, 'Content-Type': 'application/json' } })
        }
        case 'PUT': {
          const body = await req.text()
          if (body.length > MAX_ROUTING_BODY) return text('bad request', 400)
          let parsed: { service?: unknown; proof?: DataIntegrityProof; [key: string]: unknown }
          try {
            parsed = JSON.parse(body)
          } catch {
            return text('invalid JSON', 400)
          }
          if (!Array.isArray(parsed.service) || !parsed.proof) return text('service and proof required', 400)
          const updateKeys = currentUpdateKeys(domain, name)
          if (!updateKeys?.length) return text('no did:webvh log for this name yet', 404)
          const vmMatch = /^did:key:([^#]+)(?:#.+)?$/.exec(parsed.proof.verificationMethod ?? '')
          const key = vmMatch?.[1]
          if (!key || !updateKeys.includes(key)) return text('routing.json: signing key not authorized by current updateKeys', 401)
          let publicKey: Uint8Array
          try {
            publicKey = decodeMultikey(key)
          } catch {
            return text('routing.json: invalid signing key', 400)
          }
          // The proof covers the WHOLE routing document (routing.ts's
          // putRouting signs `doc` as-is, not just `service`) — verify and
          // store everything except the `proof` envelope field itself.
          const { proof, ...doc } = parsed
          if (!verifyProof(doc, proof, publicKey)) {
            return text('routing.json: invalid signature', 401)
          }
          webvh.writeRouting(domain, name, JSON.stringify(doc))
          return new Response(null, { status: 204, headers: CORS })
        }
        default:
          return text('method not allowed', 405)
      }
    }
    : async () => notFound()

  // POST /_anchor/devices/vouch — the per-device JMAP credential's one DID-touching
  // step (devicebind.ts's file header): a relay forwards its client's
  // root-key-signed "this DID authorizes this device pubkey" statement here,
  // same server-to-server shape as `/_anchor/identity/*` (Bearer relay_token — this
  // anchor's own relays only, never a browser directly). Stateless: unlike
  // `/_anchor/identity/*` there is no NEW registry entry to write, just a yes/no —
  // the relay itself keeps the resulting authorized-device list.
  //
  // Two checks, not one. verifyDeviceVouch alone proves "this DID's current
  // root key authorizes this device pubkey" — but a relay stores no DID
  // material of its own (ANCHOR.md decision 1: "no relay handles DID
  // material any more" — see this file's own header), so it has no local way
  // to know whether `did` is even the right one for the `username`@`domain`
  // mailbox the caller means to add a device to. This function also checks
  // the claim registry itself (the same `claims` a provisioning POST
  // /_anchor/identity/<localpart> writes to) agrees `did` is who that address
  // belongs to — without it, a validly-signed vouch for a real DID could
  // still be presented for somebody ELSE's mailbox.
  async function handleDeviceVouch(req: Request): Promise<Response> {
    if (req.method !== 'POST') return text('method not allowed', 405)
    if (!fromOwnRelay(req)) return forbidden()
    const raw = await req.text()
    if (raw.length > MAX_BODY) return text('bad request', 400)
    let body: { did?: string; device_pub_key?: string; label?: string; bind_ts?: number; sig?: string; username?: string; domain?: string } | null = null
    try {
      body = JSON.parse(raw)
    } catch {
      return text('bad request', 400)
    }
    const did = body?.did ?? ''
    const devicePubKey = body?.device_pub_key ?? ''
    const label = body?.label ?? ''
    const username = body?.username ?? ''
    const domain = body?.domain ?? ''
    if (!did || !devicePubKey || !username || !domain) {
      return text('did, device_pub_key, username and domain required', 400)
    }
    if (!body?.sig) return text('device vouch: sig required', 401)
    const r = await verifyDeviceVouch({ did, devicePubKey, label, ts: Number(body.bind_ts), sigB64: body.sig }, resolveRootKey)
    if (!r.ok) return text('device vouch: ' + r.reason, 401)

    // Two ways an address can be legitimately bound to this DID, checked in
    // that order: a recorded claim (the `allow_provision`/`provision_secret`
    // path, POST /_anchor/identity/*), or — when there is no claim on
    // record — the DID's OWN webvh identifier naming this exact
    // domain+username (the `authorized_did_domain` path, verify-binding
    // above, which deliberately never writes a claim). Symmetric with that
    // endpoint's own reasoning: a 1:1 mail-domain:did-domain pairing needs no
    // registry to say who owns a name, because the DID string already says it.
    const claimed = claims.read(domain, username.toLowerCase())
    if (claimed) {
      if (claimed.did !== did) {
        return text('device vouch: did does not match the claim on record for that address', 401)
      }
    } else {
      // Two ways a DID can name ITSELF as the owner of `username`, with no
      // claim-registry entry needed: the human path segment (the original
      // check), or — SCID-primary accounts (PLANSCID.md) — the DID's own
      // permanent SCID segment. A SCID-primary account's real JMAP login
      // identity is the case-safe z-base32 projection of the SCID, so every
      // vouch after the first (the one
      // embedded in provisioning, which still sends the human name and so
      // hits the claim-registry branch above) is signed with `username` set
      // to that localpart — restore.ts, sync.ts, and left-pane.ts's "Reconnect
      // device" all resolve it via provision.ts's scidLoginAddress. Without
      // this, EVERY vouch after the very first one for such an account —
      // any new device, and any RE-vouch of an already-known one — was
      // rejected outright, since neither the claim registry (keyed by the
      // human name only) nor the human-path-segment check recognizes a SCID
      // string as belonging to this DID (found live, 2026-08-18: y@biset.md
      // locked out of restore entirely, the very first real-account use of
      // this scheme after migration).
      const selfNamed = did.startsWith('did:webvh:')
        && parseWebvhDid(did).domain.toLowerCase() === domain.toLowerCase()
        && (bisetWebvhUsername(did) === username.toLowerCase()
          || scidToLocalpart(parseWebvhDid(did).scid) === username.toLowerCase())
      if (!selfNamed) {
        return text('device vouch: did does not match the claim on record for that address', 401)
      }
    }
    return json({ ok: true }, 200)
  }

  async function handle(req: Request): Promise<Response> {
    const url = new URL(req.url)

    // The mediator owns `/` and `/.well-known/did.json`; the registry owns
    // `/_anchor/identity/*`. Ask first and fall through, so a request for neither still
    // gets the registry's 404 rather than a mediator error about a message it
    // was never sent.
    if (mediator) {
      const resp = await mediator.handle(req, url)
      if (resp) {
        // The mediator is browser-facing: biset is a browser app, and a
        // relay-less identity (DID⊥relay) reaches the mediator directly — from
        // a t.biset.md page or even origin `null` (file://). Its handlers build
        // plain Responses, so add CORS at this single choke point rather than on
        // every one. (Preflight OPTIONS is already answered globally below.)
        const headers = new Headers(resp.headers)
        for (const [k, v] of Object.entries(CORS)) headers.set(k, v)
        return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers })
      }
    }

    // Every OTHER route this anchor answers lives under `/_anchor/*`
    // (RESERVED_USERNAME's own note) — checked BEFORE the webvh catch-all
    // below, so `/_anchor/...` itself is never mistaken for a one-segment
    // username's did.jsonl path.
    if (url.pathname === '/_anchor/devices/vouch') return handleDeviceVouch(req)
    if (url.pathname === '/_anchor/verify-binding') return handleVerifyBinding(req)
    if (url.pathname.startsWith('/_anchor/alias-target/')) {
      const localpart = url.pathname.slice('/_anchor/alias-target/'.length)
      return handleAliasTarget(req, url, localpart)
    }
    if (url.pathname.startsWith('/_anchor/identity/')) {
      const rest = url.pathname.slice('/_anchor/identity/'.length)
      return handleIdentity(req, url, rest)
    }
    // No `/dids/` prefix any more (RESERVED_USERNAME's note) — any other
    // one-segment path ending in did.jsonl is a webvh log request;
    // handleWebvh itself 404s anything that doesn't actually match.
    if (/^\/[^/]+\/did\.jsonl$/.test(url.pathname)) return handleWebvh(req, url)
    if (/^\/[^/]+\/routing\.json$/.test(url.pathname)) return handleRouting(req, url)
    return notFound()
  }

  // POST /_anchor/verify-binding { domain, username, did, did_sig, bind_ts, host }
  // → 200 | 400/401/403
  //
  // The `authorized_did_domain` counterpart to POST /_anchor/identity/<localpart>
  // (jmapsmtp's ARC.md §2a): proves a DID's root key signed the binding, exactly
  // as handleIdentity does, but **writes nothing to the claim registry**. A mail
  // domain pinned 1:1 to one did-domain (`authorized_did_domain`) needs no
  // registry to enforce non-duplication — the did:webvh log store's own
  // append-only-per-(domain,username) shape already is that guarantee (this
  // file's own note on the claim registry's role explains the gap a 1:N config
  // would reopen; this endpoint exists for the 1:1 case where that gap cannot
  // occur). What POST /_anchor/identity/* does beyond verification — record a
  // claim — has no counterpart here at all: discovery (src/did/discovery.ts)
  // reads `https://<domain>/<username>/did.jsonl` directly, which for this
  // exact 1:1 shape is already served by the did:webvh log this DID's own
  // update just wrote — there is nothing left for this endpoint to publish.
  //
  // No `existed`/`claims.claim()` call, and therefore no 409 either: the
  // did:webvh log itself is what "already claimed" means here, and its
  // append-only PUT already refused a conflicting write long before this
  // endpoint is ever reached — by the time a caller has a `did` to present
  // here, the log write already succeeded or failed on its own terms.
  async function handleVerifyBinding(req: Request): Promise<Response> {
    if (req.method !== 'POST') return text('method not allowed', 405)
    if (!fromOwnRelay(req)) return forbidden()
    const raw = await req.text()
    if (raw.length > MAX_BODY) return text('domain, username and did required', 400)
    let body: { domain?: string; username?: string; did?: string; did_sig?: string; bind_ts?: number; host?: string } | null = null
    try {
      body = JSON.parse(raw)
    } catch {
      return text('domain, username and did required', 400)
    }
    const domain = body?.domain ?? ''
    const username = (body?.username ?? '').toLowerCase()
    const did = body?.did ?? ''
    if (!domain || !username || !did) return text('domain, username and did required', 400)
    if (!body?.did_sig) return text('did binding: did_sig required', 401)

    // The check the claim registry's non-duplication guarantee is replaced
    // BY, not merely alongside: without this, a valid did_sig proves only
    // that the presenting DID's root key signed a statement naming this
    // username — which any DID can do about any username, since the
    // signature says nothing about who that username actually belongs to.
    // With a claim registry, `claims.claim()` was the thing that separately
    // enforced "and this address is actually yours." Here there is no
    // registry, so the DID's OWN webvh path segment has to say so instead —
    // exactly the invariant a 1:1 mail-domain:did-domain pairing exists to
    // make true (jmapsmtp's provision.rs::did_domain_gate does the identical
    // check before this endpoint is ever called, on the Rust side — this is
    // the same check enforced again here, so this endpoint is safe to call
    // on its own rather than only safe behind a caller that happens to have
    // already checked).
    if (!did.startsWith('did:webvh:') || bisetWebvhUsername(did) !== username) {
      return text('did binding: DID does not name this username', 401)
    }
    let didDomain: string
    try {
      didDomain = parseWebvhDid(did).domain
    } catch {
      return text('did binding: malformed did:webvh identifier', 401)
    }
    if (didDomain.toLowerCase() !== domain.toLowerCase()) {
      return text('did binding: DID is not rooted at this domain', 401)
    }

    const r = await verifyDIDBinding({
      did,
      username,
      relayHost: body.host ?? '',
      bindTs: Number(body.bind_ts),
      sigB64: body.did_sig,
    }, resolveRootKey)
    if (!r.ok) return text('did binding: ' + r.reason, 401)

    return json({ ok: true }, 200)
  }

  /** `GET /_anchor/alias-target/<localpart>?domain=<domain>` —
   * jmapsmtp's alias-reconcile sweep (crates/jmapserver/src/anchor.rs's
   * `current_alias`) asking "what does `localpart@domain`'s bound DID
   * currently claim as its address". Answers the SCID-primary design
   * (PLANSCID.md) directly: `localpart` is the account's immutable SCID, and
   * the response names whatever human-chosen username/domain the DID's
   * CURRENT did:webvh identifier resolves to — the one alias jmapsmtp should
   * keep alive, with everything else on that primary being stale and safe to
   * drop. Relay-internal only (`fromOwnRelay`), same gate as every other
   * `/_anchor/*` route — this is not the public discovery route
   * handleIdentity's own header explains was removed; it answers a
   * maintenance question a relay asks about ITS OWN accounts, not "whose DID
   * is this address" for the world.
   *
   * 404 means no claim recorded at all (a pre-SCID account, or one that
   * never bound a DID) — the caller's own note on `AliasLookup::NotBound`
   * explains why that means "leave every alias alone", not "remove them". A
   * genuine resolve failure (network, malformed log) THROWS here rather than
   * quietly answering with nothing — turned into a 503 below, which the
   * caller reads as `Unknown`, never as grounds to delete anything: a
   * transient anchor or upstream hiccup must never be indistinguishable from
   * "this identity is gone". Only a clean, successful resolve that returns
   * `null` (deactivated) is reported as "no valid alias" — every other
   * failure mode reports "couldn't tell". */
  async function handleAliasTarget(req: Request, url: URL, localpart: string): Promise<Response> {
    if (req.method !== 'GET') return text('method not allowed', 405)
    if (!fromOwnRelay(req)) return forbidden()
    const domain = url.searchParams.get('domain')
    if (!domain) return text('domain required', 400)

    const claim = claims.read(domain, localpart)
    if (!claim) return notFound()

    let doc: Awaited<ReturnType<typeof resolveWebvhDocument>>
    try {
      doc = await resolveWebvhDocument(claim.did, webvh)
    } catch (e) {
      console.error(`[anchor] alias-target: resolve failed for ${claim.did}:`, e)
      return text('resolve failed', 503)
    }
    if (!doc) {
      // Deactivated, or the log is simply gone (webvh-sweep.ts eventually
      // reaps a location this DID moved away from and never returned to) —
      // either way, a clean answer of "nothing", not a failure.
      return json({ did: claim.did, currentUsername: null, currentDomain: null })
    }
    // Self-heal the stored pointer to the identity's CURRENT location — see
    // ClaimStore.rebind's own note: without this, a stale stored DID whose
    // OWN original location later falls to webvh-sweep.ts's TTL becomes
    // permanently unresolvable, and this route would start reporting a
    // perfectly live identity as gone.
    if (doc.id !== claim.did) claims.rebind(domain, localpart, doc.id)
    const currentUsername = bisetWebvhUsername(doc.id)
    let currentDomain: string | null
    try {
      currentDomain = parseWebvhDid(doc.id).domain
    } catch {
      currentDomain = null
    }
    return json({ did: claim.did, currentUsername: currentUsername ?? null, currentDomain })
  }

  async function handleIdentity(req: Request, url: URL, rest: string): Promise<Response> {
    const localpart = rest.toLowerCase() // Go: strings.ToLower(rest)
    if (localpart === '' || localpart.includes('/')) return notFound()
    // The primary enforcement point for RESERVED_USERNAME (see its own
    // note): refuse to ever CLAIM this name, so no account can be created
    // whose did:webvh log path would then be unservable.
    if (localpart === RESERVED_USERNAME) return text('reserved username', 400)

    // GET is a 404, not a 405. 405 would say "this resource is readable, just
    // not that way" — there is no readable resource here at all. This
    // registry answers its own relays' writes and nothing else; address→DID
    // is the did.jsonl path's own question (this file's header note).
    if (req.method === 'GET') return notFound()

    switch (req.method) {
      case 'POST': {
        if (!fromOwnRelay(req)) return forbidden()
        const raw = await req.text()
        if (raw.length > MAX_BODY) return text('domain and did required', 400)
        let body: { domain?: string; did?: string; did_sig?: string; bind_ts?: number; host?: string } | null = null
        try {
          body = JSON.parse(raw)
        } catch {
          return text('domain and did required', 400)
        }
        const domain = body?.domain ?? ''
        const did = body?.did ?? ''
        // A DID is the only thing there is to claim by. The body used to accept
        // an envelope fingerprint instead — see store.ts for why that is gone.
        if (!domain || !did) return text('domain and did required', 400)

        // Proof that the claimant controls the DID (ANCHOR.md decision 1:
        // verification is the anchor's job, relays pass it through).
        //
        // **Naming a DID requires proving it.** Until every relay forwarded the
        // proof this accepted claims without one, which meant the registry took
        // a DID on the relay's word: PUT /account/did carried no signature, so
        // anyone holding a self-service account could have a stranger's DID
        // bound to their own address — because owning an *account* was never
        // evidence of owning an *identity*.
        if (!body?.did_sig) return text('did binding: did_sig required', 401)
        const r = await verifyDIDBinding({
          did,
          username: localpart,
          relayHost: body.host ?? '',
          bindTs: Number(body.bind_ts),
          sigB64: body.did_sig,
        }, resolveRootKey)
        if (!r.ok) return text('did binding: ' + r.reason, 401)

        const existed = claims.read(domain, localpart) !== null
        if (!claims.claim(domain, localpart, did)) {
          return text('identity owned by a different key', 409)
        }
        return json(claims.read(domain, localpart), existed ? 200 : 201)
      }

      case 'DELETE': {
        if (!fromOwnRelay(req)) return forbidden()
        // Account-delete's counterpart to claim (POST).
        const domain = url.searchParams.get('domain')
        if (!domain) return text('domain required', 400)
        try {
          claims.release(domain, localpart)
        } catch {
          return text('release failed', 500)
        }
        return new Response(null, { status: 204, headers: CORS })
      }

      default:
        return text('method not allowed', 405)
    }
  }

  const server = Bun.serve({
    port,
    hostname,
    idleTimeout: 35,
    async fetch(req) {
      if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS })
      try {
        return await handle(req)
      } catch (e) {
        console.error('[anchor] unhandled:', e)
        return text('internal error', 500)
      }
    },
  })
  return server
}
