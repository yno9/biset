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
//   GET    /<username>/did.jsonl                      → did:webvh log | 404
//   PUT    /<username>/did.jsonl  body = JSONL         → 204 | 400/409
//   POST   /_anchor/devices/vouch   {"did":…,"device_pub_key":…,"label":…,…} → 200 | 400/401
//
// **The claim registry (/_anchor/identity/*) is for this anchor's own relays
// only** — naming a DID requires proving it (a relay_token Bearer), and the
// registry had two read routes with no caller (a stranger's operator must not
// learn who is looking them up — src/did/discovery.ts asks DNS instead). The
// mediator is the other thing here the world may talk to.
import type { ClaimStore } from './store.ts'
import { CloudflareAnchor } from './cloudflare.ts'
import { verifyDIDBinding, verifyDeviceVouch, rootKeyResolver } from './didbind.ts'
import type { MediatorHandler } from './mediator/server.ts'
import type { WebvhLogStore } from './webvh-store.ts'
import { resolveEntries } from '../did/webvh/resolver.ts'
import { buildBisetWebvhDid, parseWebvhDid, bisetWebvhUsername } from '../did/webvh/identifier.ts'
import type { LogEntry } from '../did/webvh/log.ts'

import { createHash, timingSafeEqual } from 'node:crypto'

const MAX_BODY = 1 << 12 // matches Go's io.LimitReader(r.Body, 1<<12)
// What one REQUEST may carry. A did:webvh log is append-only and every entry
// embeds the whole document, so the log itself outgrows any request-sized
// bound eventually — which is why a write sends only what is new (POST below)
// and this bounds a handful of entries, not a history. It stays generous
// because the whole-log PUT is still accepted from clients that predate the
// append route.
//
// This is the ONLY bound available before the caller is known: writes here are
// authorized by the update key inside the body (see handleWebvh's note), which
// cannot be checked until the body has been buffered and parsed.
const MAX_WEBVH_LOG_BODY = 1 << 20 // 1MiB

// What one IDENTITY may accumulate on this disk, enforced explicitly rather
// than left to the request cap to imply. The request cap used to be the de
// facto storage bound — and did the job so badly that a legitimate client
// crossed it and could no longer publish AT ALL, including the update that
// would have shrunk its document (y@biset.md, 2026-08-13): every way out
// needed an append, and the append was what no longer fit.
//
// Two numbers rather than one because the two failure modes differ: a log of
// enormous entries and a log of endless tiny ones both need stopping, and
// saying so plainly is better than a single byte count that silently means
// different things for different documents.
const serializeLines = (lines: string[]): string => lines.join('\n') + '\n'

const MAX_WEBVH_LOG_ENTRIES = 10_000
const MAX_WEBVH_LOG_BYTES = 16 << 20 // 16MiB

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
  cloudflare: CloudflareAnchor
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

export function startAnchor({ claims, cloudflare, port, hostname, mediator, webvh, relayToken }: AnchorOptions) {
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
  // GET/PUT /<username>/did.jsonl — did:webvh log storage (PLANWEBVH.md
  // §2.1/§2.3). Domain comes from the request Host header, not the path: a
  // username is only unique within its own domain, and biset serves two
  // (biset.md gated, t.biset.md open) off this one process.
  //
  // No `dids/` prefix any more (2026-08-11, user-requested — shorter DIDs):
  // the path is now just `/<username>/did.jsonl`, which means a username
  // MUST NOT be able to collide with any of this anchor's own reserved
  // top-level names (`_anchor`, the prefix every other internal route below
  // now lives under) — checked once, at the bottom of this function, rather
  // than trusted to never come up.
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
  // about. Falling back to Host keeps direct-to-anchor callers (tests, curl
  // against anchor.biset.md itself) working unchanged.
  //
  // Both GET and PUT are open to anyone — no relay_token gate — same
  // "gateway holds zero authority" stance the anchor already takes: a did:webvh
  // log is self-certifying (SCID + per-entry Data Integrity proofs), so a
  // browser client can PUT it directly and this store cannot forge one, only
  // withhold. (Originally gated behind fromOwnRelay, on the theory that a
  // `username` — unlike a did:dht key — is a scarce human-readable name and
  // needed the same ownership proof `/_anchor/identity/*` requires for addresses.
  // That gate made the endpoint unusable from a browser: relay_token is a
  // server-side secret the client never holds. Fixed by enforcing ownership
  // a different way — see the append-only check below — rather than by
  // requiring a secret the caller can't have.)
  async function handleWebvh(req: Request, url: URL): Promise<Response> {
    if (!webvh) return notFound()
    const m = /^\/([^/]+)\/did\.jsonl$/.exec(url.pathname)
    if (!m) return notFound()
    const username = m[1]!
    // Reserved: the one name every OTHER route on this anchor lives under
    // (RESERVED_USERNAME, checked below too so account creation itself can
    // never mint a claim this route would then be unable to serve).
    if (username === RESERVED_USERNAME) return notFound()
    const domain = (req.headers.get('x-biset-domain') ?? req.headers.get('host') ?? '').split(':')[0]
    if (!domain) return text('missing host', 400)

    switch (req.method) {
      case 'GET': {
        const jsonl = webvh.read(domain, username)
        if (!jsonl) return notFound()
        return new Response(jsonl, { status: 200, headers: { ...CORS, 'Content-Type': 'text/jsonl' } })
      }
      case 'POST':
      case 'PUT': {
        const body = await req.text()
        // A did:webvh log accumulates a full state + proof per entry (unlike
        // the single-JSON-object bodies MAX_BODY was sized for), so it
        // outgrows that 4KB limit within a handful of updates — a dedicated,
        // much larger cap instead.
        if (body.length > MAX_WEBVH_LOG_BODY) return text('log too large', 400)
        const lines = body.split('\n').map(l => l.trim()).filter(Boolean)
        if (lines.length === 0) return text('empty log', 400)
        let entries: LogEntry[]
        try {
          entries = lines.map(l => JSON.parse(l) as LogEntry)
        } catch {
          return text('invalid JSONL', 400)
        }
        // What this store DOES enforce, in place of the relay_token gate: an
        // update to an EXISTING username must extend its current log
        // verbatim (every existing line byte-identical, only new lines
        // appended), never replace it outright. `username` is a scarce
        // human-readable name — without this, anyone could overwrite a
        // stranger's log with a fabricated one of their own and erase their
        // entire history. A first-ever PUT for a username (genesis) is
        // unrestricted — first-come, same as claiming any name anywhere.
        const existing = webvh.read(domain, username)
        const existingLines = existing ? existing.split('\n').map(l => l.trim()).filter(Boolean) : []
        // POST carries ONLY the new entries; the stored log is the prefix.
        // PUT carries the whole thing, as it always did.
        //
        // The distinction matters far past convenience: with PUT, the request
        // grows with the history, so a long-lived identity eventually cannot
        // write at all — and the operation it needs in order to shrink is
        // itself a write. POST's body is one entry's worth forever.
        const isAppend = req.method === 'POST' && existingLines.length > 0
        const allLines = isAppend ? [...existingLines, ...lines] : lines
        if (!isAppend && existing) {
          // The append-only rule, unchanged for a whole-log PUT: every line
          // the store already holds must come back byte-identical. `username`
          // is a scarce human-readable name, and without this anyone could
          // replace a stranger's log with a fabricated one and erase their
          // history.
          const extendsExisting = lines.length >= existingLines.length && existingLines.every((l, i) => l === lines[i])
          if (!extendsExisting) return text('update must extend the existing log, not replace it', 409)
        }
        if (allLines.length > MAX_WEBVH_LOG_ENTRIES) {
          return text(`log would exceed ${MAX_WEBVH_LOG_ENTRIES} entries for this name`, 507)
        }
        const totalBytes = allLines.reduce((n, l) => n + l.length + 1, 0)
        if (totalBytes > MAX_WEBVH_LOG_BYTES) {
          return text(`log would exceed ${MAX_WEBVH_LOG_BYTES} bytes for this name`, 507)
        }
        let allEntries: LogEntry[]
        try {
          allEntries = isAppend ? [...existingLines.map(l => JSON.parse(l) as LogEntry), ...entries] : entries
        } catch {
          return text('stored log is not valid JSONL', 500)
        }
        // Full did:webvh verification (SCID, entryHash chain, versionTime
        // monotonicity, every entry's Data Integrity proof against the
        // updateKeys the PRIOR entry authorized) — same check resolve() does,
        // run here too before accepting the write. Used to be skipped ("the
        // resolver's job"), on the theory that this store holds zero
        // cryptographic authority over a log's content — true for reading,
        // but append-only writes have no undo: once a wrongly-signed entry
        // (e.g. a rotation signed with the wrong key) is accepted, every
        // future resolve fails at that entry forever, and there is no way to
        // retract it (found live: an editor tool signed a rotation with a
        // superseded key, and the DID was permanently unresolvable from that
        // point on). Rejecting a bad log HERE, before it's ever written,
        // costs nothing a well-formed client would notice.
        // Verified against the DID of the LOCATION being written to — built
        // from (this domain, this username, the log's own SCID) — not against
        // whatever `state.id` the genesis entry happens to carry. Two things
        // fall out of that, both needed:
        //
        //  - A domain move (webvh/publish.ts's moveDidToNewDomain) writes the
        //    SAME log to a NEW location, where the genesis names the OLD DID.
        //    resolveEntries' rule is "SOME entry's state.id matches", so the
        //    move entry satisfies it here while the genesis satisfies it back
        //    at the old location. Validating against the genesis DID instead
        //    would have accepted both, but for the wrong reason.
        //  - It rejects parking a valid log for DID X under an unrelated
        //    username Y at this domain: no entry names Y, so nothing matches.
        //    Squatting like that could never be RESOLVED (the resolver applies
        //    the same rule), but it would still consume a scarce human-readable
        //    name and shadow the real owner's first-ever PUT.
        const scid = allEntries[0]?.parameters?.scid
        if (!scid) return text('first entry parameters.scid missing', 400)
        const locationDid = buildBisetWebvhDid(scid, domain, username)
        try {
          resolveEntries(locationDid, allEntries)
        } catch (e) {
          return text(`invalid did:webvh log: ${e instanceof Error ? e.message : String(e)}`, 400)
        }
        webvh.write(domain, username, serializeLines(allLines))
        return new Response(null, { status: 204, headers: CORS })
      }
      default:
        return text('method not allowed', 405)
    }
  }

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
      const selfNamed = did.startsWith('did:webvh:') && bisetWebvhUsername(did) === username.toLowerCase()
        && parseWebvhDid(did).domain.toLowerCase() === domain.toLowerCase()
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
    if (url.pathname.startsWith('/_anchor/identity/')) {
      const rest = url.pathname.slice('/_anchor/identity/'.length)
      return handleIdentity(req, url, rest)
    }
    // No `/dids/` prefix any more (RESERVED_USERNAME's note) — any other
    // one-segment path ending in did.jsonl is a webvh log request;
    // handleWebvh itself 404s anything that doesn't actually match.
    if (/^\/[^/]+\/did\.jsonl$/.test(url.pathname)) return handleWebvh(req, url)
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
  // claim, publish a DNS TXT — only the TXT half still applies here: the DNS
  // anchor is how other clients discover this address's DID (src/did/
  // discovery.ts), and skipping the registry write does not change that.
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

    // Best-effort, same as the claim path: publication failing must not fail
    // a binding that already verified.
    await cloudflare.writeAnchorTXT(username, domain, did)
      .catch(e => console.error(`[dns-anchor] failed for ${username}@${domain}:`, e?.message ?? e))
    return json({ ok: true }, 200)
  }

  async function handleIdentity(req: Request, url: URL, rest: string): Promise<Response> {
    const localpart = rest.toLowerCase() // Go: strings.ToLower(rest)
    if (localpart === '' || localpart.includes('/')) return notFound()
    // The primary enforcement point for RESERVED_USERNAME (see its own
    // note): refuse to ever CLAIM this name, so no account can be created
    // whose did:webvh log path would then be unservable.
    if (localpart === RESERVED_USERNAME) return text('reserved username', 400)

    // GET is a 404, not a 405. 405 would say "this resource is readable, just
    // not that way" — there is no readable resource here at all. The registry
    // answers its own relays' writes and nothing else; address→DID is DNS's
    // question, deliberately (src/did/discovery.ts).
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
        // bound to their own address — and a `_did` TXT record published saying
        // so — because owning an *account* was never evidence of owning an
        // *identity*.
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
        if (did) {
          // Best-effort, exactly as in Go: a DNS failure must not undo an
          // accepted claim — the claim is the authority, DNS is its publication.
          await cloudflare.writeAnchorTXT(localpart, domain, did)
            .catch(e => console.error(`[dns-anchor] failed for ${localpart}@${domain}:`, e?.message ?? e))
        }
        return json(claims.read(domain, localpart), existed ? 200 : 201)
      }

      case 'DELETE': {
        if (!fromOwnRelay(req)) return forbidden()
        // Account-delete's counterpart to claim (POST): drop the claim, then
        // withdraw its publication. Both halves matter — a released address
        // that keeps its TXT record goes on telling the world it belongs to the
        // DID of whoever held it last, and the next holder's claim can't undo
        // that (a fresh claim with a *different* DID rewrites it, but a claim
        // with no DID leaves the old record standing).
        const domain = url.searchParams.get('domain')
        if (!domain) return text('domain required', 400)
        try {
          claims.release(domain, localpart)
        } catch {
          return text('release failed', 500)
        }
        // Best-effort, mirroring the claim path: the registry is the authority
        // and it has already let go, so a DNS failure must not fail the release
        // — that would leave the caller retrying a delete that already happened.
        await cloudflare.deleteAnchorTXT(localpart, domain)
          .catch(e => console.error(`[dns-anchor] delete failed for ${localpart}@${domain}:`, e?.message ?? e))
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
