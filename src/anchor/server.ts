// The anchor's HTTP surface. Ported from go-didanchor's main.go, whose route
// shapes, status codes and error strings this matched exactly — so the deployed
// relays could keep working against it unmodified while it was swapped in
// (ANCHOR.md decision 5). **That constraint is spent.** The migration finished,
// go-didanchor is retired, and the routes below have since moved on: naming a
// DID requires proving it, `/pkarr` is here at all, and the two read routes are
// gone (see below).
//
//   POST   /identity/<localpart>   {"domain":…,"did":…,"did_sig":…,…} → 201/200/409
//   DELETE /identity/<localpart>?domain=<domain>                    → 204
//   GET    /pkarr/<z-base-32 pubkey>                       → wire payload | 404
//   PUT    /pkarr/<z-base-32 pubkey>   body = wire payload → 204 | 400
//
// **Every route is for this anchor's own relays. Nothing here answers a
// stranger.** The registry had two read routes and neither had a caller: the
// client never learns the anchor's URL, and asks DNS for address→DID precisely
// so a stranger's operator does not learn who is looking them up
// (src/did/discovery.ts). Their "public by design" rationale was inherited from
// go-jmapserver's /identity/local, which existed for operational lookups by
// hand — a question `grep` over identity.fp still answers, without a public
// surface to defend. The mediator is the one thing here the world may talk to.
import type { ClaimStore } from './store.ts'
import { CloudflareAnchor } from './cloudflare.ts'
import { verifyDIDBinding, didPublicKey } from './didbind.ts'
import type { MediatorHandler } from './mediator/server.ts'
import type { PkarrGateway } from './pkarr.ts'
import { createHash, timingSafeEqual } from 'node:crypto'
import { zbase32Decode } from '../did/zbase32.ts'

const MAX_BODY = 1 << 12 // matches Go's io.LimitReader(r.Body, 1<<12)

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
  /** Absent when the DHT gateway is off — `/pkarr/*` then 404s, as it did
   * before the anchor could serve it. */
  pkarr?: PkarrGateway
  /** The secret this anchor's own relays present. Not optional: see index.ts. */
  relayToken: string
}

export function startAnchor({ claims, cloudflare, port, hostname, mediator, pkarr, relayToken }: AnchorOptions) {
  const expected = createHash('sha256').update(relayToken).digest()

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
  // GET/PUT /pkarr/<z-base-32 pubkey> — the Pkarr relay surface browsers need
  // (they cannot speak UDP). Clients reach it through their own relay, which
  // proxies here: go-jmapserver used to run this itself, one DHT node per relay
  // (ANCHOR.md decision 1).
  async function handlePkarr(req: Request, url: URL): Promise<Response> {
    if (!pkarr) return notFound()
    // Relays only. Clients reach this through their own relay's /pkarr, which
    // proxies here with the token — nobody else has a reason to, and an open
    // gateway is both bandwidth anyone can spend and, per resolver.ts's privacy
    // note, a view of strangers' lookups.
    if (!fromOwnRelay(req)) return forbidden()
    const key = url.pathname.slice('/pkarr/'.length)
    if (key === '' || key.includes('/')) return notFound()
    let pubkey: Buffer
    try {
      pubkey = Buffer.from(zbase32Decode(key, 32))
    } catch {
      return text('invalid key', 400)
    }
    switch (req.method) {
      case 'GET': {
        const payload = await pkarr.get(pubkey)
        if (!payload) return notFound()
        return new Response(payload, { status: 200, headers: { ...CORS, 'Content-Type': 'application/octet-stream' } })
      }
      case 'PUT': {
        const body = Buffer.from(await req.arrayBuffer())
        try {
          await pkarr.put(pubkey, body)
        } catch (e) {
          // A bad signature and an unreachable DHT are both the caller's problem
          // to retry, and the Go gateway answered 400 to both. Keep that.
          return text(e instanceof Error ? e.message : 'pkarr: put failed', 400)
        }
        return new Response(null, { status: 204, headers: CORS })
      }
      default:
        return text('method not allowed', 405)
    }
  }

  async function handle(req: Request): Promise<Response> {
    const url = new URL(req.url)

    // The mediator owns `/` and `/.well-known/did.json`; the registry owns
    // `/identity/*`. Ask first and fall through, so a request for neither still
    // gets the registry's 404 rather than a mediator error about a message it
    // was never sent.
    if (mediator) {
      const resp = await mediator.handle(req, url)
      if (resp) return resp
    }

    if (url.pathname.startsWith('/pkarr/')) return handlePkarr(req, url)

    if (!url.pathname.startsWith('/identity/')) return notFound()
    const rest = url.pathname.slice('/identity/'.length)

    const localpart = rest.toLowerCase() // Go: strings.ToLower(rest)
    if (localpart === '' || localpart.includes('/')) return notFound()

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
        const r = verifyDIDBinding({
          did,
          username: localpart,
          relayHost: body.host ?? '',
          bindTs: Number(body.bind_ts),
          sigB64: body.did_sig,
        })
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
        // Read the DID before releasing — afterwards the claim is gone and with
        // it the only record of which key this address belonged to.
        const releasedDid = claims.read(domain, localpart)?.did
        try {
          claims.release(domain, localpart)
        } catch {
          return text('release failed', 500)
        }
        // Stop re-announcing the deleted identity's DHT record. The relays used
        // to do this themselves (pkarr.Gateway.Forget, from the DID the client
        // put in the delete body); now that the gateway lives here, the anchor
        // knows the DID from its own claim and the client never has to say it.
        if (releasedDid && pkarr) {
          const pk = didPublicKey(releasedDid)
          if (pk) pkarr.forget(Buffer.from(pk))
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
