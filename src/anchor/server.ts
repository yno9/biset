// The anchor's HTTP surface. Ported from go-didanchor's main.go — the route
// shapes, status codes and error strings are deliberately identical, because
// the existing relays (`go-jmapserver`'s AnchorClaim/AnchorRelease) must keep
// working against this **unmodified** during the staged migration (ANCHOR.md
// decision 5).
//
//   POST   /identity/<localpart>                {"domain":…,"fingerprint":…,"did":…} → 201/200/409
//   GET    /identity/<localpart>?domain=<domain>                    → {"fingerprint":…,"did":…} | 404
//   GET    /identity/by-did/<did>                                   → {"domain":…,"localpart":…} | 404
//   DELETE /identity/<localpart>?domain=<domain>                    → 204
import type { ClaimStore } from './store.ts'
import { CloudflareAnchor } from './cloudflare.ts'
import { verifyDIDBinding } from './didbind.ts'
import type { MediatorHandler } from './mediator/server.ts'

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
}

export function startAnchor({ claims, cloudflare, port, hostname, mediator }: AnchorOptions) {
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

    if (!url.pathname.startsWith('/identity/')) return notFound()
    const rest = url.pathname.slice('/identity/'.length)

    // GET /identity/by-did/<did>
    if (rest.startsWith('by-did/')) {
      const did = rest.slice('by-did/'.length)
      if (did === '' || req.method !== 'GET') return notFound()
      const found = claims.resolveDid(did)
      return found ? json(found) : notFound()
    }

    const localpart = rest.toLowerCase() // Go: strings.ToLower(rest)
    if (localpart === '' || localpart.includes('/')) return notFound()

    switch (req.method) {
      case 'GET': {
        const domain = url.searchParams.get('domain')
        if (!domain) return text('domain required', 400)
        const rec = claims.read(domain, localpart)
        return rec ? json(rec) : notFound()
      }

      case 'POST': {
        const raw = await req.text()
        if (raw.length > MAX_BODY) return text('domain, and fingerprint or did, required', 400)
        let body: { domain?: string; fingerprint?: string; did?: string; did_sig?: string; bind_ts?: number; host?: string } | null = null
        try {
          body = JSON.parse(raw)
        } catch {
          return text('domain, and fingerprint or did, required', 400)
        }
        const domain = body?.domain ?? ''
        const fingerprint = body?.fingerprint ?? ''
        const did = body?.did ?? ''
        if (!domain || (!fingerprint && !did)) return text('domain, and fingerprint or did, required', 400)

        // Proof that the claimant controls the DID (ANCHOR.md decision 1:
        // verification is the anchor's job, relays pass it through).
        //
        // **Naming a DID now requires proving it.** Until every relay forwarded
        // the proof this had to accept claims without one, which meant the
        // registry took a DID on the relay's word: PUT /account/did carried no
        // signature, so anyone holding a self-service account could have a
        // stranger's DID bound to their own address — and a `_did` TXT record
        // published saying so — because owning an *account* was never evidence
        // of owning an *identity*. Both relays send a proof on both paths now,
        // so absence is a 401.
        //
        // A claim with no DID at all is untouched: fingerprint-only claims
        // (backfill, envelope rotation) have no identity to prove.
        if (did) {
          if (!body?.did_sig) return text('did binding: did_sig required', 401)
          const r = verifyDIDBinding({
            did,
            username: localpart,
            relayHost: body.host ?? '',
            bindTs: Number(body.bind_ts),
            sigB64: body.did_sig,
          })
          if (!r.ok) return text('did binding: ' + r.reason, 401)
        }

        const existed = claims.read(domain, localpart) !== null
        if (!claims.claim(domain, localpart, fingerprint, did)) {
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
