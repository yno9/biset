// One way to resolve a DID document whatever its method. biset holds identities of two kinds: a did:vh (no host in the DID: its
// log is looked for where the contact is known by, or at a watcher), and the did:web document a did:vh publishes beside itself (a
// shadow, derived from the log; didmail's bridges are did:web too). Callers that only need "the document of this DID" call this
// and do not branch on the method themselves.
import type { DidDocument } from './vh/document.ts'
import { resolveDidWeb, type DidWebDocument } from './didcomm/did-web.ts'
import { isDomainHost, isVhDid } from './vh/identifier.ts'
import { fetchVhResolution, type VhLogSources } from './vh/fetch.ts'
import type { LogEntry } from './vh/log.ts'
import { checkDidWebShadow, didWebCandidates, didWebDocumentUrl, verifiedAddress } from './vh/didweb.ts'
import type { VersionMemory } from './freshness.ts'

export interface DidResolveContext {
  fetch?: typeof fetch
  links?: DidLinks
  /** Ask the watchers for their copies of a did:vh's log and compare (a newer copy wins, a fork is refused): for a caller about to
   * rely on the current keys (sending, verifying a signature). Off by default: showing a name should not ask several servers. */
  checkWatchers?: boolean
  /** Where to look for the log of a did:vh. */
  vh?: Omit<VhLogSources, 'fetch'>
  /** Refuses an old or forked log. */
  memory?: VersionMemory
}

/** What the app knows about where did:vh logs are, set once when it starts (and again when its contacts change): every caller of
 * resolveDidDocument then asks the same places and shares one memory. */
export interface DidResolution {
  /** Watcher base URLs (`GET /log?scid=`). */
  watchers?: readonly string[]
  /** The web hosts a did:vh is known by (`alice.did.md`): from the contact's addresses and `alsoKnownAs`. */
  locationsOf?: (did: string) => readonly string[]
  memory?: VersionMemory
  /** Which did:vh a did:web was found to be the shadow of (see `resolveTrustedDid`). */
  links?: DidLinks
}

/** The did:web DIDs known to be shadows of a did:vh, remembered between loads: once a did:web is tied to a did:vh, only the did:vh
 * is believed about it, even if the did:vh later stops naming the did:web. */
export interface DidLinks {
  get(webDid: string): string | undefined
  set(webDid: string, vhDid: string): void
}

let configured: DidResolution = {}
export function configureDidResolution(resolution: DidResolution): void { configured = resolution }

// Hosts a did:vh was met at (an address answered with it: `alice@did.md` is at `alice.did.md`), for the rest of the session.
// Only where to look: whatever is found there is verified like any other copy.
const metAt = new Map<string, Set<string>>()
export function rememberVhLocation(did: string, host: string): void {
  if (!isDomainHost(host.toLowerCase())) return // an IP address, a path, anything that is not a domain name is never asked
  const hosts = metAt.get(did) ?? new Set<string>()
  hosts.add(host.toLowerCase())
  metAt.set(did, hosts)
}

function vhSources(did: string, context: DidResolveContext): VhLogSources {
  return {
    locations: [...(context.vh?.locations ?? []), ...(configured.locationsOf?.(did) ?? []), ...(metAt.get(did) ?? [])],
    watchers: [...(context.vh?.watchers ?? []), ...(configured.watchers ?? [])],
    fetch: context.fetch ?? fetch,
    // Only when asked (didvh-spec: the resolver retrieves further copies only when the client asks): the owner's watchers (in the
    // log) and this client's are asked for their copies; a newer one replaces the one found, two continuations are refused.
    compareCopies: context.checkWatchers === true,
  }
}

/** The whole verified log of a did:vh and its latest document; null when nobody asked has it (or it does not verify for this
 * DID). Throws on a log that is stale or forked relative to the memory. */
export async function fetchDidLog(did: string, context: DidResolveContext = {}): Promise<{ entries: LogEntry[]; document: DidDocument | null; versionId: string } | null> {
  const found = await fetchVhResolution(did, vhSources(did, context), context.memory ?? configured.memory)
  return found ? { entries: found.log, document: found.resolution.doc, versionId: found.resolution.latestVersionId } : null
}

/** The latest document of `did`; null when it does not resolve (no log, deactivated, nobody has it). Throws on a log that is
 * invalid, stale or forked. */
export async function resolveDidDocument(did: string, context: DidResolveContext = {}): Promise<DidDocument | null> {
  if (did.startsWith('did:vh:')) return (await fetchDidLog(did, context))?.document ?? null
  if (did.startsWith('did:web:')) return (await resolveDidWeb(did, context.fetch ?? fetch)) as DidDocument | null
  throw new Error(`resolveDidDocument: unsupported DID method for ${did}`)
}

/** The address a did:vh goes by (`alice@did.md`), or undefined: its latest document must name a plain-host did:web DID in
 * `alsoKnownAs`, and the document served there must be the shadow the log derives (vh/didweb.ts). Never invented, never from
 * what a sender says of itself. */
export async function verifiedVhAddress(did: string, context: DidResolveContext = {}): Promise<string | undefined> {
  const document = await resolveDidDocument(did, context).catch(() => null)
  if (!document) return undefined
  const fetchImpl = context.fetch ?? fetch
  for (const webDid of didWebCandidates(document as unknown as Record<string, unknown>)) {
    let shadow: unknown
    try {
      const response = await fetchImpl(didWebDocumentUrl(webDid))
      if (!response.ok) continue
      shadow = await response.json()
    } catch { continue }
    const address = verifiedAddress(document as unknown as Record<string, unknown>, webDid, shadow)
    if (address) return address
  }
  return undefined
}

/** What to believe about a DID someone is reached at: the DID whose document counts, and that document. */
export interface TrustedDid {
  /** The DID to address, sign for and verify against: the did:vh of a did:web that is its shadow, else the DID itself. */
  did: string
  document: DidDocument | DidWebDocument
  /** True when `did` is a did:vh reached through a did:web that points to it. */
  linked: boolean
}

/** The did:vh a did:web document points to in `alsoKnownAs` (`did:vh:<SCID>` or `did:vh:<SCID>?src=…`), the hosts to look for its log
 * at (the did:web's own host, and the host a `src` names), or undefined when it points to none. Two different did:vh DIDs are refused. */
function vhPointerOf(webDid: string, document: DidWebDocument): { did: string; hosts: string[] } | undefined {
  const found = new Map<string, string[]>()
  const own = /^did:web:([^:%/]+)$/.exec(webDid)?.[1]
  for (const alias of Array.isArray(document.alsoKnownAs) ? document.alsoKnownAs : []) {
    if (typeof alias !== 'string' || !alias.startsWith('did:vh:')) continue
    const [did = '', query] = alias.split('?', 2)
    if (!isVhDid(did)) continue
    const hosts = found.get(did) ?? (own ? [own] : [])
    try {
      const src = query ? new URLSearchParams(query).get('src') : null
      const url = src ? new URL(src) : undefined
      if (url && url.protocol === 'https:' && !url.port && (url.pathname === '/' || url.pathname === '') && isDomainHost(url.hostname)) hosts.push(url.hostname)
    } catch { /* an unreadable src names no host */ }
    found.set(did, hosts)
  }
  if (found.size > 1) throw new Error(`${webDid} points to more than one did:vh`)
  const [first] = found
  return first ? { did: first[0], hosts: [...new Set(first[1].filter(isDomainHost))] } : undefined
}

/**
 * Whom to believe when someone is addressed by a did:web.
 *  - Already known to be the shadow of a did:vh (`links`): only that did:vh counts, from its own log. The did:web is not asked at all,
 *    so a host that changes its document, or a did:vh that stops naming the did:web, does not end the relationship.
 *  - Its document points to a did:vh: that did:vh's log is fetched and verified, it must name the did:web, and the did:web document
 *    must be exactly what the log derives. Then it is remembered, and only the did:vh counts from here on. If any of that fails, the
 *    DID is refused: it does not fall back to the did:web document.
 *  - Its document points to none (a mail bridge, a mediator): the did:web document is believed as it is.
 * A did:vh (or anything else) is its own answer. null when nothing resolves.
 */
export async function resolveTrustedDid(did: string, context: DidResolveContext = {}): Promise<TrustedDid | null> {
  if (!did.startsWith('did:web:')) {
    const document = await resolveDidDocument(did, context)
    return document ? { did, document, linked: false } : null
  }
  const links = context.links ?? configured.links
  const pinned = links?.get(did)
  if (pinned) {
    const document = await resolveDidDocument(pinned, context)
    if (!document) throw new Error(`${did} is the shadow of ${pinned}, which does not resolve`)
    return { did: pinned, document, linked: true }
  }
  const web = await resolveDidWeb(did, context.fetch ?? fetch)
  if (!web) return null
  const pointer = vhPointerOf(did, web)
  if (!pointer) return { did, document: web, linked: false }
  for (const host of pointer.hosts) rememberVhLocation(pointer.did, host)
  const found = await fetchDidLog(pointer.did, context)
  if (!found?.document) throw new Error(`${did} points to ${pointer.did}, whose log was not found`)
  const check = checkDidWebShadow(found.document as unknown as Record<string, unknown>, did, web)
  if (!check.ok) throw new Error(`${did} points to ${pointer.did}, which does not confirm it: ${check.reason}`)
  ;(context.links ?? configured.links)?.set(did, pointer.did)
  return { did: pointer.did, document: found.document, linked: true }
}
