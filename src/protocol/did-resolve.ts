// One way to resolve a DID document whatever its method. biset holds identities of two kinds: a did:vh (no host in the DID: its
// log is looked for where the contact is known by, or at a watcher), and the did:web document a did:vh publishes beside itself (a
// shadow, derived from the log; didmail's bridges are did:web too). Callers that only need "the document of this DID" call this
// and do not branch on the method themselves.
import type { DidDocument } from './vh/document.ts'
import { resolveDidWeb } from './didcomm/did-web.ts'
import { fetchVhResolution, type VhLogSources } from './vh/fetch.ts'
import type { LogEntry } from './vh/log.ts'
import { didWebCandidates, didWebDocumentUrl, verifiedAddress } from './vh/didweb.ts'
import type { VersionMemory } from './freshness.ts'

export interface DidResolveContext {
  fetch?: typeof fetch
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
}

let configured: DidResolution = {}
export function configureDidResolution(resolution: DidResolution): void { configured = resolution }

// Hosts a did:vh was met at (an address answered with it: `alice@did.md` is at `alice.did.md`), for the rest of the session.
// Only where to look: whatever is found there is verified like any other copy.
const metAt = new Map<string, Set<string>>()
export function rememberVhLocation(did: string, host: string): void {
  const hosts = metAt.get(did) ?? new Set<string>()
  hosts.add(host.toLowerCase())
  metAt.set(did, hosts)
}

function vhSources(did: string, context: DidResolveContext): VhLogSources {
  return {
    locations: [...(context.vh?.locations ?? []), ...(configured.locationsOf?.(did) ?? []), ...(metAt.get(did) ?? [])],
    watchers: [...(context.vh?.watchers ?? []), ...(configured.watchers ?? [])],
    fetch: context.fetch ?? fetch,
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
