// Which did:vh each did:web was found to be the shadow of (protocol/did-resolve.ts `resolveTrustedDid`), kept between page loads. A
// did:web only leads to its did:vh the first time; from then on the did:vh is the only thing believed about that person, so this
// has to outlast the page. Not secret; plain localStorage, and where that is unavailable the links last for the page.
import type { DidLinks } from '../../protocol/did-resolve.ts'

const KEY = 'biset.did-links'

export class StoredDidLinks implements DidLinks {
  private readonly links = new Map<string, string>()

  constructor(private readonly storage: Pick<Storage, 'getItem' | 'setItem'> | undefined = safeStorage()) {
    try {
      const parsed: unknown = JSON.parse(storage?.getItem(KEY) ?? '{}')
      if (typeof parsed === 'object' && parsed !== null) for (const [web, vh] of Object.entries(parsed)) if (typeof vh === 'string' && web.startsWith('did:web:') && vh.startsWith('did:vh:')) this.links.set(web, vh)
    } catch { /* damaged: start empty, as a first visit */ }
  }

  get(webDid: string): string | undefined { return this.links.get(webDid) }

  set(webDid: string, vhDid: string): void {
    this.links.set(webDid, vhDid)
    try { this.storage?.setItem(KEY, JSON.stringify(Object.fromEntries(this.links))) } catch { /* kept for the page only */ }
  }
}

function safeStorage(): Storage | undefined {
  try { return globalThis.localStorage } catch { return undefined }
}
