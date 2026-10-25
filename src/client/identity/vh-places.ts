// The places each did:vh was met at (protocol/did-resolve.ts `VhPlaces`), kept between page loads: for a DID written with a `src`
// (`did:vh:<SCID>?src=https://example.com/dids/issuer`) it is the only record of where its log is. Not secret; plain localStorage, and
// where that is unavailable the places last for the page. A few per DID, and the least recently met DIDs go first.
import type { VhPlaces } from '../../protocol/did-resolve.ts'

const KEY = 'biset.vh-places'
const PER_DID = 4
const MAX_DIDS = 500

export class StoredVhPlaces implements VhPlaces {
  private readonly places = new Map<string, string[]>()

  constructor(private readonly storage: Pick<Storage, 'getItem' | 'setItem'> | undefined = safeStorage()) {
    try {
      const parsed: unknown = JSON.parse(storage?.getItem(KEY) ?? '{}')
      if (typeof parsed === 'object' && parsed !== null) {
        for (const [did, list] of Object.entries(parsed)) {
          if (did.startsWith('did:vh:') && Array.isArray(list)) this.places.set(did, list.filter((place): place is string => typeof place === 'string').slice(-PER_DID))
        }
      }
    } catch { /* damaged: start empty, as a first visit */ }
  }

  get(did: string): readonly string[] { return this.places.get(did) ?? [] }

  add(did: string, place: string): void {
    const list = (this.places.get(did) ?? []).filter(known => known !== place)
    list.push(place)
    this.places.delete(did) // so the Map keeps the DIDs in the order they were last met
    this.places.set(did, list.slice(-PER_DID))
    while (this.places.size > MAX_DIDS) this.places.delete(this.places.keys().next().value!)
    try { this.storage?.setItem(KEY, JSON.stringify(Object.fromEntries(this.places))) } catch { /* kept for the page only */ }
  }
}

function safeStorage(): Storage | undefined {
  try { return globalThis.localStorage } catch { return undefined }
}
