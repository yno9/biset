// routing.json storage for the subdomain-per-identity scheme, alongside
// webvh-store.ts's did.jsonl -- same one-key-per-domain shape, different
// file (routing.json instead of did.jsonl) and no append semantics (a
// routing.json PUT always replaces the whole document, see routing-http.ts).
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

const resourcePath = (dataDir: string, domain: string) => join(dataDir, '_webvh', domain, 'routing.json')

export class RoutingDocStore {
  constructor(private dataDir: string) {}

  /** Raw JSON text, or null if this domain has no routing.json yet. */
  read(domain: string): string | null {
    try {
      return readFileSync(resourcePath(this.dataDir, domain), 'utf-8')
    } catch {
      return null
    }
  }

  /** Overwrites the whole document. Callers verify the DataIntegrityProof
   * before calling this -- see routing-http.ts. */
  write(domain: string, json: string): void {
    const path = resourcePath(this.dataDir, domain)
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    writeFileSync(path, json, { mode: 0o600 })
  }
}
