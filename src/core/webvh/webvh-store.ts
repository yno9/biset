// did:webvh log storage for the subdomain-per-identity scheme
// (identity/webvh/identifier.ts: did:webvh:{scid}:{domain}, no pathSegments).
// Ported from the pre-Vault-Core anchor's webvh-store.ts, dropped down to one
// key (`domain`) instead of (domain, username) -- a subdomain already names
// exactly one identity, so there is no separate username axis here.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

const resourcePath = (dataDir: string, domain: string) => join(dataDir, '_webvh', domain, 'did.jsonl')

export class WebvhLogStore {
  constructor(private dataDir: string) {}

  /** Raw JSONL text, or null if this domain has no log yet. */
  read(domain: string): string | null {
    try {
      return readFileSync(resourcePath(this.dataDir, domain), 'utf-8')
    } catch {
      return null
    }
  }

  /** Overwrites the whole log. Callers verify the new content resolves
   * before calling this -- see webvh-http.ts. */
  write(domain: string, jsonl: string): void {
    const path = resourcePath(this.dataDir, domain)
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    writeFileSync(path, jsonl, { mode: 0o600 })
  }
}

export function ensureWebvhDataDir(dataDir: string): void {
  const dir = join(dataDir, '_webvh')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 })
}
