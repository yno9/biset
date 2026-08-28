// Storage for did:web mirror documents (identity/web/mirror.ts) -- one
// did.json per subdomain, same shape as WebvhLogStore but for the derived
// did:web copy rather than the signed did:webvh log itself.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

const resourcePath = (dataDir: string, domain: string) => join(dataDir, '_web', domain, 'did.json')

export class DidWebStore {
  constructor(private dataDir: string) {}

  read(domain: string): string | null {
    try {
      return readFileSync(resourcePath(this.dataDir, domain), 'utf-8')
    } catch {
      return null
    }
  }

  write(domain: string, json: string): void {
    const path = resourcePath(this.dataDir, domain)
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    writeFileSync(path, json, { mode: 0o600 })
  }
}
