// did:webvh log storage — backs GET/PUT <domain>/dids/<username>/did.jsonl
// (PLANWEBVH.md §2.1/§2.3: SCID persistence + did.jsonl distribution both
// live in the anchor, same reasoning as pkarr.ts's gateway — DID⊥relay
// orthogonality, and the same "plain file per name" shape as store.ts's
// ClaimStore). Domain is part of the storage key because biset runs two
// domains off one anchor process (biset.md gated, t.biset.md open) and a
// username is only unique within its own domain.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

const resourcePath = (dataDir: string, domain: string, username: string, filename: string) =>
  join(dataDir, '_webvh', domain, username, filename)

export class WebvhLogStore {
  constructor(private dataDir: string) {}

  /** Raw JSONL text, or null if this domain+username has no log yet. */
  read(domain: string, username: string): string | null {
    try {
      return readFileSync(resourcePath(this.dataDir, domain, username, 'did.jsonl'), 'utf-8')
    } catch {
      return null
    }
  }

  /** Overwrites the whole log. Callers are responsible for having read
   * the previous version first (publish.ts's updateDocument does a
   * read-modify-write) — this store has no append/CAS semantics of its own
   * (PLANWEBVH.md §6 remaining infra work). */
  write(domain: string, username: string, jsonl: string): void {
    const path = resourcePath(this.dataDir, domain, username, 'did.jsonl')
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    writeFileSync(path, jsonl, { mode: 0o600 })
  }

  /** did/webvh/routing.ts's sibling resource — volatile connectivity data
   * (mediatorUrl/routingKey, relay endpoints) that a did:webvh log entry no
   * longer carries (that file's own note has the why). Same per-(domain,
   * username) directory as did.jsonl, different filename, no history: a PUT
   * here always overwrites, there being nothing to preserve. */
  readRouting(domain: string, username: string): string | null {
    try {
      return readFileSync(resourcePath(this.dataDir, domain, username, 'routing.json'), 'utf-8')
    } catch {
      return null
    }
  }

  writeRouting(domain: string, username: string, json: string): void {
    const path = resourcePath(this.dataDir, domain, username, 'routing.json')
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    writeFileSync(path, json, { mode: 0o600 })
  }
}
