// Mirrors a did:webvh identity's CURRENT state to a plain did:web document at
// the same subdomain — no verifiable history, no proof, just the resolved
// document under a different DID so did:web-only verifiers (Bluesky's
// atproto handling among them) can read the same keys without speaking
// did:webvh at all. Re-derived from the webvh state on every write that
// changes it (genesis, device-key registration, ...) rather than
// incrementally patched, since a did:web document carries no history to
// patch against — it is always a full overwrite of "whatever webvh
// currently says."
import { didWebToHttpsUrl, buildWebDid } from './identifier.ts'
import type { SignedWebvhState } from '../webvh/document.ts'
import { defaultFetch } from '../../app/net-fetch.ts'

export interface SyncDidWebMirrorOptions {
  /** The did:webvh identity's own domain segment (`y.biset.md`) — reused
   * as-is for the did:web mirror, since both name the same subdomain. */
  domain: string
  fetch?: typeof fetch
}

/** Rewrites every occurrence of `webvhDid` in the state to `did:web:{domain}`
 * — id, controller, and every verificationMethod/authentication DID URL —
 * via one whole-document string replace (the same approach create-genesis.ts
 * uses to substitute its SCID placeholder). */
export function buildDidWebMirrorDocument(webvhDid: string, domain: string, state: SignedWebvhState): SignedWebvhState {
  const webDid = buildWebDid(domain)
  return JSON.parse(JSON.stringify(state).split(webvhDid).join(webDid)) as SignedWebvhState
}

export async function syncDidWebMirror(webvhDid: string, state: SignedWebvhState, opts: SyncDidWebMirrorOptions): Promise<void> {
  const mirrored = buildDidWebMirrorDocument(webvhDid, opts.domain, state)
  const fetchImpl = opts.fetch ?? defaultFetch()
  const response = await fetchImpl(didWebToHttpsUrl(buildWebDid(opts.domain)), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(mirrored),
  })
  if (!response.ok) throw new Error(`syncDidWebMirror: PUT failed with HTTP ${response.status} ${await response.text().catch(() => '')}`)
}
