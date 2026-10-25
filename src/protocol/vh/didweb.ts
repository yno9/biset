// did:web as a shadow of did:vh (dito PLAN-didvh.md §1.2). did:vh is the identity; a did:web DID names a web location, so it
// serves where a did:web is expected, but it is only as good as the host that serves it (no hash chain, witnesses, watchers).
// Its document is therefore *derived* from the latest did:vh document: every `did:vh:<SCID>` becomes the did:web DID, and
// `alsoKnownAs` becomes `[did:vh:<SCID>?src=<the location>]` and nothing else. A did:web document is accepted as that shadow only if it equals
// the derivation, *and* the did:vh document names the did:web DID: a link in both directions. Checked against the same
// vectors as dito's packages/vh (test/fixtures/did-vh-vectors.json).
import { canonicalize } from './jcs.ts'

type Document = Record<string, unknown>

function replaceDid(value: unknown, vhDid: string, webDid: string): unknown {
  if (typeof value === 'string') {
    if (value === vhDid) return webDid
    return value.startsWith(vhDid) && /^[#?/]/.test(value.slice(vhDid.length)) ? webDid + value.slice(vhDid.length) : value
  }
  if (Array.isArray(value)) return value.map(item => replaceDid(item, vhDid, webDid))
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replaceDid(item, vhDid, webDid)]))
  return value
}

/** The web location a did:web DID names (`did:web:alice.did.md` is `https://alice.did.md`). */
function srcOfDidWeb(webDid: string): string {
  const parts = webDid.split(':')
  if (parts[0] !== 'did' || parts[1] !== 'web' || parts.length < 3 || parts.some(part => part === '')) throw new Error('Not a did:web DID.')
  try { return ['https://' + decodeURIComponent(parts[2]!), ...parts.slice(3).map(decodeURIComponent)].join('/') } catch { throw new Error('Not a did:web DID.') }
}

/** `did:vh:<scid>?src=<location>`: only what would end the value early is escaped. */
function srcAlias(did: string, src: string): string {
  return `${did}?src=${src.replace(/\/+$/, '').replace(/[%&=#+\s]/g, character => `%${character.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`)}`
}

/** The did:web document derived from a did:vh document. */
function deriveDidWebDocument(vhDocument: Document, webDid: string): Document {
  const vhDid = vhDocument.id
  if (typeof vhDid !== 'string' || !vhDid.startsWith('did:vh:')) throw new Error('Not a did:vh document.')
  const { alsoKnownAs: _dropped, ...rest } = replaceDid(vhDocument, vhDid, webDid) as Document
  return { ...rest, alsoKnownAs: [srcAlias(vhDid, srcOfDidWeb(webDid))] }
}

export type ShadowCheck = { ok: true } | { ok: false; reason: string }

/** Whether `webDocument` (fetched for `webDid`) is a faithful shadow of the verified, latest did:vh document. */
export function checkDidWebShadow(vhDocument: Document, webDid: string, webDocument: unknown): ShadowCheck {
  const links = Array.isArray(vhDocument.alsoKnownAs) ? vhDocument.alsoKnownAs : []
  if (!links.includes(webDid)) return { ok: false, reason: `The did:vh document does not name ${webDid} in alsoKnownAs.` }
  if (!webDocument || typeof webDocument !== 'object' || Array.isArray(webDocument)) return { ok: false, reason: 'The did:web document is not an object.' }
  let expected: Document
  try { expected = deriveDidWebDocument(vhDocument, webDid) } catch (error) { return { ok: false, reason: (error as Error).message } }
  if (canonicalize(expected) !== canonicalize(webDocument)) return { ok: false, reason: 'The did:web document is not what the did:vh document derives.' }
  return { ok: true }
}

/** The plain-host did:web DIDs a did:vh document names (`did:web:alice.did.md`; not one with a port or a path): the candidates to fetch. */
export function didWebCandidates(vhDocument: Document): string[] {
  const links = Array.isArray(vhDocument.alsoKnownAs) ? vhDocument.alsoKnownAs : []
  return links.filter((link): link is string => typeof link === 'string' && /^did:web:[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(link))
}

/** `https://<host>/.well-known/did.json`: where the shadow of a plain-host did:web DID is. */
export function didWebDocumentUrl(webDid: string): string {
  const match = /^did:web:([a-z0-9-]+(?:\.[a-z0-9-]+)+)$/.exec(webDid)
  if (!match) throw new Error('Not a plain-host did:web DID.')
  return `https://${match[1]}/.well-known/did.json`
}

/**
 * The mail-style address a verified did:vh identity goes by: `alice@did.md` for `did:web:alice.did.md`, once the shadow is
 * confirmed in both directions. undefined when it is not (the DID is then shown as it is; an address is never invented).
 */
export function verifiedAddress(vhDocument: Document, webDid: string, webDocument: unknown): string | undefined {
  if (!checkDidWebShadow(vhDocument, webDid, webDocument).ok) return undefined
  // `name.apex`, the apex itself at least two labels (`alice.did.md`): a host of two labels (`example.com`) has no name in it.
  const host = /^did:web:([a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9.-]+)$/.exec(webDid)?.[1]
  const dot = host ? host.indexOf('.') : -1
  return host && dot > 0 ? `${host.slice(0, dot)}@${host.slice(dot + 1)}` : undefined
}
