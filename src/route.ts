// Conversation-permalink hash segment encoding.
//
// Its own module (rather than living in utils.ts) so the Service Worker can
// build the exact same permalink for a notification's click target without
// dragging utils.ts's contact-store / DID dependencies — and openpgp behind
// them — into the sw.js bundle.
//
// `@` and `:` are left literal: an address or a DID reads as itself in the
// URL bar, and both are legal in a fragment.
export function hashSeg(s: string): string {
  return encodeURIComponent(s).replace(/%40/g, '@').replace(/%3A/gi, ':')
}

export function unhashSeg(s: string): string {
  try { return decodeURIComponent(s) } catch { return s }
}
