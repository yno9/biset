/** Parses the provider (authority) component out of a `mimi://` URI --
 * `mimi://a.example/u/alice`, `mimi://a.example/r/clubhouse`, etc. (spec
 * line 344-352). protocol-types.ts keeps `MimiRoomId`/`MimiUserUri`
 * deliberately opaque strings at that boundary; only federation code needs
 * to parse the provider domain back out of one. */
export function mimiUriProviderDomain(uri: string): string {
  let parsed: URL
  try { parsed = new URL(uri) } catch { throw new TypeError(`not a mimi:// URI: ${uri}`) }
  if (parsed.protocol !== 'mimi:' || !parsed.hostname) throw new TypeError(`not a mimi:// URI: ${uri}`)
  return parsed.hostname.toLowerCase()
}
