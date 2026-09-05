/** Resolves a remote MIMI provider's HTTPS origin from its domain, per spec
 * §5's `.well-known/mimi-protocol-directory` convention -- the same
 * directory this hub itself serves (directory.ts). Federation dispatch uses
 * this to find where to POST a `/notify` fanout: the identity domain
 * embedded in a `mimi://` URI is not assumed to equal the hub's actual HTTP
 * origin, so this always asks the domain rather than guessing `https://`
 * + domain directly. */
import { MIMI_PROTOCOL_DIRECTORY_PATH, type MimiProtocolDirectory } from './directory.ts'

export async function resolveMimiProviderBaseUrl(domain: string, fetchImpl: typeof fetch = fetch): Promise<string> {
  const response = await fetchImpl(`https://${domain}${MIMI_PROTOCOL_DIRECTORY_PATH}`)
  if (!response.ok) throw new Error(`could not fetch MIMI provider directory for ${domain} (${response.status})`)
  const directory = await response.json() as Partial<MimiProtocolDirectory>
  if (typeof directory.notify !== 'string') throw new TypeError(`MIMI provider directory for ${domain} is missing notify`)
  return new URL(directory.notify.replace('{roomId}', 'x')).origin
}
