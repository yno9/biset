// Did the Wallet publish what this browser asked for? A document edit's `services` are
// requested either as a whole ("replace": the published service must BE the requested one)
// or as endpoints to add ("merge": the published service must CONTAIN them -- it may hold
// more, put there by another device -- and never carries the request-only `endpointMode`).
// `removeEndpoints` asks for every endpoint matching `match` to be gone. These are the
// semantics of did.md Wallet's document-edit contract, checked here from the published
// document alone.

type Endpoint = string | Record<string, unknown>
export type RequestedService = { id: string; type?: string; serviceEndpoint?: Endpoint | Endpoint[]; endpointMode?: 'replace' | 'merge' }
export type PublishedService = { id: string; type?: string; serviceEndpoint?: Endpoint | Endpoint[] }
export type EndpointRemoval = { serviceId: string; match: Record<string, unknown> }

const endpoints = (value: Endpoint | Endpoint[] | undefined): Endpoint[] => value === undefined ? [] : Array.isArray(value) ? value : [value]

/** JSON with object keys sorted, so two documents that differ only in key order compare equal. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`
  return JSON.stringify(value) ?? 'null'
}

export function serviceIsPublished(published: PublishedService | undefined, requested: RequestedService): boolean {
  if (!published) return false
  const { endpointMode, ...wanted } = requested
  if (endpointMode !== 'merge') return canonical(published) === canonical(wanted)
  const present = endpoints(published.serviceEndpoint).map(canonical)
  return published.type === wanted.type && endpoints(wanted.serviceEndpoint).every(endpoint => present.includes(canonical(endpoint)))
}

/** True when no endpoint of the published service matches every property of the removal (a string endpoint has only `uri`). */
export function endpointsAreRemoved(published: PublishedService | undefined, removal: EndpointRemoval): boolean {
  return !endpoints(published?.serviceEndpoint).some(endpoint => {
    const properties: Record<string, unknown> = typeof endpoint === 'string' ? { uri: endpoint } : endpoint
    const keys = Object.keys(removal.match)
    return keys.length > 0 && keys.every(key => key in properties && canonical(properties[key]) === canonical(removal.match[key]))
  })
}
