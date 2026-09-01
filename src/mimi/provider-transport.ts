/** Provider-to-provider HTTPS transport and mTLS-bound request identity. */

export interface MimiMtlsMaterial {
  cert: NonNullable<Bun.TLSOptions['cert']>
  key: NonNullable<Bun.TLSOptions['key']>
  /** Optional private CA bundle; without it Bun uses its normal trust store. */
  ca?: Bun.TLSOptions['ca']
}

export interface MimiProviderTransportOptions {
  /** Domain authenticated by this provider's client certificate. */
  sourceProviderDomain: string
  tls: MimiMtlsMaterial
  fetchImpl?: typeof fetch
}

export interface ProviderPost {
  path: string
  body: string | ArrayBuffer
  contentType?: string
  headers?: Headers | Record<string, string>
  signal?: AbortSignal
}

/** Identity observed after the TLS terminator authenticated the peer cert. */
export interface VerifiedProviderPeer {
  providerDomain: string
}

/**
 * Creates outbound requests required by MIMI draft §4.1.  TLS server identity
 * validation remains enabled and every request has the client certificate,
 * Host, and exact `From: mimi@<source-domain>` binding.
 */
export class MimiProviderTransport {
  private readonly sourceProviderDomain: string
  private readonly fetchImpl: typeof fetch
  private readonly tls: Bun.TLSOptions

  constructor(options: MimiProviderTransportOptions) {
    this.sourceProviderDomain = providerDomain(options.sourceProviderDomain)
    if (!options.tls.cert || !options.tls.key) throw new TypeError('provider mTLS requires a client certificate and key')
    this.fetchImpl = options.fetchImpl ?? fetch
    this.tls = { cert: options.tls.cert, key: options.tls.key, ...(options.tls.ca === undefined ? {} : { ca: options.tls.ca }), rejectUnauthorized: true }
  }

  async post(targetBaseUrl: string | URL, request: ProviderPost): Promise<Response> {
    const target = new URL(targetBaseUrl)
    if (target.protocol !== 'https:') throw new TypeError('provider transport requires an HTTPS target URL')
    if (target.username || target.password) throw new TypeError('provider target URL must not contain user info')
    const targetDomain = providerDomain(target.hostname)
    if (!request.path.startsWith('/') || request.path.startsWith('//')) throw new TypeError('provider request path must be an absolute path')
    const url = new URL(request.path, target)
    const headers = new Headers(request.headers)
    headers.set('content-type', request.contentType ?? 'application/json')
    headers.set('host', target.host)
    headers.set('from', `mimi@${this.sourceProviderDomain}`)
    return this.fetchImpl(url, { method: 'POST', headers, body: request.body, signal: request.signal, tls: this.tls })
  }
}

/** TLS settings for a Bun server which must reject unauthenticated providers. */
export function mimiProviderMtlsServerOptions(material: MimiMtlsMaterial): Bun.TLSOptions {
  if (!material.cert || !material.key) throw new TypeError('provider mTLS requires a server certificate and key')
  return { cert: material.cert, key: material.key, ...(material.ca === undefined ? {} : { ca: material.ca }), requestCert: true, rejectUnauthorized: true }
}

/**
 * Binds MIMI's HTTP-level source identity to the identity verified by mTLS.
 * The HTTPS listener (or a trusted TLS terminator) must supply `peer`; headers
 * alone are intentionally never considered authentication.
 */
export function verifyMimiProviderRequest(request: Request, targetProviderDomain: string, peer: VerifiedProviderPeer): { sourceProviderDomain: string } {
  const expectedTarget = providerDomain(targetProviderDomain)
  const host = request.headers.get('host')
  if (!host || hostDomain(host) !== expectedTarget) throw new TypeError('Host header does not identify this provider')
  const from = request.headers.get('from')
  if (!from) throw new TypeError('MIMI provider request requires a From header')
  const match = /^mimi@([A-Za-z0-9.-]+)$/.exec(from)
  if (!match) throw new TypeError('MIMI provider From header must be mimi@<provider-domain>')
  const sourceProviderDomain = providerDomain(match[1]!)
  if (sourceProviderDomain !== providerDomain(peer.providerDomain)) throw new TypeError('From header does not match the mTLS-authenticated provider')
  return { sourceProviderDomain }
}

function hostDomain(value: string): string {
  // Parse as an authority so non-standard ports are ignored for the identity
  // comparison, as required by draft §4.1.
  try { return providerDomain(new URL(`https://${value}`).hostname) } catch { throw new TypeError('Host header is not a provider domain') }
}

function providerDomain(value: string): string {
  const normalized = value.toLowerCase().replace(/\.$/, '')
  if (!normalized || normalized.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(normalized)) throw new TypeError('provider domain is invalid')
  return normalized
}
