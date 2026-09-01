/**
 * Safe hub-side direct asset proxy: never turn the MIMI hub into an open
 * proxy.  This implements the authenticated `proxyDownload` path, but is
 * deliberately **not** an RFC 9458 OHTTP Gateway: it receives a plain HTTPS
 * request from the peer provider and therefore cannot provide OHTTP's relay /
 * gateway unlinkability.  No OHTTP configuration endpoint or capability is
 * advertised by this deployment.
 *
 * draft-ietf-mimi-protocol-06 §5.10.3 makes a gateway required for a fully
 * conformant hub.  Biset scopes that optional deployment role out until it
 * can be supplied with a real OHTTP gateway, peer-asset registration, and
 * relay integration; operators must not describe this class as OHTTP-capable.
 */
export interface MimiAssetProxyOptions {
  allowedAssetHosts: readonly string[]
  fetchImpl?: typeof fetch
  maxBytes?: number
}

export class MimiAssetProxy {
  private readonly hosts: Set<string>
  private readonly fetchImpl: typeof fetch
  private readonly maxBytes: number

  constructor(options: MimiAssetProxyOptions) {
    this.hosts = new Set(options.allowedAssetHosts.map(host => host.toLowerCase()))
    if (this.hosts.size === 0) throw new TypeError('at least one asset host must be configured')
    for (const host of this.hosts) validHost(host)
    this.fetchImpl = options.fetchImpl ?? fetch
    this.maxBytes = options.maxBytes ?? 25 * 1024 * 1024
    if (!Number.isSafeInteger(this.maxBytes) || this.maxBytes < 1) throw new TypeError('asset proxy maximum size is invalid')
  }

  async download(downloadUrl: string): Promise<Response> {
    const target = new URL(downloadUrl)
    if (target.protocol !== 'https:' || target.username || target.password || !this.hosts.has(target.hostname.toLowerCase())) throw new TypeError('asset URL is not an allowed HTTPS asset host')
    const response = await this.fetchImpl(target, { method: 'GET', redirect: 'error' })
    if (!response.ok) return new Response(null, { status: response.status })
    const length = Number(response.headers.get('content-length') ?? 0)
    if (!Number.isFinite(length) || length > this.maxBytes) throw new RangeError('asset exceeds proxy size limit')
    const bytes = new Uint8Array(await response.arrayBuffer())
    if (bytes.length > this.maxBytes) throw new RangeError('asset exceeds proxy size limit')
    return new Response(bytes, { status: 200, headers: { 'content-type': response.headers.get('content-type') ?? 'application/octet-stream', 'content-length': String(bytes.length), 'cache-control': 'private, max-age=300' } })
  }
}

function validHost(host: string): void {
  if (host !== host.toLowerCase() || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host)) throw new TypeError('asset host is invalid')
}
