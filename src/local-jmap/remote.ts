import type { AccountTransport, JmapMethodCall, JmapSession } from './transport.ts'
import { defaultFetch } from '../net-fetch.ts'

export interface RemoteJmapTransportOptions {
  /** Provider origin or an explicit `/.well-known/jmap` URL. */
  discoveryUrl: string
  accountId: string
  fetch?: typeof fetch
  requestInit?: Omit<RequestInit, 'method' | 'body'>
}

interface JmapResponse {
  methodResponses: unknown[]
  sessionState: string
  [key: string]: unknown
}

/**
 * Standard JMAP transport for a conventional third-party account. It has no
 * dependency on Biset identity, MLS, or a local vault and can therefore keep
 * serving the client's pure-JMAP account mode during the migration.
 */
export class RemoteJmapTransport implements AccountTransport {
  private sessionValue: JmapSession | undefined
  private readonly fetchImpl: typeof fetch

  constructor(private readonly options: RemoteJmapTransportOptions) {
    if (!options.accountId) throw new TypeError('remote JMAP accountId is required')
    this.fetchImpl = options.fetch ?? defaultFetch()
  }

  async session(): Promise<JmapSession> {
    if (this.sessionValue) return this.sessionValue
    const response = await this.fetchImpl(normalizeDiscoveryUrl(this.options.discoveryUrl), {
      ...this.options.requestInit,
      method: 'GET',
      headers: acceptJson(this.options.requestInit?.headers),
    })
    if (!response.ok) throw new Error(`JMAP session discovery failed: HTTP ${response.status}`)
    const value = await response.json()
    assertSession(value)
    this.sessionValue = value
    return value
  }

  async call<T>(methodCalls: JmapMethodCall[]): Promise<T> {
    const session = await this.session()
    const response = await this.fetchImpl(session.apiUrl, {
      ...this.options.requestInit,
      method: 'POST',
      headers: contentTypeJson(this.options.requestInit?.headers),
      body: JSON.stringify({
        using: Object.keys(session.capabilities),
        methodCalls: methodCalls.map(call => [call.name, call.arguments, call.callId]),
      }),
    })
    if (!response.ok) throw new Error(`JMAP API call failed: HTTP ${response.status}`)
    const value = await response.json()
    if (!isJmapResponse(value)) throw new TypeError('JMAP API returned an invalid response')
    return value as T
  }

  async download(blobId: string, range?: { start: number; end?: number }): Promise<Uint8Array> {
    if (!blobId) throw new TypeError('JMAP blobId is required')
    if (range && (!Number.isSafeInteger(range.start) || range.start < 0 || (range.end !== undefined && (!Number.isSafeInteger(range.end) || range.end < range.start)))) {
      throw new TypeError('invalid JMAP download range')
    }
    const session = await this.session()
    const headers = new Headers(this.options.requestInit?.headers)
    headers.set('Accept', 'application/octet-stream')
    if (range) headers.set('Range', `bytes=${range.start}-${range.end ?? ''}`)
    const response = await this.fetchImpl(expandDownloadUrl(session.downloadUrl, this.options.accountId, blobId), {
      ...this.options.requestInit,
      method: 'GET',
      headers,
    })
    if (!response.ok) throw new Error(`JMAP download failed: HTTP ${response.status}`)
    return new Uint8Array(await response.arrayBuffer())
  }
}

function normalizeDiscoveryUrl(value: string): string {
  const url = new URL(value)
  if (url.pathname.endsWith('/.well-known/jmap')) return url.toString()
  url.pathname = '/.well-known/jmap'
  url.search = ''
  url.hash = ''
  return url.toString()
}

function assertSession(value: unknown): asserts value is JmapSession {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('JMAP session must be an object')
  const session = value as Record<string, unknown>
  if (typeof session.apiUrl !== 'string' || typeof session.downloadUrl !== 'string') throw new TypeError('JMAP session lacks API or download URL')
  if (session.capabilities === null || typeof session.capabilities !== 'object' || Array.isArray(session.capabilities)) throw new TypeError('JMAP session lacks capabilities')
  if (session.accounts === null || typeof session.accounts !== 'object' || Array.isArray(session.accounts)) throw new TypeError('JMAP session lacks accounts')
}

function isJmapResponse(value: unknown): value is JmapResponse {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Array.isArray((value as Record<string, unknown>).methodResponses)
    && typeof (value as Record<string, unknown>).sessionState === 'string'
}

function acceptJson(headers: HeadersInit | undefined): Headers {
  const result = new Headers(headers)
  result.set('Accept', 'application/json')
  return result
}

function contentTypeJson(headers: HeadersInit | undefined): Headers {
  const result = acceptJson(headers)
  result.set('Content-Type', 'application/json')
  return result
}

function expandDownloadUrl(template: string, accountId: string, blobId: string): string {
  return template
    .replace('{accountId}', encodeURIComponent(accountId))
    .replace('{blobId}', encodeURIComponent(blobId))
    .replace('{type}', encodeURIComponent('application/octet-stream'))
    .replace('{name}', encodeURIComponent('blob'))
}
