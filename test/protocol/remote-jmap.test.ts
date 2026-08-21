import { describe, expect, test } from 'bun:test'
import { RemoteJmapTransport } from '../../src/local-jmap/remote.ts'

describe('RemoteJmapTransport', () => {
  test('discovers a standard JMAP session, calls its API, and expands blob URLs', async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = []
    const transport = new RemoteJmapTransport({
      discoveryUrl: 'https://mail.example/path-that-is-not-a-session',
      accountId: 'account/a',
      fetch: async (url, init) => {
        requests.push({ url: String(url), init })
        if (String(url) === 'https://mail.example/.well-known/jmap') {
          return Response.json({
            apiUrl: 'https://mail.example/jmap/api',
            downloadUrl: 'https://mail.example/download/{accountId}/{blobId}?type={type}&name={name}',
            capabilities: { 'urn:ietf:params:jmap:core': {} },
            accounts: { 'account/a': {} },
          })
        }
        if (String(url) === 'https://mail.example/jmap/api') {
          return Response.json({ methodResponses: [['Mailbox/get', { list: [] }, 'a']], sessionState: 'state-1' })
        }
        return new Response(new Uint8Array([1, 2, 3]), { status: 206 })
      },
    })

    expect((await transport.session()).apiUrl).toBe('https://mail.example/jmap/api')
    await expect(transport.call([{ name: 'Mailbox/get', arguments: {}, callId: 'a' }])).resolves.toMatchObject({ sessionState: 'state-1' })
    expect(await transport.download('blob / 1', { start: 10 })).toEqual(new Uint8Array([1, 2, 3]))

    expect(requests).toHaveLength(3)
    expect(requests[1].init?.body).toBe(JSON.stringify({ using: ['urn:ietf:params:jmap:core'], methodCalls: [['Mailbox/get', {}, 'a']] }))
    expect(requests[2].url).toBe('https://mail.example/download/account%2Fa/blob%20%2F%201?type=application%2Foctet-stream&name=blob')
    expect(new Headers(requests[2].init?.headers).get('Range')).toBe('bytes=10-')
  })

  test('rejects malformed discovery responses and failed HTTP results', async () => {
    const malformed = new RemoteJmapTransport({
      discoveryUrl: 'https://mail.example',
      accountId: 'account-a',
      fetch: async () => Response.json({ apiUrl: 'https://mail.example/jmap' }),
    })
    await expect(malformed.session()).rejects.toThrow('lacks API or download URL')

    const rejected = new RemoteJmapTransport({
      discoveryUrl: 'https://mail.example',
      accountId: 'account-a',
      fetch: async () => new Response('', { status: 503 }),
    })
    await expect(rejected.session()).rejects.toThrow('HTTP 503')
  })
})
