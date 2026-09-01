import { describe, expect, test } from 'bun:test'
import { MimiProviderTransport, mimiProviderMtlsServerOptions, verifyMimiProviderRequest } from '../../src/mimi/provider-transport.ts'

describe('MIMI provider transport', () => {
  test('binds outgoing HTTPS requests to the mTLS credential and provider headers', async () => {
    let observed: { url: URL; init: BunFetchRequestInit } | undefined
    const transport = new MimiProviderTransport({
      sourceProviderDomain: 'Source.Example.', tls: { cert: 'client-cert', key: 'client-key', ca: 'private-ca' },
      fetchImpl: async (input, init) => { observed = { url: new URL(input.toString()), init: init! }; return new Response('ok') },
    })
    expect((await transport.post('https://target.example:8443/base', { path: '/notify/a', body: '{}' })).status).toBe(200)
    expect(observed?.url.href).toBe('https://target.example:8443/notify/a')
    expect(new Headers(observed?.init.headers).get('host')).toBe('target.example:8443')
    expect(new Headers(observed?.init.headers).get('from')).toBe('mimi@source.example')
    expect(observed?.init.tls).toMatchObject({ cert: 'client-cert', key: 'client-key', ca: 'private-ca', rejectUnauthorized: true })
    await expect(transport.post('http://target.example', { path: '/notify/a', body: '{}' })).rejects.toThrow('HTTPS')
  })

  test('requires mTLS settings and binds From to the TLS-authenticated peer', () => {
    expect(mimiProviderMtlsServerOptions({ cert: 'server-cert', key: 'server-key', ca: 'private-ca' })).toMatchObject({ requestCert: true, rejectUnauthorized: true })
    const request = new Request('https://target.example/update/x', { headers: { host: 'target.example:9443', from: 'mimi@source.example' } })
    expect(verifyMimiProviderRequest(request, 'target.example', { providerDomain: 'source.example' })).toEqual({ sourceProviderDomain: 'source.example' })
    expect(() => verifyMimiProviderRequest(request, 'target.example', { providerDomain: 'attacker.example' })).toThrow('does not match')
    expect(() => verifyMimiProviderRequest(new Request('https://target.example/', { headers: { host: 'wrong.example', from: 'mimi@source.example' } }), 'target.example', { providerDomain: 'source.example' })).toThrow('Host')
  })
})
