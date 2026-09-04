import { describe, expect, test } from 'bun:test'
import { oidcClientCallback, oidcClientCallbackScript } from '../../src/anchor/oidc-client-callback.ts'

describe('file Client OIDC callback bridge', () => {
  test('serves a script-only no-store callback that reports only to its opener', async () => {
    const page = oidcClientCallback()
    expect(page.status).toBe(200)
    expect(page.headers.get('cache-control')).toBe('no-store')
    expect(page.headers.get('content-security-policy')).toContain("default-src 'none'")
    expect(await page.text()).toContain('/oauth/client-callback.js')

    const script = oidcClientCallbackScript()
    const body = await script.text()
    expect(script.headers.get('referrer-policy')).toBe('no-referrer')
    expect(body).toContain('biset.oidc.callback.v1')
    expect(body).toContain('window.opener.postMessage')
  })
})
