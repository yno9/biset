import { describe, expect, test } from 'bun:test'
import { AnchorOidcPkceClient } from '../src/oidc/client.ts'

describe('AnchorOidcPkceClient popup ordering', () => {
  test('registers the wallet bridge listener before navigating the popup', async () => {
    let listenerRegistered = false
    let popupClosed = false
    let listener: ((event: MessageEvent<unknown>) => void) | undefined
    const eventTarget = {
      addEventListener(type: string, callback: EventListenerOrEventListenerObject) {
        if (type === 'message') {
          listenerRegistered = true
          listener = callback as (event: MessageEvent<unknown>) => void
        }
      },
      removeEventListener() { listener = undefined },
    }
    const popup = {
      closed: false,
      close() { popupClosed = true },
      location: {
        replace(value: string) {
          if (!listenerRegistered) throw new Error('listener was registered after popup navigation')
          const state = new URL(value).searchParams.get('state')!
          queueMicrotask(() => listener?.({
            origin: 'https://biset.md', source: popup,
            data: { type: 'biset.oidc.callback.v1', state, error: 'access_denied', errorDescription: 'test completed' },
          } as unknown as MessageEvent<unknown>))
        },
      },
    }
    const client = new AnchorOidcPkceClient({
      issuer: 'https://biset.md',
      clientId: 'biset-file-client',
      audience: 'https://coordinator.biset.md',
      allowedScopes: ['vault.pull'],
      wallet: {} as never,
      openPopup: () => popup as never,
      eventTarget: eventTarget as never,
      fetch: (async () => Response.json({
        issuer: 'https://biset.md',
        authorization_endpoint: 'https://biset.md/oauth/authorize',
        token_endpoint: 'https://biset.md/oauth/token',
        jwks_uri: 'https://biset.md/oauth/jwks',
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        subject_types_supported: ['pairwise'],
        id_token_signing_alg_values_supported: ['ES256'],
        token_endpoint_auth_methods_supported: ['none'],
        code_challenge_methods_supported: ['S256'],
        scopes_supported: ['openid', 'vault.pull'],
      })) as typeof fetch,
      timeoutMs: 60_000,
    })

    await expect(client.authorize()).rejects.toThrow('Anchor login failed: access_denied')
    expect(listenerRegistered).toBe(true)
    expect(popupClosed).toBe(true)
  })
})
