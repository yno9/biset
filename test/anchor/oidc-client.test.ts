import { describe, expect, test } from 'bun:test'
import { p256 } from '@noble/curves/nist.js'
import { AnchorOidcProvider, MemoryAnchorAuthorizationCodeStore } from '../../src/anchor/oidc.ts'
import { AnchorOidcPkceClient } from '../../src/oidc/client.ts'
import type { BisetOid4vpWallet } from '../../src/oid4vp/wallet.ts'

const issuer = 'https://anchor.test'
const audience = 'https://coordinator.test'
const scopes = ['vault.create', 'vault.group.install', 'vault.append', 'vault.pull', 'vault.ack'] as const

describe('file Client OIDC Code + PKCE', () => {
  test('exchanges an exact popup callback and verifies the ID/access token signatures and claims', async () => {
    const provider = new AnchorOidcProvider({
      issuer,
      clients: [{ clientId: 'biset-client', redirectUris: [`${issuer}/oauth/client-callback`], sectorIdentifier: 'biset-client', audience, allowedScopes: [...scopes] }],
      authenticator: { authenticate: async () => ({ subject: 'root-account', generation: `1-${'a'.repeat(32)}` }) },
      codes: new MemoryAnchorAuthorizationCodeStore(),
      signingPrivateKey: p256.utils.randomSecretKey(),
      pairwiseSecret: new Uint8Array(32).fill(7),
    })
    const events = new FakeMessageTarget()
    let authorizationUrl = ''
    const popup = {
      closed: false,
      location: {
        replace(value: string) {
          authorizationUrl = value
          setTimeout(async () => {
            const response = await provider.authorize(new Request(value))
            const callback = new URL(response.headers.get('location')!)
            events.dispatch({
              origin: issuer,
              source: popup as unknown as Window,
              data: { type: 'biset.oidc.callback.v1', state: callback.searchParams.get('state'), code: callback.searchParams.get('code') },
            })
          }, 0)
        },
      },
      close() { this.closed = true },
    }
    const fetchImpl: typeof fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init)
      const path = new URL(request.url).pathname
      if (path === '/.well-known/openid-configuration') return Response.json(provider.metadata())
      if (path === '/oauth/jwks') return Response.json(provider.jwks())
      if (path === '/oauth/token') return provider.token(request)
      return new Response('not found', { status: 404 })
    }
    let savedRefreshToken: string | undefined
    const wallet = {
      async refreshToken() { return savedRefreshToken },
      async saveRefreshToken(_clientId: string, value: string) { savedRefreshToken = value },
      async clearRefreshToken() { savedRefreshToken = undefined },
    } as BisetOid4vpWallet
    const client = new AnchorOidcPkceClient({
      issuer, clientId: 'biset-client', audience, allowedScopes: [...scopes],
      wallet,
      fetch: fetchImpl,
      openPopup: () => popup as unknown as Window,
      eventTarget: events,
      timeoutMs: 2_000,
    })

    await expect(client.getAccessToken('vault.pull')).rejects.toThrow('interaction is required')
    const token = await client.authorize()
    expect(token.split('.')).toHaveLength(3)
    expect(new URL(authorizationUrl).searchParams.get('code_challenge_method')).toBe('S256')
    expect(new URL(authorizationUrl).searchParams.get('redirect_uri')).toBe(`${issuer}/oauth/client-callback`)
    expect(popup.closed).toBeTrue()
    expect(await client.getAccessToken('vault.append')).toBe(token)
    expect(savedRefreshToken).toHaveLength(43)
  })
})

class FakeMessageTarget {
  private readonly listeners = new Set<EventListener>()
  addEventListener(_type: string, listener: EventListenerOrEventListenerObject): void { this.listeners.add(listener as EventListener) }
  removeEventListener(_type: string, listener: EventListenerOrEventListenerObject): void { this.listeners.delete(listener as EventListener) }
  dispatch(value: Pick<MessageEvent, 'origin' | 'source' | 'data'>): void {
    for (const listener of this.listeners) listener(value as MessageEvent)
  }
}
