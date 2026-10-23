import { describe, expect, test } from 'vitest'
import { createMediatorDeployment } from '../src/server/mediator/deployment.ts'

describe('the mediator\'s CORS answer', () => {
  async function ask(origin: string | undefined, allowed: string[]) {
    const deployment = await createMediatorDeployment({ publicUrl: 'http://127.0.0.1', databasePath: ':memory:', port: 0, log: () => {}, allowedOrigins: new Set(allowed) })
    try {
      return await fetch(`http://127.0.0.1:${deployment.server.port}/.well-known/did.json`, { headers: origin === undefined ? {} : { origin } })
    } finally { await deployment.shutdown('test') }
  }

  test('an allowed origin is echoed', async () => {
    const response = await ask('https://mail.did.md', ['https://mail.did.md'])
    expect(response.status).toBe(200)
    expect(response.headers.get('access-control-allow-origin')).toBe('https://mail.did.md')
  })

  test('a page that hides its origin (Origin: null, e.g. a Tor Browser onion page) gets *, the only value a browser accepts for it', async () => {
    const response = await ask('null', ['null'])
    expect(response.headers.get('access-control-allow-origin')).toBe('*')
  })

  test('an origin not allowed is refused', async () => {
    expect((await ask('https://evil.example', ['https://mail.did.md'])).status).toBe(403)
  })
})
