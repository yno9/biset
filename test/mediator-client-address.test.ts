// Which address the mediator's limits are kept by: the entry the trusted proxy wrote into X-Forwarded-For, never one the client
// wrote in front of it.
import { describe, expect, test } from 'vitest'
import { createMediatorDeployment } from '../src/server/mediator/deployment.ts'

async function statuses(headers: (index: number) => Record<string, string>, options: { trustedProxyHops?: number } = {}): Promise<number[]> {
  const deployment = await createMediatorDeployment({ publicUrl: 'http://127.0.0.1', databasePath: ':memory:', port: 0, log: () => {}, rateLimitPerMinute: 2, ...options })
  try {
    const result: number[] = []
    for (let index = 0; index < 4; index++) {
      const response = await fetch(`http://127.0.0.1:${deployment.server.port}/`, { method: 'POST', headers: { 'content-type': 'application/didcomm-encrypted+json', ...headers(index) }, body: '{}' })
      result.push(response.status)
    }
    return result
  } finally { await deployment.shutdown('test') }
}

describe('the client address behind a reverse proxy', () => {
  test('a client that writes a new X-Forwarded-For each time is still limited by the address the proxy appended', async () => {
    const seen = await statuses(index => ({ 'x-forwarded-for': `10.0.0.${index}, 203.0.113.7` }))
    expect(seen.slice(2)).toEqual([429, 429])
  })

  test('different clients, as the proxy saw them, are limited apart', async () => {
    const seen = await statuses(index => ({ 'x-forwarded-for': `203.0.113.${index}` }))
    expect(seen).not.toContain(429)
  })

  test('with no trusted proxy the header is ignored', async () => {
    const seen = await statuses(index => ({ 'x-forwarded-for': `203.0.113.${index}` }), { trustedProxyHops: 0 })
    expect(seen.slice(2)).toEqual([429, 429])
  })
})
