import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createBisetAnchorDeployment } from '../../src/anchor/deployment.ts'

function withAnchor<T>(run: (fetch: (request: Request) => Promise<Response>) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'biset-anchor-test-'))
  const anchor = createBisetAnchorDeployment({ dataDir: dir })
  return run(anchor.fetch).finally(() => rmSync(dir, { recursive: true, force: true }))
}

describe('biset-anchor application boundary', () => {
  test('identifies itself as a public identity service', () => withAnchor(async fetch => {
    const response = await fetch(new Request('https://anchor.test/healthz'))
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({
      ok: true,
      service: 'biset-anchor',
      storage: 'public-identity-only',
    })
  }))

  test('does not expose core relay, MLS, mail, roster, or DIDComm paths', () => withAnchor(async fetch => {
    for (const path of [
      '/v1/vault-delivery/pull',
      '/v1/mls/messages',
      '/v1/mail/submit',
      '/v1/roster/install',
      '/v1/didcomm/ingress',
    ]) {
      const response = await fetch(new Request(`https://anchor.test${path}`, { method: 'POST' }))
      expect(response.status).toBe(404)
    }
  }))

  test('owns the public well-known routes', () => withAnchor(async fetch => {
    for (const path of [
      '/.well-known/did.jsonl',
      '/.well-known/did.json',
      '/.well-known/routing.json',
    ]) {
      const response = await fetch(new Request(`https://anchor.test${path}`, {
        headers: { 'x-biset-domain': 'anchor.test' },
      }))
      expect(response.status).toBe(404)
      expect(response.headers.get('access-control-allow-origin')).toBe('*')
    }
  }))
})
