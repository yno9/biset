import { describe, expect, test } from 'vitest'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { validateManifest } from '../src/server/mediator/v2-admin-settings.ts'
import { mediatorSettingDefs, openLiveMediatorLimits, type MediatorStart } from '../src/server/mediator/settings.ts'
import { createMediatorAdminApi } from '../src/server/mediator/admin-api.ts'
import { SqliteMediatorStore } from '../src/server/mediator/sqlite-store.ts'
import { IpRateLimiter } from '../src/server/mediator/rate-limit.ts'

const start: MediatorStart = { requestsPerMinute: 3000, newInboxesPerAddressPerHour: 60, limits: { maxInboxes: 30000, maxDevicesPerDid: 3, maxQueueItemsPerInbox: 1024, maxQueueBytesPerInbox: 64 * 1024 * 1024 } }
const manifest = JSON.parse(readFileSync(new URL('../src/server/mediator/admin.manifest.json', import.meta.url), 'utf8'))

describe('mediator and v2 admin', () => {
  test('the manifest is valid and its defaults and ranges are the code\'s', () => {
    expect(validateManifest(manifest).id).toBe('mediator')
    const defs = mediatorSettingDefs(start)
    expect(Object.keys(manifest.settings).sort()).toEqual(Object.keys(defs).sort())
    for (const [key, def] of Object.entries(defs)) {
      const m = manifest.settings[key]
      expect([key, m.type, m.default, m.min, m.max]).toEqual([key, def.type, def.default, def.min, def.max])
    }
  })

  test('a value set on the screen is in force; a bad one is not', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mediator-settings-'))
    const live = openLiveMediatorLimits(start, { dir, intervalMs: 0 })
    expect(live.requestsPerMinute()).toBe(3000)
    expect(live.registrationOpen()).toBe(true)
    writeFileSync(join(dir, 'mediator.json'), JSON.stringify({ version: 1, updatedAt: 1, values: { 'limits.requestsPerMinute': 10, 'registration.open': false, 'limits.maxInboxes': 0 } }))
    expect(live.requestsPerMinute()).toBe(10)
    expect(live.registrationOpen()).toBe(false)
    expect(live.storeLimits().maxInboxes).toBe(30000)
  })

  test('a rate limiter follows a number that changes; a store takes new limits only if they are legal together', () => {
    let max = 2
    const limiter = new IpRateLimiter(() => max)
    expect([limiter.allow('a', 1), limiter.allow('a', 2), limiter.allow('a', 3)]).toEqual([true, true, false])
    max = 3
    expect(limiter.allow('a', 4)).toBe(true)
    const store = SqliteMediatorStore.memory()
    store.setLimits({ maxInboxes: 5 })
    expect(store.limits.maxInboxes).toBe(5)
    expect(() => store.setLimits({ maxInboxes: 9, maxQueueBytesPerInbox: 1024 })).toThrow()
    expect(store.limits.maxInboxes).toBe(5) // nothing changed
  })

  test('the admin interface answers only the token', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'mediator-admin-'))
    const tokenFile = join(dir, 'token')
    const api = createMediatorAdminApi({ store: SqliteMediatorStore.memory(), tokenFile })
    const call = (path: string, token?: string) => api(new Request(`http://127.0.0.1${path}`, { headers: token ? { authorization: `Bearer ${token}` } : {} }), new URL(`http://127.0.0.1${path}`))
    expect(await call('/healthz')).toBeUndefined()
    expect((await call('/admin/metrics'))!.status).toBe(404)
    writeFileSync(tokenFile, 'tok\n')
    expect((await call('/admin/metrics', 'bad'))!.status).toBe(404)
    expect((await call('/admin/other', 'tok'))!.status).toBe(404)
    const body = await (await call('/admin/metrics', 'tok'))!.json() as { metrics: Record<string, { value: number }> }
    expect(body.metrics.inboxes!.value).toBe(0)
  })
})
