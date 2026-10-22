// The numbers v2 admin can change while the mediator runs (ops/admin.manifest.json lists them, with their ranges). Each starts from
// what the MEDIATOR_* environment gave (index.ts); a value set on the screen replaces it; with no admin the environment's stand.
import { openSettings, type SettingDef } from './v2-admin-settings.ts'
import type { LiveMediatorLimits } from './deployment.ts'
import type { SqliteMediatorLimits } from './sqlite-store.ts'

export interface MediatorStart {
  requestsPerMinute: number
  newInboxesPerAddressPerHour: number
  limits: Pick<SqliteMediatorLimits, 'maxInboxes' | 'maxDevicesPerDid' | 'maxQueueItemsPerInbox' | 'maxQueueBytesPerInbox'>
}

export function mediatorSettingDefs(start: MediatorStart): Record<string, SettingDef> {
  return {
    'registration.open': { type: 'boolean', default: true },
    'registration.newInboxesPerAddressPerHour': { type: 'integer', default: start.newInboxesPerAddressPerHour, min: 1, max: 1000000 },
    'limits.maxInboxes': { type: 'integer', default: start.limits.maxInboxes, min: 1, max: 10000000 },
    'limits.maxDevicesPerDid': { type: 'integer', default: start.limits.maxDevicesPerDid, min: 1, max: 64 },
    'limits.requestsPerMinute': { type: 'integer', default: start.requestsPerMinute, min: 1, max: 1000000 },
    'limits.maxQueueItemsPerInbox': { type: 'integer', default: start.limits.maxQueueItemsPerInbox, min: 1, max: 100000 },
    'limits.maxQueueBytesPerInbox': { type: 'integer', default: start.limits.maxQueueBytesPerInbox, min: 1048576, max: 1073741824 },
  }
}

export function openLiveMediatorLimits(start: MediatorStart, options: { dir?: string; intervalMs?: number; onProblem?: (message: string) => void } = {}): LiveMediatorLimits {
  const settings = openSettings({ service: 'mediator', settings: mediatorSettingDefs(start), ...options })
  const n = (key: string) => settings.get(key) as number
  return {
    requestsPerMinute: () => n('limits.requestsPerMinute'),
    newInboxesPerAddressPerHour: () => n('registration.newInboxesPerAddressPerHour'),
    registrationOpen: () => settings.get('registration.open') as boolean,
    storeLimits: () => ({ maxInboxes: n('limits.maxInboxes'), maxDevicesPerDid: n('limits.maxDevicesPerDid'), maxQueueItemsPerInbox: n('limits.maxQueueItemsPerInbox'), maxQueueBytesPerInbox: n('limits.maxQueueBytesPerInbox') }),
  }
}
