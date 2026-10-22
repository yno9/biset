// GENERATED from v2 admin (7b50f63): src/manifest/index.ts and src/client-lib/index.ts, joined. Do not edit here; run
// `node scripts/vendor.mjs <this file>` in the admin repository. What a service uses: openSettings (reads its settings), and the
// types and checks the manifest of the service is held to.
import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
// The manifest a service puts in `/etc/v2-admin/services/<id>.json` to describe itself to v2 admin: the settings that may be
// changed from the screen, the numbers it can report, and the operations it can carry out. Everything the screen shows is made
// from it; v2 admin knows nothing else about a service.
//
// Every number has a range, every text a length, every list a size: a setting that can be set to anything can be set to a value
// that switches the thing it limits off. A value outside its range is never used (resolveValues).

export type SettingType = 'integer' | 'number' | 'boolean' | 'string' | 'list'

export interface SettingDef {
  type: SettingType
  default: unknown
  /** integer and number: required. */
  min?: number
  max?: number
  /** string, and the items of a list: the longest text (default 256, at most 4096). */
  maxLength?: number
  /** string: the values it may take. */
  enum?: string[]
  /** string, and the items of a list: a pattern the text must match entirely. */
  pattern?: string
  /** list: what the items are (default string), and how many there may be (required, at most 10000). */
  item?: 'string' | 'integer' | 'number'
  maxItems?: number
  unit?: string
  group?: string
  description?: string
  /** `live`: the service reads a new value as it runs. `restart`: it only takes it up when it starts. */
  reload?: 'live' | 'restart'
}

export type ParamDef = { type: 'string' | 'integer' | 'boolean'; required?: boolean; description?: string; maxLength?: number; min?: number; max?: number; pattern?: string }

export interface ActionDef {
  description: string
  /** Where v2 admin POSTs the operation (a loopback address). */
  url: string
  params?: Record<string, ParamDef>
  /** The screen asks to confirm before running it. */
  danger?: boolean
}

export interface Manifest {
  id: string
  name: string
  description?: string
  /** The systemd unit whose state the screen shows. */
  unit?: string
  settings: Record<string, SettingDef>
  metrics?: { url: string }
  actions?: Record<string, ActionDef>
}

export class ManifestError extends Error {}

const SERVICE_ID = /^[a-z][a-z0-9-]{0,31}$/
const SETTING_KEY = /^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)*$/
const ACTION_NAME = /^[a-z][a-zA-Z0-9-]{0,47}$/
const UNIT = /^[A-Za-z0-9@_.:-]{1,100}\.(?:service|socket|timer)$/
const DEFAULT_MAX_LENGTH = 256
const HARD_MAX_LENGTH = 4096
const HARD_MAX_ITEMS = 10_000

const isObject = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value)

/** Only the machine itself: v2 admin never POSTs where a manifest says if that is anywhere else. */
export function isLoopbackUrl(value: string): boolean {
  try {
    const url = new URL(value)
    return url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) && url.username === '' && url.password === ''
  } catch { return false }
}

function only(value: Record<string, unknown>, keys: readonly string[], path: string): void {
  for (const key of Object.keys(value)) if (!keys.includes(key)) throw new ManifestError(`${path}: unknown property ${key}`)
}

function safeRegExp(pattern: string, path: string): RegExp {
  if (pattern.length > 200) throw new ManifestError(`${path}: pattern is too long`)
  try { return new RegExp(`^(?:${pattern})$`) } catch { throw new ManifestError(`${path}: pattern is not a regular expression`) }
}

export type Checked<T> = { ok: true; value: T } | { ok: false; error: string }

/** Whether `value` is a legal value for `def`: the type, the range, the length, the choices. */
export function checkValue(def: SettingDef, value: unknown): Checked<unknown> {
  const fail = (error: string): Checked<unknown> => ({ ok: false, error })
  switch (def.type) {
    case 'boolean': return typeof value === 'boolean' ? { ok: true, value } : fail('must be true or false')
    case 'integer':
      if (typeof value !== 'number' || !Number.isSafeInteger(value)) return fail('must be a whole number')
      if (value < def.min! || value > def.max!) return fail(`must be between ${def.min} and ${def.max}`)
      return { ok: true, value }
    case 'number':
      if (typeof value !== 'number' || !Number.isFinite(value)) return fail('must be a number')
      if (value < def.min! || value > def.max!) return fail(`must be between ${def.min} and ${def.max}`)
      return { ok: true, value }
    case 'string': {
      if (typeof value !== 'string') return fail('must be text')
      if (value.length > (def.maxLength ?? DEFAULT_MAX_LENGTH)) return fail(`must be at most ${def.maxLength ?? DEFAULT_MAX_LENGTH} characters`)
      if (def.enum && !def.enum.includes(value)) return fail(`must be one of ${def.enum.join(', ')}`)
      if (def.pattern && !safeRegExp(def.pattern, 'pattern').test(value)) return fail('is not in the form expected')
      return { ok: true, value }
    }
    case 'list': {
      if (!Array.isArray(value)) return fail('must be a list')
      if (value.length > def.maxItems!) return fail(`must have at most ${def.maxItems} items`)
      const kind = def.item ?? 'string'
      const seen = new Set<unknown>()
      for (const item of value) {
        if (kind === 'string') {
          if (typeof item !== 'string' || item.length > (def.maxLength ?? DEFAULT_MAX_LENGTH)) return fail(`each item must be text of at most ${def.maxLength ?? DEFAULT_MAX_LENGTH} characters`)
          if (def.pattern && !safeRegExp(def.pattern, 'pattern').test(item)) return fail('an item is not in the form expected')
        } else if (typeof item !== 'number' || !Number.isFinite(item) || (kind === 'integer' && !Number.isSafeInteger(item))) return fail(`each item must be a ${kind === 'integer' ? 'whole ' : ''}number`)
        else if (def.min !== undefined && (item < def.min || item > def.max!)) return fail(`each item must be between ${def.min} and ${def.max}`)
        if (seen.has(item)) return fail('has the same item twice')
        seen.add(item)
      }
      return { ok: true, value }
    }
  }
}

function validateSetting(key: string, raw: unknown): SettingDef {
  const path = `settings.${key}`
  if (!SETTING_KEY.test(key)) throw new ManifestError(`${path}: the name is not a dotted name of letters and digits`)
  if (!isObject(raw)) throw new ManifestError(`${path}: must be an object`)
  only(raw, ['type', 'default', 'min', 'max', 'maxLength', 'enum', 'pattern', 'item', 'maxItems', 'unit', 'group', 'description', 'reload'], path)
  const type = raw.type
  if (type !== 'integer' && type !== 'number' && type !== 'boolean' && type !== 'string' && type !== 'list') throw new ManifestError(`${path}.type: must be integer, number, boolean, string or list`)
  const def = raw as unknown as SettingDef
  if (!('default' in raw)) throw new ManifestError(`${path}.default: is required`)
  const text = (name: 'unit' | 'group' | 'description') => { if (raw[name] !== undefined && (typeof raw[name] !== 'string' || (raw[name] as string).length > 500)) throw new ManifestError(`${path}.${name}: must be text of at most 500 characters`) }
  text('unit'); text('group'); text('description')
  if (raw.reload !== undefined && raw.reload !== 'live' && raw.reload !== 'restart') throw new ManifestError(`${path}.reload: must be live or restart`)
  const range = type === 'integer' || type === 'number' || (type === 'list' && (raw.item === 'integer' || raw.item === 'number'))
  if (range) {
    if (typeof raw.min !== 'number' || typeof raw.max !== 'number' || !Number.isFinite(raw.min) || !Number.isFinite(raw.max) || raw.min > raw.max) throw new ManifestError(`${path}: a number needs a range (min and max, min not above max)`)
  } else if (raw.min !== undefined || raw.max !== undefined) throw new ManifestError(`${path}: min and max are only for numbers`)
  if (type === 'string' || (type === 'list' && (raw.item === undefined || raw.item === 'string'))) {
    if (raw.maxLength !== undefined && (!Number.isSafeInteger(raw.maxLength) || (raw.maxLength as number) < 1 || (raw.maxLength as number) > HARD_MAX_LENGTH)) throw new ManifestError(`${path}.maxLength: must be between 1 and ${HARD_MAX_LENGTH}`)
    if (raw.pattern !== undefined) { if (typeof raw.pattern !== 'string') throw new ManifestError(`${path}.pattern: must be text`); safeRegExp(raw.pattern, `${path}.pattern`) }
  } else if (raw.maxLength !== undefined || raw.pattern !== undefined) throw new ManifestError(`${path}: maxLength and pattern are only for text`)
  if (raw.enum !== undefined) {
    if (type !== 'string' || !Array.isArray(raw.enum) || raw.enum.length === 0 || raw.enum.some(item => typeof item !== 'string')) throw new ManifestError(`${path}.enum: only a string takes a list of texts`)
  }
  if (type === 'list') {
    if (raw.item !== undefined && raw.item !== 'string' && raw.item !== 'integer' && raw.item !== 'number') throw new ManifestError(`${path}.item: must be string, integer or number`)
    if (!Number.isSafeInteger(raw.maxItems) || (raw.maxItems as number) < 0 || (raw.maxItems as number) > HARD_MAX_ITEMS) throw new ManifestError(`${path}.maxItems: a list needs a size limit of at most ${HARD_MAX_ITEMS}`)
  } else if (raw.item !== undefined || raw.maxItems !== undefined) throw new ManifestError(`${path}: item and maxItems are only for lists`)
  const checked = checkValue(def, raw.default)
  if (!checked.ok) throw new ManifestError(`${path}.default: ${checked.error}`)
  return def
}

function validateAction(name: string, raw: unknown): ActionDef {
  const path = `actions.${name}`
  if (!ACTION_NAME.test(name)) throw new ManifestError(`${path}: the name is not a short name of letters, digits and hyphens`)
  if (!isObject(raw)) throw new ManifestError(`${path}: must be an object`)
  only(raw, ['description', 'url', 'params', 'danger'], path)
  if (typeof raw.description !== 'string' || raw.description.length === 0 || raw.description.length > 500) throw new ManifestError(`${path}.description: is required`)
  if (typeof raw.url !== 'string' || !isLoopbackUrl(raw.url)) throw new ManifestError(`${path}.url: must be an http URL on this machine (127.0.0.1, localhost or [::1])`)
  if (raw.danger !== undefined && typeof raw.danger !== 'boolean') throw new ManifestError(`${path}.danger: must be true or false`)
  if (raw.params !== undefined) {
    if (!isObject(raw.params)) throw new ManifestError(`${path}.params: must be an object`)
    for (const [param, def] of Object.entries(raw.params)) {
      if (!/^[A-Za-z][A-Za-z0-9]{0,31}$/.test(param) || !isObject(def)) throw new ManifestError(`${path}.params.${param}: is not a valid parameter`)
      only(def, ['type', 'required', 'description', 'maxLength', 'min', 'max', 'pattern'], `${path}.params.${param}`)
      if (def.type !== 'string' && def.type !== 'integer' && def.type !== 'boolean') throw new ManifestError(`${path}.params.${param}.type: must be string, integer or boolean`)
      if (def.type === 'integer' && (typeof def.min !== 'number' || typeof def.max !== 'number')) throw new ManifestError(`${path}.params.${param}: an integer needs a range`)
      if (def.pattern !== undefined) safeRegExp(String(def.pattern), `${path}.params.${param}.pattern`)
    }
  }
  return raw as unknown as ActionDef
}

/** The manifest, checked; throws a ManifestError that says where the fault is. */
export function validateManifest(value: unknown): Manifest {
  if (!isObject(value)) throw new ManifestError('the manifest must be an object')
  only(value, ['id', 'name', 'description', 'unit', 'settings', 'metrics', 'actions'], 'manifest')
  if (typeof value.id !== 'string' || !SERVICE_ID.test(value.id)) throw new ManifestError('id: must be a short lower-case name (letters, digits, hyphens)')
  if (typeof value.name !== 'string' || value.name.length === 0 || value.name.length > 100) throw new ManifestError('name: is required')
  if (value.description !== undefined && (typeof value.description !== 'string' || value.description.length > 500)) throw new ManifestError('description: must be text of at most 500 characters')
  if (value.unit !== undefined && (typeof value.unit !== 'string' || !UNIT.test(value.unit))) throw new ManifestError('unit: must be a systemd unit name such as didmail.service')
  if (!isObject(value.settings)) throw new ManifestError('settings: must be an object (it may be empty)')
  const settings: Record<string, SettingDef> = {}
  for (const [key, raw] of Object.entries(value.settings)) settings[key] = validateSetting(key, raw)
  if (value.metrics !== undefined) {
    if (!isObject(value.metrics)) throw new ManifestError('metrics: must be an object')
    only(value.metrics, ['url'], 'metrics')
    if (typeof value.metrics.url !== 'string' || !isLoopbackUrl(value.metrics.url)) throw new ManifestError('metrics.url: must be an http URL on this machine (127.0.0.1, localhost or [::1])')
  }
  const actions: Record<string, ActionDef> = {}
  if (value.actions !== undefined) {
    if (!isObject(value.actions)) throw new ManifestError('actions: must be an object')
    for (const [name, raw] of Object.entries(value.actions)) actions[name] = validateAction(name, raw)
  }
  return { id: value.id, name: value.name, ...(value.description ? { description: value.description } : {}), ...(value.unit ? { unit: value.unit } : {}), settings, ...(value.metrics ? { metrics: value.metrics as { url: string } } : {}), ...(value.actions ? { actions } : {}) }
}

/** Every setting at its default. */
export function defaultsOf(manifest: Pick<Manifest, 'settings'>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(manifest.settings).map(([key, def]) => [key, structuredClone(def.default)]))
}

export interface Resolved { values: Record<string, unknown>; problems: Array<{ key: string; error: string }> }

/** The values a service should use, from what a snapshot holds: each setting from the snapshot if it is legal, else its default
 * (and a problem is reported). A setting the snapshot does not know, or lacks, is not a problem for the others. */
export function resolveValues(manifest: Pick<Manifest, 'settings'>, raw: unknown): Resolved {
  const values = defaultsOf(manifest)
  const problems: Resolved['problems'] = []
  const held = isObject(raw) ? raw : {}
  for (const [key, def] of Object.entries(manifest.settings)) {
    if (!(key in held)) continue
    const checked = checkValue(def, held[key])
    if (checked.ok) values[key] = checked.value
    else problems.push({ key, error: checked.error })
  }
  return { values, problems }
}

/** The arguments of an action, checked against its parameters. */
export function checkParams(action: Pick<ActionDef, 'params'>, raw: unknown): Checked<Record<string, unknown>> {
  const given = isObject(raw) ? raw : {}
  const params = action.params ?? {}
  for (const key of Object.keys(given)) if (!(key in params)) return { ok: false, error: `${key}: not a parameter of this operation` }
  const out: Record<string, unknown> = {}
  for (const [key, def] of Object.entries(params)) {
    const value = given[key]
    if (value === undefined || value === '') {
      if (def.required) return { ok: false, error: `${key}: is required` }
      continue
    }
    if (def.type === 'boolean' && typeof value !== 'boolean') return { ok: false, error: `${key}: must be true or false` }
    if (def.type === 'integer' && (typeof value !== 'number' || !Number.isSafeInteger(value) || value < def.min! || value > def.max!)) return { ok: false, error: `${key}: must be a whole number between ${def.min} and ${def.max}` }
    if (def.type === 'string') {
      if (typeof value !== 'string' || value.length > (def.maxLength ?? DEFAULT_MAX_LENGTH)) return { ok: false, error: `${key}: must be text of at most ${def.maxLength ?? DEFAULT_MAX_LENGTH} characters` }
      if (def.pattern && !safeRegExp(def.pattern, key).test(value)) return { ok: false, error: `${key}: is not in the form expected` }
    }
    out[key] = value
  }
  return { ok: true, value: out }
}

// What a service uses to read the settings v2 admin holds for it. The snapshot is a file the admin writes; the service only reads it,
// a few seconds apart, and never needs v2 admin to be running: with no snapshot, or a snapshot that is wrong, it runs on its
// defaults (a setting at a time), and a limit never goes away because the admin did.
//
//   const settings = openSettings({ service: 'didmail', settings: { 'sendLimit.perHour': { type: 'integer', default: 60, min: 1, max: 1000 } } })
//   settings.get('sendLimit.perHour')   // the value in force now

export const DEFAULT_SNAPSHOT_DIR = '/var/lib/v2-admin/config'

export interface OpenSettingsOptions {
  service: string
  /** The settings the service has, with their ranges: the same definitions as its manifest. */
  settings: Record<string, SettingDef>
  /** Where the snapshots are (default /var/lib/v2-admin/config, or $V2_ADMIN_CONFIG_DIR). */
  dir?: string
  /** How often the file is looked at (default 3 s). */
  intervalMs?: number
  now?: () => number
  /** Told when a setting could not be used and its default is in force (once per change of the file). */
  onProblem?: (message: string) => void
}

export interface Settings {
  /** The value in force for `key`. */
  get<T = unknown>(key: string): T
  /** Every value in force. */
  all(): Record<string, unknown>
  /** The version of the snapshot in force (0: none). */
  version(): number
}

export function openSettings(options: OpenSettingsOptions): Settings {
  for (const [key, def] of Object.entries(options.settings)) {
    const checked = checkValue(def, def.default)
    if (!checked.ok) throw new Error(`the default of ${key} is not a legal value: ${checked.error}`)
  }
  const file = join(options.dir ?? process.env.V2_ADMIN_CONFIG_DIR ?? DEFAULT_SNAPSHOT_DIR, `${options.service}.json`)
  const intervalMs = options.intervalMs ?? 3000
  const now = options.now ?? Date.now
  const spec = { settings: options.settings }
  let values = defaultsOf(spec)
  let version = 0
  let signature = ''
  let checkedAt = Number.NEGATIVE_INFINITY

  function refresh(): void {
    checkedAt = now()
    let stamp: string
    try { const stat = statSync(file); stamp = `${stat.mtimeMs}:${stat.size}` } catch {
      // No snapshot (never written, or removed): the defaults, once.
      if (signature !== 'none') { signature = 'none'; values = defaultsOf(spec); version = 0 }
      return
    }
    if (stamp === signature) return
    signature = stamp
    try {
      const parsed = JSON.parse(readFileSync(file, 'utf8')) as { version?: unknown; values?: unknown }
      const resolved = resolveValues(spec, parsed.values)
      values = resolved.values
      version = Number.isSafeInteger(parsed.version) ? parsed.version as number : 0
      for (const problem of resolved.problems) options.onProblem?.(`${options.service}: ${problem.key} ${problem.error}; its default is in force`)
    } catch (error) {
      // A file that cannot be read as it is (half-written, damaged): what was in force stays; the next change is looked at.
      options.onProblem?.(`${options.service}: the settings file could not be read (${error instanceof Error ? error.message : String(error)}); the last settings stay in force`)
    }
  }

  const current = () => { if (now() - checkedAt >= intervalMs) refresh(); return values }
  return {
    get: <T = unknown>(key: string): T => {
      if (!(key in options.settings)) throw new Error(`${options.service} has no setting ${key}`)
      return current()[key] as T
    },
    all: () => ({ ...current() }),
    version: () => { current(); return version },
  }
}
