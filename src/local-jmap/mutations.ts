import type { CanonicalValue } from '../protocol/canonical.ts'
import type { VaultEventKind } from '../protocol/vault.ts'

/**
 * Plain, validated intent before vault transaction encryption. The transaction
 * stores `payload` in an encrypted object and creates the signed event that
 * refers to it; JMAP parsing never writes the projection directly.
 */
export interface VaultMutationIntent {
  kind: VaultEventKind
  targetIds: string[]
  payload: CanonicalValue
}

interface EmailSetMutationInput {
  accountId?: string
  update?: Record<string, unknown>
  destroy?: string[]
}

/**
 * v1 supports the state mutations a mail UI needs most often. Message create
 * and import require an encrypted RFC822/object transaction and are kept out
 * of this parser until that transaction is implemented.
 */
export function emailSetToVaultMutationIntents(input: unknown): VaultMutationIntent[] {
  const request = record(input, 'Email/set arguments') as EmailSetMutationInput
  const allowed = new Set(['accountId', 'update', 'destroy'])
  for (const key of Object.keys(request)) if (!allowed.has(key)) throw new TypeError(`unsupported Email/set argument: ${key}`)

  const intents: VaultMutationIntent[] = []
  const changed = new Set<string>()
  if (request.update !== undefined) {
    const updates = record(request.update, 'Email/set update')
    for (const [emailId, patchValue] of Object.entries(updates)) {
      assertId(emailId, 'Email/set update ID')
      const patch = record(patchValue, `Email/set update ${emailId}`)
      const keys = Object.keys(patch)
      if (keys.length === 0) throw new TypeError(`Email/set update ${emailId} is empty`)
      for (const key of keys) if (key !== 'mailboxIds' && key !== 'keywords') throw new TypeError(`unsupported Email/set property: ${key}`)
      if (patch.mailboxIds !== undefined) {
        intents.push({ kind: 'mailbox.set', targetIds: [emailId], payload: { emailId, mailboxIds: booleanMap(patch.mailboxIds, 'mailboxIds') } })
      }
      if (patch.keywords !== undefined) {
        intents.push({ kind: 'keyword.set', targetIds: [emailId], payload: { emailId, keywords: booleanMap(patch.keywords, 'keywords') } })
      }
      changed.add(emailId)
    }
  }
  if (request.destroy !== undefined) {
    if (!Array.isArray(request.destroy)) throw new TypeError('Email/set destroy must be an array')
    const destroyed = new Set<string>()
    for (const emailId of request.destroy) {
      assertId(emailId, 'Email/set destroy ID')
      if (destroyed.has(emailId)) throw new TypeError('Email/set destroy has duplicate ID')
      if (changed.has(emailId)) throw new TypeError('Email/set cannot update and destroy the same email')
      destroyed.add(emailId)
      intents.push({ kind: 'message.tombstone', targetIds: [emailId], payload: { emailId } })
    }
  }
  if (intents.length === 0) throw new TypeError('Email/set has no supported mutation')
  return intents
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} must be an object`)
  return value as Record<string, unknown>
}

function assertId(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || !value) throw new TypeError(`${name} must be a non-empty string`)
}

function booleanMap(value: unknown, name: string): Record<string, boolean> {
  const map = record(value, `Email/set ${name}`)
  const result: Record<string, boolean> = {}
  for (const [id, enabled] of Object.entries(map)) {
    assertId(id, `Email/set ${name} key`)
    if (typeof enabled !== 'boolean') throw new TypeError(`Email/set ${name} values must be booleans`)
    result[id] = enabled
  }
  return result
}
