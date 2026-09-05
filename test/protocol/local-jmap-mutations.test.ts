import { describe, expect, test } from 'bun:test'
import { emailSetToVaultMutationIntents } from '../../src/client/store/projection/mutations.ts'

describe('Local JMAP mutation intents', () => {
  test('turns Email/set mailbox and keyword updates into immutable vault intents', () => {
    expect(emailSetToVaultMutationIntents({
      accountId: 'biset:did:web:alice.example',
      update: {
        'email-1': { mailboxIds: { inbox: true, archive: false }, keywords: { '$seen': true } },
      },
      destroy: ['email-2'],
    })).toEqual([
      { kind: 'mailbox.set', targetIds: ['email-1'], payload: { emailId: 'email-1', mailboxIds: { inbox: true, archive: false } } },
      { kind: 'keyword.set', targetIds: ['email-1'], payload: { emailId: 'email-1', keywords: { '$seen': true } } },
      { kind: 'message.tombstone', targetIds: ['email-2'], payload: { emailId: 'email-2' } },
    ])
  })

  test('does not silently accept direct projection writes or contradictory mutations', () => {
    expect(() => emailSetToVaultMutationIntents({ update: { 'email-1': { subject: 'rewrite' } } })).toThrow('unsupported Email/set property')
    expect(() => emailSetToVaultMutationIntents({ update: { 'email-1': { keywords: {} } }, destroy: ['email-1'] })).toThrow('update and destroy')
    expect(() => emailSetToVaultMutationIntents({ create: { x: {} } })).toThrow('unsupported Email/set argument')
  })
})
