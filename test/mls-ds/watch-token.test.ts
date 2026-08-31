import { describe, expect, test } from 'bun:test'
import { ConversationWatchTokenIssuer } from '../../src/mls-ds/watch-token.ts'

describe('ConversationWatchTokenIssuer', () => {
  test('issue then resolve round-trips groupId/requesterId', () => {
    const issuer = new ConversationWatchTokenIssuer()
    const { token, expiresAt } = issuer.issue('group-1', 'alice-id')
    expect(token).toMatch(/^[0-9a-f]{48}$/)
    expect(new Date(expiresAt).getTime()).toBeGreaterThan(Date.now())
    expect(issuer.resolve(token)).toEqual({ groupId: 'group-1', requesterId: 'alice-id' })
  })

  test('two issued tokens for the same group are distinct', () => {
    const issuer = new ConversationWatchTokenIssuer()
    const a = issuer.issue('group-1', 'alice-id')
    const b = issuer.issue('group-1', 'alice-id')
    expect(a.token).not.toBe(b.token)
  })

  test('resolve returns undefined for an unknown token', () => {
    const issuer = new ConversationWatchTokenIssuer()
    expect(issuer.resolve('not-a-real-token')).toBeUndefined()
  })

  test('resolve returns undefined and forgets an expired token', () => {
    const issuer = new ConversationWatchTokenIssuer(-1) // already expired the instant it's issued
    const { token } = issuer.issue('group-1', 'alice-id')
    expect(issuer.resolve(token)).toBeUndefined()
    expect(issuer.resolve(token)).toBeUndefined() // still undefined, not a crash on double-delete
  })

  test('revoke forgets a token immediately', () => {
    const issuer = new ConversationWatchTokenIssuer()
    const { token } = issuer.issue('group-1', 'alice-id')
    expect(issuer.resolve(token)).toBeDefined()
    issuer.revoke(token)
    expect(issuer.resolve(token)).toBeUndefined()
  })
})
