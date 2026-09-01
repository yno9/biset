import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import { createSegmentKey, decryptVaultObject } from '../../src/vault/objects.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { DISPOSITION_REACTION, DISPOSITION_RENDER, type MimiContent } from '../../src/mls/mimi-content.ts'
import {
  classifyMimiContent,
  messageIdToEmailId,
  MimiContentProjectionError,
  projectMimiConversationMessage,
  type MimiConversationMessageContext,
} from '../../src/mls/mimi-content-projector.ts'

const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

function context(): MimiConversationMessageContext {
  return {
    identityId: 'did:web:alice.example', actorDeviceId: 'device-a', actorSeq: 1, parents: [],
    segmentId: 'segment-1', segmentKey: createSegmentKey(), createdAt: '2026-08-31T00:00:00.000Z',
  }
}

function id(fill: number): Uint8Array { return new Uint8Array(32).fill(fill) }

function plainContent(text: string, overrides: Partial<MimiContent> = {}): MimiContent {
  return {
    salt: new Uint8Array(16).fill(1),
    replaces: null, topicId: new Uint8Array(0), expires: null, inReplyTo: null, extensions: {},
    nestedPart: { disposition: DISPOSITION_RENDER, language: 'en', part: { kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode(text) } },
    ...overrides,
  }
}

describe('classifyMimiContent', () => {
  test('an ordinary message (no replaces) is an add', () => {
    expect(classifyMimiContent(plainContent('hi'))).toEqual({ kind: 'add' })
  })

  test('replaces + SinglePart body is an edit', () => {
    expect(classifyMimiContent(plainContent('corrected', { replaces: id(1) }))).toEqual({ kind: 'edit', targetId: messageIdToEmailId(id(1)) })
  })

  test('replaces + NullPart body is a delete', () => {
    const content: MimiContent = { ...plainContent('x', { replaces: id(2) }), nestedPart: { disposition: DISPOSITION_RENDER, language: 'en', part: { kind: 'null' } } }
    expect(classifyMimiContent(content)).toEqual({ kind: 'delete', targetId: messageIdToEmailId(id(2)) })
  })

  test('disposition=reaction + inReplyTo (no replaces) is a new reaction', () => {
    const content: MimiContent = {
      ...plainContent('👍', { inReplyTo: id(3) }),
      nestedPart: { disposition: DISPOSITION_REACTION, language: 'en', part: { kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode('👍') } },
    }
    expect(classifyMimiContent(content)).toEqual({ kind: 'reaction', targetId: messageIdToEmailId(id(3)), emoji: '👍' })
  })

  test('disposition=reaction + replaces + NullPart is a reaction retraction', () => {
    const content: MimiContent = {
      ...plainContent('x', { replaces: id(4) }),
      nestedPart: { disposition: DISPOSITION_REACTION, language: 'en', part: { kind: 'null' } },
    }
    expect(classifyMimiContent(content)).toEqual({ kind: 'reaction', targetId: messageIdToEmailId(id(4)), emoji: null })
  })

  test('rejects a reaction retraction with a non-null body', () => {
    const content: MimiContent = {
      ...plainContent('👍', { replaces: id(5) }),
      nestedPart: { disposition: DISPOSITION_REACTION, language: 'en', part: { kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode('👍') } },
    }
    expect(() => classifyMimiContent(content)).toThrow(MimiContentProjectionError)
  })

  test('rejects a new reaction with no inReplyTo', () => {
    const content: MimiContent = {
      ...plainContent('👍'),
      nestedPart: { disposition: DISPOSITION_REACTION, language: 'en', part: { kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode('👍') } },
    }
    expect(() => classifyMimiContent(content)).toThrow(MimiContentProjectionError)
  })
})

describe('projectMimiConversationMessage', () => {
  test('an ordinary group message becomes message.add with mls:<groupId> as threadId and roster as recipients', async () => {
    const ctx = context()
    const record = await projectMimiConversationMessage({
      content: plainContent('hello group'), messageId: id(11), groupId: 'group-1', senderDid: 'did:web:alice.example', otherMembers: ['did:web:bob.example'], receivedAt: '2026-08-31T00:00:01.000Z',
    }, ctx, signer)
    expect(record.events).toHaveLength(1)
    expect(record.events[0].kind).toBe('message.add')
    const metadataObject = record.objects[0]
    const decrypted = JSON.parse(new TextDecoder().decode(await decryptVaultObject(ctx.segmentKey, metadataObject))) as { payload: { email: Record<string, unknown> } }
    expect(decrypted.payload.email.id).toBe(messageIdToEmailId(id(11)))
    expect(decrypted.payload.email.threadId).toBe('mls:group-1')
    expect(decrypted.payload.email.from).toEqual([{ email: 'did:web:alice.example' }])
    expect(decrypted.payload.email.to).toEqual([{ email: 'did:web:bob.example' }])
    const rawRfc5322Object = record.objects[1]
    expect(await decryptVaultObject(ctx.segmentKey, rawRfc5322Object)).toEqual(new TextEncoder().encode('hello group'))
  })

  test('a reply sets inReplyTo on the added email', async () => {
    const ctx = context()
    const record = await projectMimiConversationMessage({
      content: plainContent('sure', { inReplyTo: id(12) }), messageId: id(13), groupId: 'group-1', senderDid: 'did:web:alice.example', otherMembers: [], receivedAt: '2026-08-31T00:00:01.000Z',
    }, ctx, signer)
    const decrypted = JSON.parse(new TextDecoder().decode(await decryptVaultObject(ctx.segmentKey, record.objects[0]))) as { payload: { email: Record<string, unknown> } }
    expect(decrypted.payload.email.inReplyTo).toBe(messageIdToEmailId(id(12)))
  })

  test('an edit produces a message.edit event targeting the replaced email', async () => {
    const ctx = context()
    const record = await projectMimiConversationMessage({
      content: plainContent('corrected', { replaces: id(14) }), messageId: id(15), groupId: 'group-1', senderDid: 'did:web:alice.example', otherMembers: [], receivedAt: '2026-08-31T00:00:01.000Z',
    }, ctx, signer)
    expect(record.events[0].kind).toBe('message.edit')
    expect(record.events[0].targetIds).toEqual([messageIdToEmailId(id(14))])
  })

  test('a delete produces a message.tombstone event', async () => {
    const ctx = context()
    const content: MimiContent = { ...plainContent('x', { replaces: id(16) }), nestedPart: { disposition: DISPOSITION_RENDER, language: 'en', part: { kind: 'null' } } }
    const record = await projectMimiConversationMessage({
      content, messageId: id(17), groupId: 'group-1', senderDid: 'did:web:alice.example', otherMembers: [], receivedAt: '2026-08-31T00:00:01.000Z',
    }, ctx, signer)
    expect(record.events[0].kind).toBe('message.tombstone')
    expect(record.events[0].targetIds).toEqual([messageIdToEmailId(id(16))])
  })

  test('a reaction produces a reaction.set event carrying sender and emoji', async () => {
    const ctx = context()
    const content: MimiContent = {
      ...plainContent('👍', { inReplyTo: id(18) }),
      nestedPart: { disposition: DISPOSITION_REACTION, language: 'en', part: { kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode('👍') } },
    }
    const record = await projectMimiConversationMessage({
      content, messageId: id(19), groupId: 'group-1', senderDid: 'did:web:bob.example', otherMembers: [], receivedAt: '2026-08-31T00:00:01.000Z',
    }, ctx, signer)
    expect(record.events[0].kind).toBe('reaction.set')
    const decrypted = JSON.parse(new TextDecoder().decode(await decryptVaultObject(ctx.segmentKey, record.objects[0]))) as { payload: Record<string, unknown> }
    expect(decrypted.payload).toEqual({ emailId: messageIdToEmailId(id(18)), sender: 'did:web:bob.example', emoji: '👍' })
  })
})
