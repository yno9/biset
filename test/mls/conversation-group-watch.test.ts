// Tests watchConversationGroupDeliveries against a FAKE EventSource
// (injected via `eventSourceCtor`) and a fake transport -- no real network,
// no dependency on Bun's own EventSource support (this module's whole
// point is being independently testable via DI, mirroring the `fetch`
// injection pattern this codebase already uses everywhere else).
import { describe, expect, test } from 'bun:test'
import { watchConversationGroupDeliveries } from '../../src/mls/conversation-group-watch.ts'
import type { ConversationLogEntry } from '../../src/protocol/conversation-mls-ds.ts'
import type { ConversationMlsDeliveryTransport } from '../../src/mls-ds/client-transport.ts'

class FakeEventSource {
  static instances: FakeEventSource[] = []
  onmessage: ((event: { data: string }) => void) | null = null
  onerror: (() => void) | null = null
  closed = false
  constructor(public readonly url: string) {
    FakeEventSource.instances.push(this)
  }
  close(): void { this.closed = true }
  emit(data: unknown): void { this.onmessage?.({ data: JSON.stringify(data) }) }
  fail(): void { this.onerror?.() }
}

function entryJson(seq: number, kind = 'application') {
  return { seq, kind, payload: 'AQID', epoch: '0', at: '2026-08-31T00:00:00.000Z' } // 'AQID' = base64url([1,2,3])
}

function fakeTransport(): ConversationMlsDeliveryTransport & { mintCount: number } {
  let mintCount = 0
  return {
    mintCount: 0,
    async watchDeliveries() {
      mintCount++
      ;(this as unknown as { mintCount: number }).mintCount = mintCount
      return { token: `token-${mintCount}`, expiresAt: '2026-08-31T01:00:00.000Z' }
    },
    streamUrl(token: string, afterSeq: number) {
      return `https://mls-ds.example/v1/conversation-mls/deliveries/stream?token=${token}&afterSeq=${afterSeq}`
    },
  } as unknown as ConversationMlsDeliveryTransport & { mintCount: number }
}

describe('watchConversationGroupDeliveries', () => {
  test('mints a token, opens EventSource at the given afterSeq, and forwards decoded entries', async () => {
    FakeEventSource.instances = []
    const transport = fakeTransport()
    const received: ConversationLogEntry[] = []
    const watch = watchConversationGroupDeliveries({
      transport, groupId: 'group-1', requesterId: 'alice-id', sign: async () => new Uint8Array(64),
      afterSeq: 5, onEntry: entry => received.push(entry), eventSourceCtor: FakeEventSource as unknown as typeof EventSource,
    })
    await Promise.resolve() // let the async connect() microtask run
    await Promise.resolve()

    expect(FakeEventSource.instances).toHaveLength(1)
    expect(FakeEventSource.instances[0]!.url).toBe('https://mls-ds.example/v1/conversation-mls/deliveries/stream?token=token-1&afterSeq=5')

    FakeEventSource.instances[0]!.emit(entryJson(6))
    expect(received).toHaveLength(1)
    expect(received[0]!.seq).toBe(6)
    expect(received[0]!.payload).toEqual(new Uint8Array([1, 2, 3]))

    watch.close()
  })

  test('an entry at or below the current cursor is ignored (a reconnect can re-deliver the tail)', async () => {
    FakeEventSource.instances = []
    const transport = fakeTransport()
    const received: number[] = []
    const watch = watchConversationGroupDeliveries({
      transport, groupId: 'group-1', requesterId: 'alice-id', sign: async () => new Uint8Array(64),
      afterSeq: 5, onEntry: entry => received.push(entry.seq), eventSourceCtor: FakeEventSource as unknown as typeof EventSource,
    })
    await Promise.resolve(); await Promise.resolve()
    FakeEventSource.instances[0]!.emit(entryJson(5))
    FakeEventSource.instances[0]!.emit(entryJson(6))
    expect(received).toEqual([6])
    watch.close()
  })

  test('on connection error, reconnects with a FRESH token and resumes from the last seen seq, not the original afterSeq', async () => {
    FakeEventSource.instances = []
    const transport = fakeTransport()
    const onError = (): void => {}
    const watch = watchConversationGroupDeliveries({
      transport, groupId: 'group-1', requesterId: 'alice-id', sign: async () => new Uint8Array(64),
      afterSeq: 0, onEntry: () => {}, onError, eventSourceCtor: FakeEventSource as unknown as typeof EventSource, reconnectDelayMs: 1,
    })
    await Promise.resolve(); await Promise.resolve()
    expect(FakeEventSource.instances).toHaveLength(1)

    FakeEventSource.instances[0]!.emit(entryJson(3))
    FakeEventSource.instances[0]!.fail()
    expect(FakeEventSource.instances[0]!.closed).toBe(true)

    await new Promise(resolve => setTimeout(resolve, 10)) // past reconnectDelayMs
    await Promise.resolve(); await Promise.resolve()

    expect(FakeEventSource.instances).toHaveLength(2)
    expect(FakeEventSource.instances[1]!.url).toBe('https://mls-ds.example/v1/conversation-mls/deliveries/stream?token=token-2&afterSeq=3')
    watch.close()
  })

  test('close() prevents any further reconnect after an error', async () => {
    FakeEventSource.instances = []
    const transport = fakeTransport()
    const watch = watchConversationGroupDeliveries({
      transport, groupId: 'group-1', requesterId: 'alice-id', sign: async () => new Uint8Array(64),
      afterSeq: 0, onEntry: () => {}, eventSourceCtor: FakeEventSource as unknown as typeof EventSource, reconnectDelayMs: 1,
    })
    await Promise.resolve(); await Promise.resolve()
    FakeEventSource.instances[0]!.fail()
    watch.close()
    await new Promise(resolve => setTimeout(resolve, 10))
    expect(FakeEventSource.instances).toHaveLength(1) // no second connection was opened
  })

  test('throws synchronously if no EventSource implementation is available', () => {
    const transport = fakeTransport()
    const originalEventSource = (globalThis as { EventSource?: unknown }).EventSource
    delete (globalThis as { EventSource?: unknown }).EventSource
    try {
      expect(() => watchConversationGroupDeliveries({
        transport, groupId: 'group-1', requesterId: 'alice-id', sign: async () => new Uint8Array(64), afterSeq: 0, onEntry: () => {},
      })).toThrow(/no EventSource implementation/)
    } finally {
      if (originalEventSource !== undefined) (globalThis as { EventSource?: unknown }).EventSource = originalEventSource
    }
  })
})
