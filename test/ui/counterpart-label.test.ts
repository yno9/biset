import { expect, test } from 'vitest'
import { counterpartLabel } from '../../src/client/app/ui/thread-model.ts'

const group = (...msgs: Array<{ from: string; from_name?: string; ts: number; to_addrs?: string[] }>) => ({ key: 'g', subject: 'Lunch', messages: msgs.map(msg => ({ msg: { thread_id: 't', ...msg } })) }) as never
const self = new Set(['me@did.md']) as never

test('a 1:1 row is named after the other side, even when we wrote last', () => {
  const g = group({ from: 'bob@x.test', from_name: 'Bob', ts: 1 }, { from: 'me@did.md', ts: 2, to_addrs: ['bob@x.test'] })
  expect(counterpartLabel([g], self)).toBe('Bob')
})

test('without a display name the short address names it; with nothing received, the members do', () => {
  expect(counterpartLabel([group({ from: 'bob@x.test', ts: 1 })], self)).toBe('bob@x.test')
  expect(counterpartLabel([group({ from: 'me@did.md', ts: 1, to_addrs: ['carol@y.test'] })], self)).toBe('carol@y.test')
})

test('a thread of which only our own first message exists is with the one it was written to, over DIDComm', async () => {
  const { threadProtocol, displayParticipantsOf } = await import('../../src/client/app/ui/thread-model.ts')
  const sent = [{ from: 'me@did.md', to_addrs: ['did:web:did.md:nine.testrun.org:hrdcv7qkr'], ts: 1, thread_id: 't' }] as never
  expect(threadProtocol(sent, self)).toBe('did')
  expect(displayParticipantsOf(sent, self)).toBe('hrdcv7qkr@nine.testrun.org')
})
