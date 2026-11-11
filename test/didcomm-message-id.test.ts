import { expect, test } from 'vitest'
import { buildPlaintext, newDidCommId } from '../src/protocol/didcomm/message.ts'

// DIDComm v2.1, "Message IDs": an id is at most 32 bytes of unreserved URI characters, and globally unique.
const UNRESERVED = /^[A-Za-z0-9\-._~]{1,32}$/

test('a message id is at most 32 bytes of unreserved URI characters, and differs each time', () => {
  const ids = Array.from({ length: 200 }, newDidCommId)
  for (const id of ids) expect(id).toMatch(UNRESERVED)
  expect(new Set(ids).size).toBe(ids.length)
})

test('a built message carries such an id unless one is given', () => {
  expect(buildPlaintext('https://didcomm.org/trust-ping/2.0/ping', {}, 'did:example:a', 'did:example:b').id).toMatch(UNRESERVED)
  expect(buildPlaintext('https://didcomm.org/trust-ping/2.0/ping', {}, 'did:example:a', 'did:example:b', { id: 'given-1' }).id).toBe('given-1')
})
