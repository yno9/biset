import { beforeEach, describe, expect, test, vi } from 'vitest'
import { generatePgpKey } from '../src/client/pgp/keyring.ts'
import { isMailBridgeDid, ownAutocryptFor } from '../src/client/pgp/autocrypt.ts'

const sent: Array<{ toDid: string; type: string; body: Record<string, unknown> }> = []
vi.mock('../src/client/didcomm/front-door-send.ts', () => ({
  sendFrontDoorMessage: async (toDid: string, type: string, body: Record<string, unknown>) => { sent.push({ toDid, type, body }); return { ok: true } },
}))
const { sendDidCommMessage } = await import('../src/client/didcomm/send-message.ts')

beforeEach(() => { sent.length = 0 })

describe('the key told to a mail bridge', () => {
  test('only a bridge DID (did:web:{host}:{domain}:{local}) is a mail address', () => {
    expect(isMailBridgeDid('did:web:did.md:4r.ma:n')).toBe(true)
    expect(isMailBridgeDid('did:web:did.md:gmail.com:bob%2Bnews')).toBe(true)
    expect(isMailBridgeDid('did:web:example.com')).toBe(false)
    expect(isMailBridgeDid('did:web:example.com:users:alice')).toBe(false)
    expect(isMailBridgeDid('did:webvh:Qm123:alice.did.md')).toBe(false)
    expect(isMailBridgeDid('did:peer:2.Ez6LS')).toBe(false)
  })

  test('a bridge DID gets this identity\'s minimal key and the mutual preference; any other DID gets nothing', async () => {
    const key = await generatePgpKey('alice@did.md')
    const own = { address: 'alice@did.md', privateKey: key.privateKey }
    const autocrypt = await ownAutocryptFor('did:web:did.md:4r.ma:n', own)
    expect(autocrypt?.preferEncrypt).toBe('mutual')
    expect(autocrypt?.keydata).toMatch(/^[A-Za-z0-9+/]+={0,2}$/)
    expect(await ownAutocryptFor('did:webvh:Qm123:bob.did.md', own)).toBeUndefined()
    expect(await ownAutocryptFor('did:web:did.md:4r.ma:n', undefined)).toBeUndefined()
  })

  test('the chat message carries the key in body.autocrypt, and has none without it', async () => {
    const opts = { fromKid: 'did:webvh:x:alice.did.md#k1', x25519PrivateKey: new Uint8Array(32) }
    await sendDidCommMessage('did:web:did.md:4r.ma:n', 'hi', { ...opts, autocrypt: { keydata: 'AAAA', preferEncrypt: 'mutual' } })
    await sendDidCommMessage('did:web:did.md:4r.ma:n', 'hi', opts)
    expect(sent[0]!.body).toMatchObject({ content: 'hi', autocrypt: { keydata: 'AAAA', preferEncrypt: 'mutual' } })
    expect('autocrypt' in sent[1]!.body).toBe(false)
  })
})
