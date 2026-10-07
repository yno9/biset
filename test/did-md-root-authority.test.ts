// did.md's Root key is `#pass-1` by name. A document may list other
// authentication keys too (PLAN-refactor.md §3-4: the DID Rotation signing
// key), in any order; the Root must never be taken to be whichever comes first.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { encodeMultikey } from '../src/protocol/webvh/multikey.ts'
import { rootAuthority } from '../src/client/identity/wallet/did-md-oauth.ts'

const DID = 'did:webvh:QmZdfGg8BAxEMLvHRC1RwDVcthg66akuBzJoeLvRdHXwQz:alice.did.md'
const key = () => encodeMultikey(ed25519.getPublicKey(ed25519.utils.randomSecretKey()))
const document = (authentication: string[], methods: Array<{ id: string; publicKeyMultibase: string }>) =>
  ({ id: DID, authentication, verificationMethod: methods.map(method => ({ ...method, type: 'Multikey', controller: DID })) }) as never

describe('rootAuthority', () => {
  test('picks #pass-1 even when another authentication key is listed first', async () => {
    const root = key()
    const authority = await rootAuthority('alice.did.md', document(['#didcomm-rotation', '#pass-1'], [{ id: '#didcomm-rotation', publicKeyMultibase: key() }, { id: '#pass-1', publicKeyMultibase: root }]))
    expect(authority.verificationMethod).toBe(`${DID}#pass-1`)
  })

  test('accepts absolute references too', async () => {
    const authority = await rootAuthority('alice.did.md', document([`${DID}#pass-1`], [{ id: `${DID}#pass-1`, publicKeyMultibase: key() }]))
    expect(authority.verificationMethod).toBe(`${DID}#pass-1`)
  })

  test('a document without #pass-1 has no Root, whatever else it authenticates with', async () => {
    await expect(rootAuthority('alice.did.md', document(['#didcomm-rotation'], [{ id: '#didcomm-rotation', publicKeyMultibase: key() }]))).rejects.toThrow('no Root authentication key')
  })
})
