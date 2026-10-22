import { expect, test } from 'vitest'
import { contactCardForDid, didContactUid } from '../../src/client/store/projection/contacts.ts'

const scid = 'QmfJMASJbk8m6aQr1Xobx8BFTBXQ6SThWz3RvFwMpvzh4E'

test('a person who changes their address stays the same contact card', () => {
  const before = `did:webvh:${scid}:kfl.did.md`
  const after = `did:webvh:${scid}:kfl2.did.md`
  expect(didContactUid(before)).toBe(didContactUid(after))
  expect(contactCardForDid([], after)).toBeUndefined()
})

test('a did:webvh card holds the bare SCID and its address among the aliases; a new address is added', async () => {
  const { aliasPatch, didContactPatch, SCID_CONTACT_PROPERTY } = await import('../../src/client/store/projection/contacts.ts')
  const created = didContactPatch(`did:webvh:${scid}:kfl.did.md`)
  expect(created.patch[SCID_CONTACT_PROPERTY]).toBe(scid)
  const emailPaths = Object.keys(created.patch).filter(path => path.startsWith('emails/'))
  expect(emailPaths).toHaveLength(1)
  expect(created.patch[emailPaths[0]!]).toEqual({ address: 'kfl@did.md' })
  const card = { id: created.cardId, '@type': 'Card', version: '1.0', uid: 'u', addressBookIds: { default: true }, emails: { [emailPaths[0]!.slice('emails/'.length)]: { address: 'kfl@did.md' } } } as const
  expect(aliasPatch(card as never, `did:webvh:${scid}:kfl.did.md`)).toBeUndefined()
  const added = aliasPatch(card as never, `did:webvh:${scid}:kfl2.did.md`)!
  expect(Object.entries(added.patch).find(([path]) => path.startsWith('emails/'))?.[1]).toEqual({ address: 'kfl2@did.md' })
  expect(didContactPatch('did:web:example.com').patch[SCID_CONTACT_PROPERTY]).toBeUndefined()
})
