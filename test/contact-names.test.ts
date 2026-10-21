import { describe, expect, test } from 'vitest'
import { applyContactSet, contactCardSet, contactDisplayName, contactNamePatch, didContactPatch, nameSourceOf, SOURCES_PROPERTY, type LocalJmapContactCard } from '../src/client/store/projection/contacts.ts'

const DID = 'did:web:did.md:nine.testrun.org:hrdcv7qkr'
const fresh = () => { const patch = didContactPatch(DID); return { cardId: patch.cardId, card: applyContactSet(undefined, patch)! } }
const withName = (card: LocalJmapContactCard, cardId: string, name: string, source: Parameters<typeof contactNamePatch>[3]) => {
  const write = contactNamePatch(cardId, card, name, source)
  return write ? applyContactSet(card, write)! : card
}

describe('a contact\'s name and where it came from', () => {
  test('a card has none until something names it, and the name records its source', () => {
    const { cardId, card } = fresh()
    expect(contactDisplayName(card)).toBeUndefined()
    const named = withName(card, cardId, '  Bob   Builder ', 'mail')
    expect(contactDisplayName(named)).toBe('Bob Builder')
    expect(nameSourceOf(named)).toBe('mail')
  })

  test('a stronger source replaces a weaker one\'s name, never the other way', () => {
    const { cardId, card } = fresh()
    let current = withName(card, cardId, 'From Mail', 'mail')
    current = withName(current, cardId, 'From Invite', 'invite')
    expect(contactDisplayName(current)).toBe('From Invite')
    expect(withName(current, cardId, 'Later Mail Name', 'mail')).toBe(current)
    expect(contactNamePatch(cardId, current, 'Later Mail Name', 'mail')).toBeUndefined()
    expect(contactDisplayName(withName(current, cardId, 'By Hand', 'user'))).toBe('By Hand')
  })

  test('writing the same name from the same source changes nothing', () => {
    const { cardId, card } = fresh()
    const named = withName(card, cardId, 'Bob', 'invite')
    expect(contactNamePatch(cardId, named, 'Bob', 'invite')).toBeUndefined()
  })

  test('a name nothing records is a person\'s, so no found-out name replaces it', () => {
    const { cardId, card } = fresh()
    const imported = { ...card, name: { full: 'Imported' } } as LocalJmapContactCard
    expect(nameSourceOf(imported)).toBe('user')
    expect(contactNamePatch(cardId, imported, 'From Mail', 'mail')).toBeUndefined()
  })

  test('JMAP: a name written through ContactCard/set is marked as a person\'s, and the source itself cannot be written', () => {
    const { card } = fresh()
    const update = contactCardSet({ update: { [card.id]: { name: { full: 'Mine' } } } }, [card])
    expect(update.updated[card.id]).toBeNull()
    const next = applyContactSet(card, (update.intents[0]!.payload as never))!
    expect(contactDisplayName(next)).toBe('Mine')
    expect(nameSourceOf(next)).toBe('user')
    const forged = contactCardSet({ update: { [card.id]: { [SOURCES_PROPERTY]: { name: 'user' } } } }, [card])
    expect(forged.notUpdated[card.id]?.type).toBe('forbidden')
  })
})

describe('a contact\'s picture', async () => {
  const { avatarOfHeader } = await import('../src/client/pgp/mime.ts')
  const { contactAvatar, contactAvatarPatch } = await import('../src/client/store/projection/contacts.ts')
  const PNG = btoa(String.fromCharCode(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3))

  test('Chat-User-Avatar: base64: is the picture, 0 removes it, the rest says nothing', () => {
    expect(avatarOfHeader(`base64:${PNG}`)).toBe(`data:image/png;base64,${PNG}`)
    expect(avatarOfHeader(`base64:${PNG.slice(0, 8)}  ${PNG.slice(8)}`)).toBe(`data:image/png;base64,${PNG}`) // folded
    expect(avatarOfHeader('0')).toBeNull()
    expect(avatarOfHeader('avatar.jpg')).toBeUndefined() // the older form names an attached part
    expect(avatarOfHeader(`base64:${btoa('not an image at all')}`)).toBeUndefined()
    expect(avatarOfHeader(undefined)).toBeUndefined()
  })

  test('the card takes a signed picture, changes with it, loses it when removed, and a picture put there by a person stays', () => {
    const { cardId, card } = fresh()
    const uri = `data:image/png;base64,${PNG}`
    const set = applyContactSet(card, contactAvatarPatch(cardId, card, uri)!)!
    expect(contactAvatar(set)).toBe(uri)
    expect(contactAvatarPatch(cardId, set, uri)).toBeUndefined()
    const other = `data:image/png;base64,${PNG.slice(0, -4)}AAAA`
    expect(contactAvatar(applyContactSet(set, contactAvatarPatch(cardId, set, other)!)!)).toBe(other)
    expect(contactAvatar(applyContactSet(set, contactAvatarPatch(cardId, set, null)!)!)).toBeUndefined()
    expect(contactAvatarPatch(cardId, card, null)).toBeUndefined() // nothing to remove

    const byHand = contactCardSet({ update: { [card.id]: { media: { avatar: { '@type': 'Media', kind: 'photo', uri: 'data:image/png;base64,AAAA' } } } } }, [card])
    const mine = applyContactSet(card, byHand.intents[0]!.payload as never)!
    expect(contactAvatarPatch(cardId, mine, uri)).toBeUndefined()
    expect(contactAvatarPatch(cardId, mine, null)).toBeUndefined()
  })
})

describe('this identity\'s own name and picture', async () => {
  const { ownNamePatch, ownAvatarPatch, contactAvatar } = await import('../src/client/store/projection/contacts.ts')

  test('a name set by hand is the strongest, is not rewritten when unchanged, and can be removed', () => {
    const { cardId, card } = fresh()
    const named = applyContactSet(card, ownNamePatch(cardId, card, '  Me   Myself ')!)!
    expect(contactDisplayName(named)).toBe('Me Myself')
    expect(nameSourceOf(named)).toBe('user')
    expect(ownNamePatch(cardId, named, 'Me Myself')).toBeUndefined()
    expect(contactNamePatch(cardId, named, 'Seen on a mail', 'mail')).toBeUndefined()
    const cleared = applyContactSet(named, ownNamePatch(cardId, named, null)!)!
    expect(contactDisplayName(cleared)).toBeUndefined()
    expect(ownNamePatch(cardId, cleared, null)).toBeUndefined()
  })

  test('a picture set by hand is kept, and a signed one does not replace it', async () => {
    const { contactAvatarPatch } = await import('../src/client/store/projection/contacts.ts')
    const { cardId, card } = fresh()
    const mine = 'data:image/jpeg;base64,/9j/AAAA'
    const set = applyContactSet(card, ownAvatarPatch(cardId, card, mine)!)!
    expect(contactAvatar(set)).toBe(mine)
    expect(ownAvatarPatch(cardId, set, mine)).toBeUndefined()
    expect(contactAvatarPatch(cardId, set, 'data:image/png;base64,iVBORw0KGgo=')).toBeUndefined()
    expect(contactAvatar(applyContactSet(set, ownAvatarPatch(cardId, set, null)!)!)).toBeUndefined()
  })
})

test('the sources of a card\'s name and picture are one property, and cards from before it are still read', () => {
  const { cardId, card } = fresh()
  const named = withName(card, cardId, 'Bob', 'mail')
  expect(named['biset.md:sources']).toEqual({ name: 'mail' })
  expect('biset.md:nameSource' in named).toBe(false)
  const legacy = { ...card, name: { full: 'Old' }, 'biset.md:nameSource': 'mail' } as LocalJmapContactCard
  expect(nameSourceOf(legacy)).toBe('mail')
  expect(contactNamePatch(cardId, legacy, 'New', 'signed')).toBeDefined()
})
