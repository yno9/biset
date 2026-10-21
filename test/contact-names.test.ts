import { describe, expect, test } from 'vitest'
import { applyContactSet, contactCardSet, contactDisplayName, contactNamePatch, didContactPatch, nameSourceOf, NAME_SOURCE_PROPERTY, type LocalJmapContactCard } from '../src/client/store/projection/contacts.ts'

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
    const forged = contactCardSet({ update: { [card.id]: { [NAME_SOURCE_PROPERTY]: 'user' } } }, [card])
    expect(forged.notUpdated[card.id]?.type).toBe('forbidden')
  })
})
