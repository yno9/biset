import { expect, test, describe } from 'bun:test'
import { ContactHistoryStore, ContactHistoryFullError } from '../../src/mail-mediator/contact-history-store.ts'

describe('ContactHistoryStore', () => {
  test('hasContact is false until record() is called', () => {
    const store = new ContactHistoryStore()
    expect(store.hasContact('y@biset.md', 'sender@example.com')).toBe(false)
    store.record('y@biset.md', 'sender@example.com')
    expect(store.hasContact('y@biset.md', 'sender@example.com')).toBe(true)
  })

  test('matching is case-insensitive on the counterparty address', () => {
    const store = new ContactHistoryStore()
    store.record('y@biset.md', 'Sender@Example.com')
    expect(store.hasContact('y@biset.md', 'sender@example.com')).toBe(true)
  })

  test('is scoped per-address, not global', () => {
    const store = new ContactHistoryStore()
    store.record('y@biset.md', 'sender@example.com')
    expect(store.hasContact('other@biset.md', 'sender@example.com')).toBe(false)
  })

  test('recording the same counterparty twice does not count twice toward the cap', () => {
    const store = new ContactHistoryStore()
    store.record('y@biset.md', 'sender@example.com')
    expect(() => store.record('y@biset.md', 'sender@example.com')).not.toThrow()
  })

  test('refuses beyond MAX_CONTACTS_PER_ADDRESS', () => {
    const store = new ContactHistoryStore()
    for (let i = 0; i < 10_000; i++) store.record('y@biset.md', `sender-${i}@example.com`)
    expect(() => store.record('y@biset.md', 'overflow@example.com')).toThrow(ContactHistoryFullError)
  })
})
