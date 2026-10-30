// @vitest-environment happy-dom
// What was written with no account is kept across the trip to make one, and comes back once.
import { beforeEach, expect, test } from 'vitest'
import { composeDraft, savePendingSend, takePendingSend } from '../../src/client/app/ui/pages/compose-page.tsx'

beforeEach(() => { sessionStorage.clear(); composeDraft.set({ to: '', subject: '' }) })

test('recipients, subject and message come back after the sign-up, once', () => {
  composeDraft.set({ to: 'alice@gmail.com bob@example.org ', subject: 'Lunch' })
  savePendingSend('Are you free at noon?')
  composeDraft.set({ to: '', subject: '' }) // the page was left and loaded again
  expect(takePendingSend()).toBe('Are you free at noon?')
  expect(composeDraft.get()).toEqual({ to: 'alice@gmail.com bob@example.org ', subject: 'Lunch' })
  expect(takePendingSend()).toBeUndefined()
})

test('nothing kept, nothing back', () => {
  expect(takePendingSend()).toBeUndefined()
})
