// @vitest-environment happy-dom
// A message waiting for the account goes out once the account can send: DIDComm is set up first, and its sending part follows.
import { expect, test, vi } from 'vitest'
import { composeDraft, configureComposePage, sendComposedWhenReady } from '../../src/client/app/ui/pages/compose-page.tsx'

const fast = { timeoutMs: 2000, pollMs: 5 }

test('it tries again while the sending part is still connecting, then sends', async () => {
  const sendMessage = vi.fn()
    .mockRejectedValueOnce(new Error('DIDComm is still connecting for this Wallet session'))
    .mockRejectedValueOnce(new Error('DIDComm is still connecting for this Wallet session'))
    .mockResolvedValueOnce(undefined)
  configureComposePage({ selfAddress: 'me', selfDid: 'did:vh:me', sendMessage })
  composeDraft.set({ to: 'alice@gmail.com ', subject: 'Lunch' })
  await sendComposedWhenReady('hello', fast)
  expect(sendMessage).toHaveBeenCalledTimes(3)
  expect(sendMessage).toHaveBeenLastCalledWith({ toAddrs: ['alice@gmail.com'], subject: 'Lunch', body: 'hello' })
  expect(composeDraft.get()).toEqual({ to: '', subject: '' })
})

test('any other failure is the end of it', async () => {
  const sendMessage = vi.fn().mockRejectedValue(new Error('A DIDComm message needs a recipient'))
  configureComposePage({ selfAddress: 'me', selfDid: 'did:vh:me', sendMessage })
  composeDraft.set({ to: 'alice@gmail.com ', subject: '' })
  await expect(sendComposedWhenReady('hello', fast)).rejects.toThrow('needs a recipient')
  expect(sendMessage).toHaveBeenCalledTimes(1)
})

test('still connecting for good: it gives up with that reason', async () => {
  const sendMessage = vi.fn().mockRejectedValue(new Error('DIDComm is still connecting for this Wallet session'))
  configureComposePage({ selfAddress: 'me', selfDid: 'did:vh:me', sendMessage })
  composeDraft.set({ to: 'alice@gmail.com ', subject: '' })
  await expect(sendComposedWhenReady('hello', { timeoutMs: 60, pollMs: 5 })).rejects.toThrow('still connecting')
})
