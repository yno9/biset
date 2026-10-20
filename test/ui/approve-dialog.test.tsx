// @vitest-environment happy-dom
import { act, cleanup, render, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

let approver: ((request: Promise<string>) => Promise<URLSearchParams>) | undefined
const mountDito = vi.fn()
vi.mock('../../src/client/identity/wallet/did-md-oauth.ts', () => ({ useDidMdWalletApprover: (fn: typeof approver) => { approver = fn } }))
vi.mock('../../src/client/identity/wallet/dito-embed.ts', () => ({ ditoEmbedOrigin: () => 'https://dito.did.md', mountDito: (...args: unknown[]) => mountDito(...args) }))

import { ApproveDialog, installDitoApprover } from '../../src/client/app/ui/approve-dialog.tsx'

beforeEach(() => {
  approver = undefined
  mountDito.mockReset()
  HTMLDialogElement.prototype.showModal = vi.fn(function (this: HTMLDialogElement) { this.setAttribute('open', '') })
})
afterEach(() => { cleanup() })

test('an approval hands dito\'s approve screen the request and returns its response, then the dialog closes', async () => {
  const response = new URLSearchParams({ state: 's' })
  const approve = vi.fn(async () => response)
  mountDito.mockResolvedValue({ approve, dispose: vi.fn() })
  installDitoApprover()
  const { container } = render(<ApproveDialog />)
  expect(container.querySelector('dialog')!.open).toBe(false)
  let result: Promise<URLSearchParams> | undefined
  act(() => { result = approver!(Promise.resolve('?request=x')) })
  await expect(result).resolves.toBe(response)
  expect(mountDito).toHaveBeenCalledWith(expect.any(HTMLIFrameElement), 'https://dito.did.md', 'approve', expect.any(Object))
  expect(approve).toHaveBeenCalledWith('?request=x')
  await waitFor(() => expect(container.querySelector('dialog')!.open).toBe(false))
})

test('closing the dialog before the frame answers is a refusal', async () => {
  mountDito.mockResolvedValue({ approve: () => new Promise(() => {}), dispose: vi.fn() })
  installDitoApprover()
  const { container } = render(<ApproveDialog />)
  let result: Promise<URLSearchParams> | undefined
  act(() => { result = approver!(Promise.resolve('?request=x')) })
  const refused = expect(result).rejects.toThrow('Cancelled.')
  await waitFor(() => expect(container.querySelector('dialog')!.open).toBe(true))
  act(() => { container.querySelector('dialog')!.dispatchEvent(new Event('close')) })
  await refused
})

test('a frame that fails to mount rejects the approval; a second one cannot open over the first', async () => {
  mountDito.mockRejectedValueOnce(new Error('The wallet did not respond.'))
  mountDito.mockReturnValue(new Promise(() => {})) // the frame loaded again for the next approval
  installDitoApprover()
  render(<ApproveDialog />)
  let first: Promise<URLSearchParams> | undefined
  let second: Promise<URLSearchParams> | undefined
  act(() => { first = approver!(Promise.resolve('?a')); second = approver!(Promise.resolve('?b')) })
  await expect(second).rejects.toThrow('Another approval is already open.')
  await expect(first).rejects.toThrow('The wallet did not respond.')
})
