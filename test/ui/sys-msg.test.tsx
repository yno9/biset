// @vitest-environment happy-dom
import { act, render } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { SysMsg, showSysMsg } from '../../src/client/app/ui/sys-msg.tsx'

beforeEach(() => { vi.useFakeTimers() })
afterEach(() => { vi.useRealTimers() })

test('a message shows, then hides after its duration', () => {
  const { container } = render(<SysMsg />)
  const toast = () => container.querySelector('#sys-msg')!
  expect(toast().classList.contains('show')).toBe(false)

  act(() => showSysMsg('Other devices removed', 1000))
  expect(toast().textContent).toBe('Other devices removed')
  expect(toast().classList.contains('show')).toBe(true)

  act(() => { vi.advanceTimersByTime(999) })
  expect(toast().classList.contains('show')).toBe(true)
  act(() => { vi.advanceTimersByTime(2) })
  expect(toast().classList.contains('show')).toBe(false)
})

test('a newer message replaces the older one and restarts the timer', () => {
  const { container } = render(<SysMsg />)
  act(() => showSysMsg('first', 1000))
  act(() => { vi.advanceTimersByTime(800) })
  act(() => showSysMsg('second', 1000))
  act(() => { vi.advanceTimersByTime(800) })
  expect(container.querySelector('#sys-msg')!.textContent).toBe('second')
  expect(container.querySelector('#sys-msg')!.classList.contains('show')).toBe(true)
  act(() => { vi.advanceTimersByTime(300) })
  expect(container.querySelector('#sys-msg')!.classList.contains('show')).toBe(false)
})
