// @vitest-environment happy-dom
import { act, cleanup, render, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, test } from 'vitest'
import { Favicon, generatedAvatarSvg } from '../../src/client/app/ui/favicon.tsx'
import { accountConfig } from '../../src/client/app/ui/account/state.ts'

const DID = 'did:vh:QmPLLKQAYjB94BqYvFx27z5xNb2CjZG6kxUWucjWwPCjDv'
const link = () => document.querySelector<HTMLLinkElement>('link[rel~="icon"]')!
const profile = (current: { name?: string; avatar?: string }) => ({ current: async () => current, setName: async () => {}, setAvatar: async () => {} })

beforeEach(() => { document.head.innerHTML = '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,original">' })
afterEach(() => { cleanup(); act(() => accountConfig.set(undefined)); document.head.innerHTML = '' })

test('the generated avatar is an SVG document drawn from the name, and the same for the same name', () => {
  const svg = generatedAvatarSvg('Quiet Heron')
  expect(svg.startsWith('<svg')).toBe(true)
  expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"')
  expect(generatedAvatarSvg('Quiet Heron').replace(/ id="[^"]*"|url\(#[^)]*\)/g, '')).toBe(svg.replace(/ id="[^"]*"|url\(#[^)]*\)/g, ''))
  expect(generatedAvatarSvg('Amber Fern').replace(/ id="[^"]*"|url\(#[^)]*\)/g, '')).not.toBe(svg.replace(/ id="[^"]*"|url\(#[^)]*\)/g, ''))
})

test('without a picture the tab icon is the avatar drawn from the display name; without an identity it is the page\'s own', async () => {
  render(<Favicon />)
  expect(link().href).toContain('original') // no identity yet
  act(() => accountConfig.set({ did: DID, profile: profile({ name: 'Quiet Heron' }) } as never))
  await waitFor(() => expect(link().href.startsWith('data:image/svg+xml;charset=utf-8,')).toBe(true))
  expect(decodeURIComponent(link().href.split(',').slice(1).join(','))).toContain('<svg')
  expect(link().type).toBe('image/svg+xml')
  act(() => accountConfig.set(undefined))
  await waitFor(() => expect(link().href).toContain('original'))
})

test('with a picture the tab icon is that picture (round when the browser can draw it)', async () => {
  const picture = 'data:image/jpeg;base64,/9j/AAAA'
  render(<Favicon />)
  act(() => accountConfig.set({ did: DID, profile: profile({ name: 'Quiet Heron', avatar: picture }) } as never))
  await waitFor(() => expect(link().href).not.toContain('original'), { timeout: 3000 })
  expect(link().href.startsWith('data:image/')).toBe(true)
  expect(link().href.startsWith('data:image/svg+xml')).toBe(false) // a picture, not the drawn face
})
