// @vitest-environment happy-dom
import { act, cleanup, render, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, test } from 'vitest'
import { Favicon, generatedAvatarSvg } from '../../src/client/app/ui/favicon.tsx'
import { accountConfig } from '../../src/client/app/ui/account/state.ts'
import { provisionalAlias } from '../../src/client/app/ui/signup-preload.ts'

const DID = 'did:vh:QmPLLKQAYjB94BqYvFx27z5xNb2CjZG6kxUWucjWwPCjDv'
const link = () => document.querySelector<HTMLLinkElement>('link[rel~="icon"]')!
// The drawing without the ids React gives its parts (they differ from one drawing to the next).
const drawing = (): string => decodeURIComponent(link().href.split(',').slice(1).join(',')).replace(/\bid="[^"]*"/g, 'id=""').replace(/url\(#[^)]*\)/g, 'url(#)')
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

test('without a picture the tab icon is the avatar drawn from the display name; without an identity it is the face of the name the account will be made with', async () => {
  render(<Favicon />)
  // No identity yet: the stand-in, the face of the provisional name (the page's own icon is not used).
  await waitFor(() => expect(link().href.startsWith('data:image/svg+xml;charset=utf-8,')).toBe(true))
  const standIn = drawing()
  expect(link().href).not.toContain('original')
  act(() => accountConfig.set({ did: DID, profile: profile({ name: 'Quiet Heron' }) } as never))
  await waitFor(() => expect(drawing()).not.toBe(standIn))
  expect(drawing()).toContain('<svg')
  expect(link().type).toBe('image/svg+xml')
  // Back to no identity: the stand-in again.
  act(() => accountConfig.set(undefined))
  await waitFor(() => expect(drawing()).toBe(standIn))
  // The provisional name changes (the sign-up page's field, a click on its face): the icon follows.
  act(() => provisionalAlias.set('123456'))
  await waitFor(() => expect(drawing()).not.toBe(standIn))
})


test('with a picture the tab icon is that picture (round when the browser can draw it)', async () => {
  const picture = 'data:image/jpeg;base64,/9j/AAAA'
  render(<Favicon />)
  act(() => accountConfig.set({ did: DID, profile: profile({ name: 'Quiet Heron', avatar: picture }) } as never))
  await waitFor(() => expect(link().href).not.toContain('original'), { timeout: 3000 })
  expect(link().href.startsWith('data:image/')).toBe(true)
  expect(link().href.startsWith('data:image/svg+xml')).toBe(false) // a picture, not the drawn face
})
