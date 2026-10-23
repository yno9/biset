// @vitest-environment happy-dom
import { cleanup, render } from '@testing-library/react'
import { afterEach, expect, test } from 'vitest'
import { GeneratedAvatar } from '../../src/client/app/ui/generated-avatar.tsx'

afterEach(cleanup)
// The SVG's parts carry ids that React makes anew for each render; the drawing is what is compared.
const svgOf = (name: string): string => render(<GeneratedAvatar name={name} />).container.querySelector('svg')!.outerHTML.replace(/ id="[^"]*"/g, '').replace(/url\(#[^)]*\)/g, 'url(#)')

test('a generated avatar is an SVG drawn from the name: the same name gives the same face, another name another', () => {
  expect(svgOf('Quiet Heron')).toBe(svgOf('Quiet Heron'))
  expect(svgOf('Quiet Heron')).not.toBe(svgOf('Amber Fern'))
})

test('it is hidden from assistive technology (the name is next to it), and fills its box', () => {
  const { container } = render(<GeneratedAvatar name="Quiet Heron" />)
  expect(container.querySelector('.avatar-generated')!.getAttribute('aria-hidden')).toBe('true')
  expect(container.querySelector('svg')!.getAttribute('width')).toBe('100%')
})
