import { expect, test } from 'vitest'
import { bubbleLeft } from '../../src/client/app/ui/account/tooltip.tsx'

test('a bubble is centred under its element', () => {
  expect(bubbleLeft(500, 100, 1000)).toBe(450)
})

test('and kept on the screen: an element at the right edge keeps its bubble beside it, not a bubble-width from the screen\'s edge', () => {
  // an icon centred at 873 on a 900 wide screen, a 76 wide bubble: pushed in by just what it takes
  expect(bubbleLeft(873, 76, 900)).toBe(816)
  // at the left edge too
  expect(bubbleLeft(25, 73, 900)).toBe(8)
})
