import { describe, expect, test } from 'vitest'
import { centeredCrop, cropRect, MAX_ZOOM } from '../src/client/app/ui/account/profile.ts'

describe('which square of the picture is shown', () => {
  test('zoom 1 is the largest square, centred; a wide picture shows its middle', () => {
    expect(cropRect(400, 200, centeredCrop(400, 200))).toEqual({ sx: 100, sy: 0, side: 200 })
    expect(cropRect(200, 400, centeredCrop(200, 400))).toEqual({ sx: 0, sy: 100, side: 200 })
  })

  test('zooming in shrinks the square around the centre; zoom stays between 1 and the maximum', () => {
    expect(cropRect(200, 200, { zoom: 2, cx: 100, cy: 100 })).toEqual({ sx: 50, sy: 50, side: 100 })
    expect(cropRect(200, 200, { zoom: 99, cx: 100, cy: 100 }).side).toBe(200 / MAX_ZOOM)
    expect(cropRect(200, 200, { zoom: 0.1, cx: 100, cy: 100 }).side).toBe(200)
  })

  test('moving it stops at the edges of the picture', () => {
    expect(cropRect(200, 200, { zoom: 2, cx: -500, cy: -500 })).toEqual({ sx: 0, sy: 0, side: 100 })
    expect(cropRect(200, 200, { zoom: 2, cx: 999, cy: 999 })).toEqual({ sx: 100, sy: 100, side: 100 })
    expect(cropRect(400, 200, { zoom: 1, cx: 0, cy: 100 })).toEqual({ sx: 0, sy: 0, side: 200 })
  })
})
