// This identity's own profile -- the name and the picture it shows the people it writes to -- lives on its own card in the
// contact list (store/projection/contacts.ts), like anyone's. The account page edits it here; what is sent to others is made
// from the same card (main.ts).

interface OwnProfileView { name?: string; avatar?: string }

export interface ProfileConfig {
  current(): Promise<OwnProfileView>
  /** `null` removes the name. */
  setName(name: string | null): Promise<void>
  /** The picture (a small JPEG data URL, made by renderAvatar); `null` removes it. */
  setAvatar(avatar: string | null): Promise<void>
}

/** Delta Chat reads a picture from a header it limits to 32 KB, so the picture is kept to 20 KB of image. */
const AVATAR_MAX_BYTES = 20 * 1024

/** Which part of an image is shown: `zoom` 1 shows the largest square, 2 half its side, and so on; `cx`, `cy` is the centre of the
 * square in image pixels. */
export interface Crop { zoom: number; cx: number; cy: number }

export const MAX_ZOOM = 5

/** The square of the image the crop shows (top-left corner and side, in image pixels), kept inside the image. */
export function cropRect(width: number, height: number, crop: Crop): { sx: number; sy: number; side: number } {
  const zoom = Math.min(MAX_ZOOM, Math.max(1, crop.zoom))
  const side = Math.min(width, height) / zoom
  const sx = Math.min(width - side, Math.max(0, crop.cx - side / 2))
  const sy = Math.min(height - side, Math.max(0, crop.cy - side / 2))
  return { sx, sy, side }
}

/** The crop that shows the middle of the image at zoom 1. */
export const centeredCrop = (width: number, height: number): Crop => ({ zoom: 1, cx: width / 2, cy: height / 2 })

/** Draws the crop of `bitmap` into a `size` square canvas. */
export function drawCrop(canvas: HTMLCanvasElement, bitmap: ImageBitmap, crop: Crop): void {
  const { sx, sy, side } = cropRect(bitmap.width, bitmap.height, crop)
  const context = canvas.getContext('2d')!
  context.clearRect(0, 0, canvas.width, canvas.height)
  context.drawImage(bitmap, sx, sy, side, side, 0, 0, canvas.width, canvas.height)
}

/** The crop as a small square JPEG data URL (shrunk until it fits AVATAR_MAX_BYTES). */
export function renderAvatar(bitmap: ImageBitmap, crop: Crop): string {
  for (const size of [256, 192, 128, 96]) {
    const canvas = document.createElement('canvas')
    canvas.width = canvas.height = size
    drawCrop(canvas, bitmap, crop)
    for (const quality of [0.85, 0.7, 0.55, 0.4]) {
      const url = canvas.toDataURL('image/jpeg', quality)
      if (Math.floor((url.length - url.indexOf(',') - 1) * 3 / 4) <= AVATAR_MAX_BYTES) return url
    }
  }
  throw new Error('This picture cannot be made small enough')
}

/** Asks for a picture file. */
export function chooseImage(): Promise<File | undefined> {
  return new Promise(resolve => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = 'image/*'
    input.onchange = () => resolve(input.files?.[0])
    input.oncancel = () => resolve(undefined)
    input.click()
  })
}

/** Said when the profile changed, so a view that shows it looks again. */
export const PROFILE_CHANGED = 'biset-profile-changed'
