// This identity's own profile -- the name and the picture it shows the people it writes to -- lives on its own card in the
// contact list (store/projection/contacts.ts), like anyone's. The account page edits it here; what is sent to others is made
// from the same card (main.ts).

export interface OwnProfileView { name?: string; avatar?: string }

export interface ProfileConfig {
  current(): Promise<OwnProfileView>
  /** `null` removes the name. */
  setName(name: string | null): Promise<void>
  /** `null` removes the picture; a file is fitted (below) first. */
  setAvatar(file: Blob | null): Promise<void>
}

/** Delta Chat reads a picture from a header it limits to 32 KB, so the picture is kept to 20 KB of image. */
export const AVATAR_MAX_BYTES = 20 * 1024

/** An image file as a small square JPEG data URL (centered crop, shrunk until it fits). */
export async function fitAvatar(file: Blob): Promise<string> {
  const bitmap = await createImageBitmap(file)
  try {
    for (const size of [256, 192, 128, 96]) {
      const canvas = document.createElement('canvas')
      canvas.width = canvas.height = size
      const context = canvas.getContext('2d')!
      const side = Math.min(bitmap.width, bitmap.height)
      context.drawImage(bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side, 0, 0, size, size)
      for (const quality of [0.85, 0.7, 0.55, 0.4]) {
        const url = canvas.toDataURL('image/jpeg', quality)
        if (Math.floor((url.length - url.indexOf(',') - 1) * 3 / 4) <= AVATAR_MAX_BYTES) return url
      }
    }
  } finally { bitmap.close() }
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
