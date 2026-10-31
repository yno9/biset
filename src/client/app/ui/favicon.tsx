// The tab's icon is this identity's avatar: its picture, cropped round, or the face drawn from its name when it has none (the same
// that the avatar shows, generated-avatar.tsx). Before there is an identity the page's own icon stays.
import Avatar from 'boring-avatars'
import { useEffect } from 'react'
import { flushSync } from 'react-dom'
import { createRoot } from 'react-dom/client'
import { useStore } from '../react/store.ts'
import { accountConfig } from './account/state.ts'
import { useOwnProfile } from './account/use-own-profile.ts'
import { partColors, usePartColors } from './color-settings.ts'

const SIZE = 64

/** The generated avatar for `name` as an SVG document: drawn into a detached node and read back, so it is the very drawing the page shows
 * (react-dom/server would write it out too, but is some 60 KB of the page for that). React refuses a synchronous render from inside an
 * effect, so this is called from a timer, never from the effect itself. */
export function generatedAvatarSvg(name: string): string {
  const host = document.createElement('div')
  const root = createRoot(host)
  flushSync(() => root.render(<Avatar name={name || '?'} variant="beam" size={SIZE} colors={[...partColors('avatar')]} />))
  const svg = host.innerHTML
  root.unmount()
  return svg.includes('xmlns=') ? svg : svg.replace('<svg', '<svg xmlns="http://www.w3.org/2000/svg"')
}

/** A picture cropped to a circle, as a PNG data URL; the picture itself when this browser cannot draw it. */
function roundPicture(picture: string): Promise<string> {
  return new Promise(resolve => {
    const image = new Image()
    image.onload = () => {
      const canvas = document.createElement('canvas')
      canvas.width = canvas.height = SIZE
      const context = canvas.getContext('2d')
      if (!context) { resolve(picture); return }
      context.beginPath()
      context.arc(SIZE / 2, SIZE / 2, SIZE / 2, 0, Math.PI * 2)
      context.clip()
      context.drawImage(image, 0, 0, SIZE, SIZE)
      resolve(canvas.toDataURL('image/png'))
    }
    image.onerror = () => resolve(picture)
    image.src = picture
  })
}

const iconLink = (): HTMLLinkElement | null => document.querySelector<HTMLLinkElement>('link[rel~="icon"]')
let original: { href: string; type: string } | undefined

export function Favicon() {
  const config = useStore(accountConfig)
  const did = config?.did ?? undefined
  const own = useOwnProfile(config?.profile)
  const colors = usePartColors('avatar')
  useEffect(() => {
    const link = iconLink()
    if (!link) return
    original ??= { href: link.href, type: link.type }
    if (!did) { link.href = original.href; link.type = original.type; return }
    // The address the identity is published at (a did:vh DID names none).
    const label = config?.wallet?.handle ?? ''
    let current = true
    const show = (href: string, type: string) => { if (current) { link.type = type; link.href = href } }
    let timer: ReturnType<typeof setTimeout> | undefined
    if (own.avatar) void roundPicture(own.avatar).then(href => show(href, href.startsWith('data:image/png') ? 'image/png' : 'image/jpeg'))
    else timer = setTimeout(() => show(`data:image/svg+xml;charset=utf-8,${encodeURIComponent(generatedAvatarSvg(own.name?.trim() || label))}`, 'image/svg+xml'), 0)
    return () => { current = false; clearTimeout(timer) }
  }, [did, own.name, own.avatar, colors])
  return null
}
