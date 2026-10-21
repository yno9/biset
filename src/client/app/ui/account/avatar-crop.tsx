// Choosing which part of a picture becomes the avatar: the image under a round window, dragged to move and zoomed with the slider
// or the wheel. `cropAvatar(file)` opens it and answers with the small JPEG data URL (account/profile.ts renderAvatar), or undefined
// when it is cancelled.
import { useEffect, useRef, useState } from 'react'
import { createStore, useStore } from '../../react/store.ts'
import { centeredCrop, cropRect, drawCrop, MAX_ZOOM, renderAvatar, type Crop } from './profile.ts'

interface Request { file: Blob; resolve(avatar: string | undefined): void }
const request = createStore<Request | undefined>(undefined)

export function cropAvatar(file: Blob): Promise<string | undefined> {
  return new Promise(resolve => {
    request.get()?.resolve(undefined)
    request.set({ file, resolve })
  })
}

const PREVIEW = 240

export function AvatarCropDialog() {
  const current = useStore(request)
  const dialog = useRef<HTMLDialogElement>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  const [bitmap, setBitmap] = useState<ImageBitmap>()
  const [crop, setCrop] = useState<Crop>({ zoom: 1, cx: 0, cy: 0 })
  const [error, setError] = useState('')
  const drag = useRef<{ x: number; y: number } | undefined>(undefined)

  useEffect(() => {
    const el = dialog.current!
    if (!current) { if (el.open) el.close(); setBitmap(undefined); return }
    setError('')
    let live = true
    createImageBitmap(current.file).then(found => {
      if (!live) { found.close(); return }
      setBitmap(found)
      setCrop(centeredCrop(found.width, found.height))
    }, () => { if (live) setError('This file is not a picture') })
    if (!el.open) el.showModal()
    return () => { live = false }
  }, [current])

  useEffect(() => { if (bitmap && canvas.current) drawCrop(canvas.current, bitmap, crop) }, [bitmap, crop])

  const finish = (avatar: string | undefined) => {
    const open = request.get()
    request.set(undefined)
    open?.resolve(avatar)
  }

  const zoomTo = (zoom: number) => setCrop(previous => ({ ...previous, zoom: Math.min(MAX_ZOOM, Math.max(1, zoom)) }))
  const move = (dx: number, dy: number) => {
    if (!bitmap) return
    setCrop(previous => {
      const { side } = cropRect(bitmap.width, bitmap.height, previous)
      const scale = side / PREVIEW // image pixels per screen pixel
      return { ...previous, cx: previous.cx - dx * scale, cy: previous.cy - dy * scale }
    })
  }

  return (
    <dialog ref={dialog} id="avatar-crop" onClose={() => { if (request.get()) finish(undefined) }}
      style={{ margin: 'auto', padding: 16, border: '1px solid color-mix(in srgb,CanvasText 20%,transparent)', borderRadius: 12, background: 'Canvas', color: 'CanvasText' }}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
        <div style={{ position: 'relative', width: PREVIEW, height: PREVIEW, touchAction: 'none', cursor: 'grab' }}
          onPointerDown={event => { drag.current = { x: event.clientX, y: event.clientY }; event.currentTarget.setPointerCapture(event.pointerId) }}
          onPointerMove={event => { if (drag.current) { move(event.clientX - drag.current.x, event.clientY - drag.current.y); drag.current = { x: event.clientX, y: event.clientY } } }}
          onPointerUp={() => { drag.current = undefined }}
          onWheel={event => zoomTo(crop.zoom * (event.deltaY < 0 ? 1.08 : 1 / 1.08))}>
          <canvas ref={canvas} width={PREVIEW} height={PREVIEW} style={{ display: 'block', background: '#0002' }} />
          {/* The round window: everything outside the circle is dimmed. */}
          <div style={{ position: 'absolute', inset: 0, borderRadius: '50%', boxShadow: '0 0 0 400px rgba(0,0,0,.55)', pointerEvents: 'none' }} />
        </div>
        <input type="range" aria-label="Zoom" min={1} max={MAX_ZOOM} step={0.01} value={crop.zoom} style={{ width: PREVIEW }} onChange={event => zoomTo(Number(event.target.value))} />
        {error ? <div role="alert" style={{ color: '#ff3b30', fontSize: 12 }}>{error}</div> : null}
        <div style={{ display: 'flex', gap: 8 }}>
          <button type="button" id="avatar-crop-cancel" onClick={() => finish(undefined)}>Cancel</button>
          <button type="button" id="avatar-crop-save" disabled={!bitmap}
            onClick={() => { try { finish(renderAvatar(bitmap!, crop)) } catch (e) { setError(e instanceof Error ? e.message : String(e)) } }}>Save</button>
        </div>
      </div>
    </dialog>
  )
}
