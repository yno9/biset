// The system toast: a short line that shows for a moment ("Other devices removed", ...).
import { createStore, useStore } from '../react/store.ts'
import { mountIsland } from '../react/island.tsx'

const toast = createStore({ text: '', shown: false })
let hideTimer: ReturnType<typeof setTimeout> | undefined

export function showSysMsg(text: string, durationMs = 1800): void {
  toast.set({ text, shown: true })
  clearTimeout(hideTimer)
  hideTimer = setTimeout(() => toast.set(current => ({ ...current, shown: false })), durationMs)
}

export function SysMsg() {
  const { text, shown } = useStore(toast)
  return <div id="sys-msg" className={shown ? 'show' : undefined}>{text}</div>
}

export function mountSysMsg(): void {
  mountIsland('sys-msg-root', <SysMsg />)
}
