// Updates of the app itself. The page is kept in the browser by the Service Worker (sw.ts) and started from there; when the server has a newer
// one, the browser installs it next to the old and it waits. `updateWaiting` says so, the account's foot offers it, and `applyUpdate` makes
// the new worker take over and reloads the page into it. The app looks for a new version once, when the page is loaded.
import { watchNetwork } from 'lft/net-activity'
import { createStore } from '../react/store.ts'

declare const __BISET_VERSION__: string
/** The version shown in the foot (major.minor of package.json). */
export const APP_VERSION: string = typeof __BISET_VERSION__ === 'undefined' ? 'dev' : __BISET_VERSION__

export const updateWaiting = createStore<boolean>(false)

let registration: ServiceWorkerRegistration | undefined

function watch(found: ServiceWorkerRegistration): void {
  const check = (): void => { if (found.waiting && navigator.serviceWorker.controller) updateWaiting.set(true) }
  check()
  found.addEventListener('updatefound', () => {
    const installing = found.installing
    installing?.addEventListener('statechange', () => { if (installing.state === 'installed') check() })
  })
}

/** Starts the Service Worker (where the browser has them and the page is served over https or from localhost) and watches for a newer one. */
export function startUpdates(): void {
  if (!('serviceWorker' in navigator) || location.protocol === 'file:') return
  navigator.serviceWorker.register('/sw.js').then(found => {
    registration = found
    watch(found)
    // The app looks for a newer version once, when the page is loaded (and not again while it stays open): the one thing it asks of its own server once it
    // is installed, written in the network log. (The browser itself looks on a navigation at most once a day, and does not say so to the page.)
    const call = watchNetwork().record({ url: '/sw.js', purpose: 'Looks for a newer version of the app', sends: 'Nothing about you (a request for one file)' })
    found.update().then(() => call.end(200), () => call.end('error'))
  }).catch(() => { /* no worker: the page is served as before */ })
}

/** The person's go-ahead: the waiting worker takes over, and the page reloads into the new version. */
export function applyUpdate(): void {
  const waiting = registration?.waiting
  if (!waiting) return
  navigator.serviceWorker.addEventListener('controllerchange', () => location.reload(), { once: true })
  waiting.postMessage('skip-waiting')
}
