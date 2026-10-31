/** Service worker: the app's one page is kept in the browser and started from there, offline too. A newer worker (the page changed) installs in
 * the background and waits; the page offers the update, and `skip-waiting` from it makes the new worker take over. */
type ServiceWorkerScope = EventTarget & {
  skipWaiting(): Promise<void>
  clients: { claim(): Promise<void> }
}
type ExtendableEvent = Event & { waitUntil(promise: Promise<unknown>): void }
type FetchEvent = Event & { request: Request; respondWith(response: Promise<Response> | Response): void }
type WorkerMessage = Event & { data: unknown }

// The client tsconfig deliberately excludes WebWorker globals. Keep the small
// boundary local instead of allowing worker types into all browser modules.
const worker = globalThis as unknown as ServiceWorkerScope
declare const __BUILD_ID__: string
/** The fonts to keep from the first visit (the build lists them). */
declare const __PRECACHE__: readonly string[]

const CACHE = `biset-${__BUILD_ID__}`
const SHELL = '/'

// No skipWaiting here: a new version waits for the person's go-ahead.
worker.addEventListener('install', (event) => {
  ;(event as ExtendableEvent).waitUntil(caches.open(CACHE).then(cache => cache.addAll([SHELL, ...__PRECACHE__].map(path => new Request(path, { cache: 'reload' })))))
})

worker.addEventListener('activate', (event) => {
  ;(event as ExtendableEvent).waitUntil((async () => {
    for (const name of await caches.keys()) if (name.startsWith('biset-') && name !== CACHE) await caches.delete(name)
    await worker.clients.claim()
  })())
})

worker.addEventListener('message', (event) => {
  if ((event as WorkerMessage).data === 'skip-waiting') void worker.skipWaiting()
})

// The page is one file for every path (the path is read by the app): a navigation is answered with it from the cache. A POST (the wallet's
// last page submitting to the callback) and everything that is not a navigation go to the network as they are.
worker.addEventListener('fetch', (event) => {
  const { request } = event as FetchEvent
  if (request.method !== 'GET') return
  const url = new URL(request.url)
  if (url.origin !== location.origin) return
  // A font: from the cache, and when it is not there yet (a Japanese piece, the first time a text needs it) from the network, and then kept.
  if (url.pathname.startsWith('/fonts/')) {
    ;(event as FetchEvent).respondWith(caches.open(CACHE).then(async cache => {
      const kept = await cache.match(request)
      if (kept) return kept
      const response = await fetch(request)
      if (response.ok) void cache.put(request, response.clone())
      return response
    }))
    return
  }
  if (request.mode !== 'navigate' || url.pathname.startsWith('/.well-known/')) return
  ;(event as FetchEvent).respondWith(caches.open(CACHE).then(async cache => (await cache.match(SHELL)) ?? fetch(request)))
})
