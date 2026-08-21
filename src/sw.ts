/** Service worker shell. Large vault restore must run in a foreground client. */
type ServiceWorkerScope = EventTarget & {
  skipWaiting(): Promise<void>
  clients: { claim(): Promise<void> }
}
type ExtendableEvent = Event & { waitUntil(promise: Promise<unknown>): void }

// The client tsconfig deliberately excludes WebWorker globals. Keep the small
// boundary local instead of allowing worker types into all browser modules.
const worker = globalThis as unknown as ServiceWorkerScope

worker.addEventListener('install', () => {
  void worker.skipWaiting()
})

worker.addEventListener('activate', (event) => {
  ;(event as ExtendableEvent).waitUntil(worker.clients.claim())
})
