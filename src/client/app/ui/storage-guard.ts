// biset keeps its vault, keys and wallet session in IndexedDB. Where the browser has none (iOS Lockdown Mode, some private modes),
// nothing here can work, and a blank page would not say why: this says it, and stops the app from starting.
// It is the first import of main.ts; throwing from it keeps the rest of the entry module from being evaluated.
if (!('indexedDB' in globalThis)) {
  const notice = document.createElement('div')
  notice.id = 'no-storage'
  const heading = document.createElement('h1')
  heading.textContent = 'biset cannot store data in this browser'
  const body = document.createElement('p')
  body.textContent = 'It keeps your mail and keys encrypted on this device, which needs the browser’s IndexedDB. It is not available here (Lockdown Mode and some private windows turn it off). Open biset in another browser, or allow this site in the browser’s settings.'
  notice.append(heading, body)
  document.body.replaceChildren(notice)
  throw new Error('IndexedDB is not available')
}
