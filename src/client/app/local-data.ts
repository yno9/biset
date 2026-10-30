// What this app keeps in the browser's plain storage about an identity and who it knew, and the purge of it (Disconnect, main.ts).
// Not the screen's own settings: the pane's width and the like stay. localStorage: where DIDs were found (did-links, vh-places, log-versions) and what avatars were sent (profileSent.*).
// sessionStorage: the page, a sign-in just made, a message waiting for an account.
const LOCAL_STORAGE_PREFIXES = ['biset.did-links', 'biset.vh-places', 'biset.log-versions', 'biset.profileSent.']
const SESSION_STORAGE_PREFIXES = ['biset:', 'biset-did-md-just-connected']

export function clearPlainStorage(): void {
  const clear = (store: Storage | undefined, prefixes: readonly string[]) => {
    try {
      if (!store) return
      // Backwards: removing a key moves the ones after it up.
      for (let index = store.length - 1; index >= 0; index -= 1) {
        const key = store.key(index)
        if (key !== null && prefixes.some(prefix => key.startsWith(prefix))) store.removeItem(key)
      }
    } catch { /* storage blocked: nothing was kept there */ }
  }
  clear(globalThis.localStorage, LOCAL_STORAGE_PREFIXES)
  clear(globalThis.sessionStorage, SESSION_STORAGE_PREFIXES)
}
