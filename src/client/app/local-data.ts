// What this app keeps in the browser about an identity and who it knew, and the purge of it (Disconnect, main.ts): its IndexedDB databases and plain storage.
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

// Every IndexedDB database this app opens, device-local and meaningless without an owning account.
const LOCAL_DATABASE_NAMES = [
  'biset-did-md-wallet', 'biset-mls-keypackages', 'biset-mls-self-group',
  'biset-vault-core', 'biset-didcomm-group-chat', 'biset-markdown-mirror',
]

/** Deletes every database above; one that will not go (blocked, failing) is left after a few seconds rather than waited for. */
export async function deleteLocalDatabases(): Promise<void> {
  await Promise.all(LOCAL_DATABASE_NAMES.map(name => new Promise<void>(resolve => {
    const request = indexedDB.deleteDatabase(name)
    request.onsuccess = () => resolve()
    request.onerror = () => resolve()
    request.onblocked = () => resolve()
    setTimeout(resolve, 3000)
  })))
}
