// Which page the right column shows. The pages are React (ui/page-host.tsx); the rest of the app
// moves between them by writing here.
import { flushSync } from 'react-dom'
import { createStore } from '../react/store.ts'

export type Page = 'thread' | 'account' | 'config' | 'compose'

export const uiPage = createStore<Page>('thread')

// Synchronous: a caller that goes on to read the page it just opened finds it on screen.
export const setPage = (page: Page): void => {
  flushSync(() => uiPage.set(page))
  try { sessionStorage.setItem(PAGE_KEY, page) } catch { /* storage blocked: reload just lands on the thread */ }
}

const PAGE_KEY = 'biset:page'

/** The page this tab was on before a reload (account or config; the others need live state). */
export function savedPage(): 'account' | 'config' | undefined {
  try { const page = sessionStorage.getItem(PAGE_KEY); return page === 'account' || page === 'config' ? page : undefined } catch { return undefined }
}
export const inPage = (page: Page): boolean => uiPage.get() === page
