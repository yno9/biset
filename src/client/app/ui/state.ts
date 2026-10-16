// Which page the right column shows. The pages are React (ui/page-host.tsx); the rest of the app
// moves between them by writing here.
import { flushSync } from 'react-dom'
import { createStore } from '../react/store.ts'

export type Page = 'thread' | 'account' | 'config' | 'compose'

export const uiPage = createStore<Page>('thread')

// Synchronous: a caller that goes on to read the page it just opened finds it on screen.
export const setPage = (page: Page): void => { flushSync(() => uiPage.set(page)) }
export const inPage = (page: Page): boolean => uiPage.get() === page
