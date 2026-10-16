// Which page the right column shows. The pages are React (ui/page-host.tsx); the rest of the app
// moves between them by writing here.
import { flushSync } from 'react-dom'
import { createStore } from '../react/store.ts'

export type Page = 'thread' | 'account' | 'config' | 'compose'

export const uiPage = createStore<Page>('thread')

// Synchronous: the DOM-built thread (ui/thread.ts) paints into the node the thread page gives it, so
// it has to be there before the caller goes on to render().
export const setPage = (page: Page): void => { flushSync(() => uiPage.set(page)) }
export const inPage = (page: Page): boolean => uiPage.get() === page
