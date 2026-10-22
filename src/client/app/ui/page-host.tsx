// The right column's page: the thread, or account / config / compose. Each renders its own
// #active-thread node.
import { useStore } from '../react/store.ts'
import { AccountPage } from './pages/account-page.tsx'
import { ComposePage } from './pages/compose-page.tsx'
import { uiPage } from './state.ts'
import { ThreadPage } from './thread-page.tsx'

export function PageHost() {
  const page = useStore(uiPage)
  switch (page) {
    case 'account': return <AccountPage />
    case 'compose': return <ComposePage />
    default: return <ThreadPage />
  }
}
