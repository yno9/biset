// The right column's page: the thread, or account / config / compose. Each page renders its own
// #active-thread node.
import { useLayoutEffect } from 'react'
import { useStore } from '../react/store.ts'
import { mountIsland } from '../react/island.tsx'
import { AccountPage } from './pages/account-page.tsx'
import { ComposePage } from './pages/compose-page.tsx'
import { ConfigPage } from './pages/config-page.tsx'
import { uiPage } from './state.ts'
import { render } from './thread.ts'

// The thread is still built by plain DOM code (ui/thread.ts): this page hands it an empty node and
// has it paint as soon as the node is there.
function ThreadPage() {
  useLayoutEffect(() => { render() }, [])
  return <div id="active-thread" />
}

function PageHost() {
  const page = useStore(uiPage)
  switch (page) {
    case 'account': return <AccountPage />
    case 'config': return <ConfigPage />
    case 'compose': return <ComposePage />
    default: return <ThreadPage />
  }
}

export function mountPageHost(): void {
  mountIsland('page-host', <PageHost />)
}
