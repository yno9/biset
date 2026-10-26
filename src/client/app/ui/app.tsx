// The whole mail UI: the left pane and right column inside #app (shown once there is an identity),
// the menu and the scroll buttons beside it, the system toast.
import { useEffect } from 'react'
import '../embed-card.css'
import { useStore } from '../react/store.ts'
import { mountIsland } from '../react/island.tsx'
import { Tooltip } from './account/tooltip.tsx'
import { ApproveDialog } from './approve-dialog.tsx'
import { TextCardDialog } from './account/text-card-dialog.tsx'
import { AvatarCropDialog } from './account/avatar-crop.tsx'
import { HamburgerMenu } from './hamburger-menu.tsx'
import { Favicon } from './favicon.tsx'
import { LeftPane } from './left-pane.tsx'
import { PaneButton, RightCol } from './right-col.tsx'
import { ScrollButtons } from './scroll-buttons.tsx'
import { uiPage } from './state.ts'
import { shell } from './stores.ts'
import { SysMsg } from './sys-msg.tsx'

function App() {
  const { appShown, singleCol, paneCompact, showLeft } = useStore(shell)
  const page = useStore(uiPage)
  // CSS scopes the left pane, header and toggle under #app.lp-enabled.
  const classes = ['lp-enabled', singleCol ? 'single-col' : '', paneCompact ? 'lp-compact' : '', showLeft ? 'show-left' : ''].filter(Boolean).join(' ')
  useEffect(() => { document.title = 'biset' }, [])
  return (
    <>
      <SysMsg />
      <Favicon />
      <HamburgerMenu />
      <Tooltip />
      <ApproveDialog />
      <TextCardDialog />
      <AvatarCropDialog />
      <div id="app" className={classes} style={{ display: appShown ? 'flex' : 'none' }} data-menu-page={page === 'thread' ? undefined : `/${page}`}>
        <LeftPane />
        <RightCol />
      </div>
      <PaneButton />
      <ScrollButtons />
    </>
  )
}

export function mountApp(): void {
  mountIsland('root', <App />)
}
