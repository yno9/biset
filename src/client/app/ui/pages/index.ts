// The pages the right column can show, and the calls the rest of the app navigates with.
import { getAccountConfig } from '../account/state.ts'
import { composeConfigured } from './compose-page.tsx'
import { inPage, setPage } from '../state.ts'

export { configureAccountPage, updateVaultCardStatus, type VaultCardStatus } from '../account/state.ts'
export { configureComposePage } from './compose-page.tsx'
export { configureMarkdownVaultToggle } from './config-page.tsx'
export { setOnWalletConnected } from './new-user-page.tsx'

export const showAccountPage = (): void => { if (getAccountConfig()) setPage('account') }
export const hideAccountPage = (): void => { if (inPage('account')) setPage('thread') }

// Without an account the page can still be opened (a message can be written there, and an address from the path is put in it); it
// is sending that needs the account.
export const showComposePage = (): void => { if (composeConfigured() || getAccountConfig()?.did === null) setPage('compose') }
export const hideComposePage = (): void => { if (inPage('compose')) setPage('thread') }
