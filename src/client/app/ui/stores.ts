// What the mail UI shows, as stores: the messages, and the shell around them (which thread is
// open, the left pane's state). The logic writes here; the screens (ui/*.tsx) subscribe.
import { createStore } from '../react/store.ts'
import type { ProcessedMessage } from './message/message-view.ts'

export const mail = createStore<{ messages: readonly ProcessedMessage[] }>({ messages: [] })

export interface Shell {
  /** The mail UI (#app) is on screen: there is an identity and its vault is open. */
  appShown: boolean
  /** Two columns on a wide screen; the left pane collapsed. */
  singleCol: boolean
  /** On a narrow screen the left pane is the column in front. */
  showLeft: boolean
  /** The left pane's filter. */
  search: string
  focusedThreadKey: string | null
  /** Left-list rows (one per counterparty) whose threads are listed under them. */
  expandedInboxKeys: ReadonlySet<string>
  /** The keyboard cursor in the left list: `inbox:<key>` or `thread:<key>`. */
  lpFocusedKey: string | null
}

export const shell = createStore<Shell>({
  appShown: false,
  singleCol: false,
  showLeft: false,
  search: '',
  focusedThreadKey: null,
  expandedInboxKeys: new Set(),
  lpFocusedKey: null,
})

export const patchShell = (change: Partial<Shell>): void => shell.set(current => ({ ...current, ...change }))

/** The narrow-screen layout (one column at a time) starts here. */
const NARROW_PX = 574
export const isNarrow = (): boolean => window.innerWidth <= NARROW_PX
