// The helper: a correspondent that answers the lines which start with `/` (a didmail bridge, PROTOCOL.md §7.5). Whatever reply
// box such a line is typed in, it goes to the helper instead of the conversation, and the helper's own conversation is opened,
// because that is where its answer comes.
import { readBisetConfig } from './config.ts'
import { sendMessageTo } from './pages/compose-page.tsx'

/** The helper's address: the deployment's `helperAddress`, else `didmail@` and its first mail gateway. Empty when there is neither. */
function helperAddress(): string {
  const config = readBisetConfig()
  if (config.helperAddress) return config.helperAddress
  const gateway = config.mailGateways[0]
  return gateway ? `didmail@${gateway}` : ''
}

let openInbox: ((address: string) => void) | undefined
/** What opens a conversation by its address (ui/route.ts), set there: this module is reached from the reply box, which route.ts reaches. */
export function setInboxOpener(opener: (address: string) => void): void { openInbox = opener }

/** Sends a `/` line to the helper and goes to the helper's conversation. */
export async function sendToHelper(line: string): Promise<void> {
  const address = helperAddress()
  if (!address) throw new Error('There is no helper to send commands to (no helperAddress, no mail gateway)')
  await sendMessageTo([address], line)
  openInbox?.(address)
}
