import type { JamClient } from 'jmap-jam'
import type { Identity } from 'jmap-rfc-types'

export async function get(
  client: JamClient,
  accountId: string,
): Promise<{ identities: Identity[]; state: string }> {
  const [r] = await (client.api as any).Identity.get({ accountId, ids: null })
  return { identities: r.list as Identity[], state: r.state as string }
}
