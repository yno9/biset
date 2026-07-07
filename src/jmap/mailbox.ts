import type { JamClient } from 'jmap-jam'
import type { Mailbox } from 'jmap-rfc-types'

export async function get(
  client: JamClient,
  accountId: string,
): Promise<{ mailboxes: Mailbox[]; state: string }> {
  const [r] = await (client.api as any).Mailbox.get({ accountId, ids: null })
  return { mailboxes: r.list as Mailbox[], state: r.state }
}

export async function queryByRole(
  client: JamClient,
  accountId: string,
  role: string,
): Promise<{ ids: string[]; queryState: string }> {
  const [r] = await (client.api as any).Mailbox.query({
    accountId,
    filter: { role },
  })
  return { ids: [...(r.ids ?? [])] as string[], queryState: r.queryState as string }
}

export async function changes(
  client: JamClient,
  accountId: string,
  sinceState: string,
): Promise<{ created: string[]; updated: string[]; destroyed: string[]; newState: string }> {
  const [r] = await client.api.Mailbox.changes({ accountId, sinceState })
  return {
    created: [...r.created] as string[],
    updated: [...r.updated] as string[],
    destroyed: [...r.destroyed] as string[],
    newState: (r as any).newState as string,
  }
}

export async function create(
  client: JamClient,
  accountId: string,
  name: string,
  parentId?: string,
): Promise<string> {
  const mb: any = { name }
  if (parentId) mb.parentId = parentId
  const [r] = await client.api.Mailbox.set({ accountId, create: { new1: mb } })
  const id = (r.created as any)?.['new1']?.id
  if (!id) throw new Error('Mailbox/set create failed')
  return id as string
}

export async function destroy(
  client: JamClient,
  accountId: string,
  id: string,
): Promise<void> {
  const [r] = await client.api.Mailbox.set({ accountId, destroy: [id as any] })
  if (!(r.destroyed as any[])?.includes(id)) throw new Error('Mailbox/set destroy failed')
}
