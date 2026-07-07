import type { JamClient } from 'jmap-jam'
import type { Email } from 'jmap-rfc-types'

const META_PROPS = [
  'id', 'threadId', 'mailboxIds', 'from', 'to', 'cc', 'subject',
  'receivedAt', 'preview', 'messageId', 'inReplyTo', 'keywords',
] as const

const BODY_PROPS = ['id', 'bodyValues', 'textBody'] as const

const SORT = [{ property: 'receivedAt', isAscending: true }] as const

export async function query(
  client: JamClient,
  accountId: string,
): Promise<{ ids: string[]; queryState: string }> {
  const [r] = await client.api.Email.query({
    accountId,
    sort: [...SORT],
    limit: 5000,
  })
  return { ids: [...r.ids] as string[], queryState: r.queryState }
}

export async function get(
  client: JamClient,
  accountId: string,
  ids: string[],
  withBody = false,
): Promise<{ emails: Email[]; state: string }> {
  const properties = withBody ? [...META_PROPS, ...BODY_PROPS] : [...META_PROPS]
  const [r] = await client.api.Email.get({
    accountId,
    ids: ids as any,
    properties,
    ...(withBody ? { fetchAllBodyValues: true } : {}),
  })
  return { emails: r.list as Email[], state: r.state }
}

export async function queryChanges(
  client: JamClient,
  accountId: string,
  sinceQueryState: string,
): Promise<{ added: string[]; removed: string[]; newQueryState: string }> {
  const [r] = await client.api.Email.queryChanges({
    accountId,
    sinceQueryState,
    sort: [...SORT],
  })
  return {
    added: r.added.map(a => a.id as string),
    removed: [...r.removed] as string[],
    newQueryState: r.newQueryState,
  }
}

export async function changes(
  client: JamClient,
  accountId: string,
  sinceState: string,
): Promise<{ created: string[]; updated: string[]; destroyed: string[]; newState: string }> {
  const [r] = await client.api.Email.changes({ accountId, sinceState })
  return {
    created: [...r.created] as string[],
    updated: [...r.updated] as string[],
    destroyed: [...r.destroyed] as string[],
    newState: r.newState,
  }
}

export async function markSeen(
  client: JamClient,
  accountId: string,
  ids: string[],
): Promise<void> {
  const update: Record<string, any> = {}
  for (const id of ids) update[id] = { 'keywords/$seen': true }
  await client.api.Email.set({ accountId, update })
}

export async function destroy(
  client: JamClient,
  accountId: string,
  ids: string[],
): Promise<void> {
  await client.api.Email.set({ accountId, destroy: ids as any })
}

export async function markArchived(
  client: JamClient,
  accountId: string,
  ids: string[],
  archived = true,
): Promise<void> {
  const update: Record<string, any> = {}
  // JMAP patch: `true` sets the keyword, `null` removes it (un-archive).
  for (const id of ids) update[id] = { 'keywords/$archived': archived ? true : null }
  await client.api.Email.set({ accountId, update })
}

export async function markSpam(
  client: JamClient,
  accountId: string,
  ids: string[],
): Promise<void> {
  const update: Record<string, any> = {}
  for (const id of ids) update[id] = { 'keywords/$junk': true }
  await client.api.Email.set({ accountId, update })
}
