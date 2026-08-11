import type { JamClient } from 'jmap-jam'

export interface ThreadEntry {
  id: string
  emailIds: string[]
}

export async function get(
  client: JamClient,
  accountId: string,
  ids: string[],
): Promise<{ threads: ThreadEntry[]; state: string }> {
  const [r] = await (client.api as any).Thread.get({ accountId, ids })
  return {
    threads: (r.list as any[]).map(t => ({ id: t.id as string, emailIds: [...t.emailIds] as string[] })),
    state: r.state as string,
  }
}

export async function changes(
  client: JamClient,
  accountId: string,
  sinceState: string,
): Promise<{ created: string[]; updated: string[]; destroyed: string[]; newState: string }> {
  const [r] = await (client.api as any).Thread.changes({ accountId, sinceState })
  return {
    created: [...(r.created ?? [])] as string[],
    updated: [...(r.updated ?? [])] as string[],
    destroyed: [...(r.destroyed ?? [])] as string[],
    newState: r.newState as string,
  }
}
