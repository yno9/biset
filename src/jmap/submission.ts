import type { JamClient } from 'jmap-jam'
import type { EmailSubmission } from 'jmap-rfc-types'

export async function get(
  client: JamClient,
  accountId: string,
): Promise<{ submissions: EmailSubmission[]; state: string }> {
  const [r] = await (client.api as any).EmailSubmission.get({ accountId, ids: null })
  return { submissions: r.list as EmailSubmission[], state: r.state as string }
}

export async function query(
  client: JamClient,
  accountId: string,
): Promise<{ ids: string[]; queryState: string }> {
  const [r] = await (client.api as any).EmailSubmission.query({ accountId })
  return { ids: [...(r.ids ?? [])] as string[], queryState: r.queryState as string }
}

export async function changes(
  client: JamClient,
  accountId: string,
  sinceState: string,
): Promise<{ created: string[]; updated: string[]; destroyed: string[]; newState: string }> {
  const [r] = await (client.api as any).EmailSubmission.changes({ accountId, sinceState })
  return {
    created: [...(r.created ?? [])] as string[],
    updated: [...(r.updated ?? [])] as string[],
    destroyed: [...(r.destroyed ?? [])] as string[],
    newState: r.newState as string,
  }
}

export async function queryChanges(
  client: JamClient,
  accountId: string,
  sinceQueryState: string,
): Promise<{ added: string[]; removed: string[]; newQueryState: string }> {
  const [r] = await (client.api as any).EmailSubmission.queryChanges({ accountId, sinceQueryState })
  return {
    added: (r.added ?? []).map((a: any) => a.id as string),
    removed: [...(r.removed ?? [])] as string[],
    newQueryState: r.newQueryState as string,
  }
}

export async function create(
  client: JamClient,
  accountId: string,
  emailCreate: Record<string, any>,
): Promise<string> {
  const [r] = await (client.api as any).Email.set({
    accountId,
    create: { draft: emailCreate },
  })
  const emailId = (r.created as any)?.['draft']?.id
  if (!emailId) throw new Error('Email/set create failed')
  return emailId as string
}

export async function submit(
  client: JamClient,
  accountId: string,
  emailId: string,
  identityId: string,
): Promise<string> {
  const [sr] = await (client.api as any).EmailSubmission.set({
    accountId,
    create: { sub: { emailId, identityId } },
  })
  const subId = (sr.created as any)?.['sub']?.id
  if (!subId) {
    const desc = (sr.notCreated as any)?.['sub']?.description
    throw new Error(desc || 'EmailSubmission/set create failed')
  }
  return subId as string
}

export async function send(
  client: JamClient,
  accountId: string,
  emailCreate: Record<string, any>,
  identityId: string,
): Promise<string> {
  const emailId = await create(client, accountId, emailCreate)
  return submit(client, accountId, emailId, identityId)
}
