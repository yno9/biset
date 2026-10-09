import { describe, expect, test } from 'bun:test'
import { isMailAddress, resolveMailAddressDid } from '../src/client/didcomm/address-resolver.ts'

function fetchFrom(answers: Record<string, unknown>, asked: string[] = []): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = new URL(String(input))
    asked.push(`${url.host} ${url.searchParams.get('resource')}`)
    const answer = answers[url.host]
    if (answer instanceof Error) throw answer
    return answer === undefined ? new Response('Not found', { status: 404 }) : Response.json(answer)
  }) as typeof fetch
}

describe('mail address -> DID (WebFinger)', () => {
  test('the address\'s own domain is asked first, and its DID wins', async () => {
    const asked: string[] = []
    const did = await resolveMailAddressDid('bob@biset.md', ['did.md'], fetchFrom({ 'biset.md': { subject: 'acct:bob@biset.md', aliases: ['https://biset.md/@bob', 'did:webvh:Qm:bob.biset.md'] } }, asked))
    expect(did).toBe('did:webvh:Qm:bob.biset.md')
    expect(asked).toEqual(['biset.md acct:bob@biset.md'])
  })

  test('a domain without a DID for it (no answer, no CORS, no DID alias) falls back to the gateway', async () => {
    const asked: string[] = []
    const did = await resolveMailAddressDid('bob+news@gmail.com', ['did.md'], fetchFrom({
      'gmail.com': new TypeError('Failed to fetch'),
      'did.md': { subject: 'acct:bob+news@gmail.com', aliases: ['did:web:did.md:gmail.com:bob%2Bnews'] },
    }, asked))
    expect(did).toBe('did:web:did.md:gmail.com:bob%2Bnews')
    expect(asked).toEqual(['gmail.com acct:bob+news@gmail.com', 'did.md acct:bob+news@gmail.com'])
    expect(await resolveMailAddressDid('a@x.test', ['did.md'], fetchFrom({ 'x.test': { aliases: ['https://x.test/a'] }, 'did.md': { aliases: ['did:web:did.md:x.test:a'] } }))).toBe('did:web:did.md:x.test:a')
  })

  test('nobody answers: an error that says so', async () => {
    await expect(resolveMailAddressDid('a@x.test', ['did.md'], fetchFrom({}))).rejects.toThrow('No DID answers for a@x.test')
    await expect(resolveMailAddressDid('a@x.test', [], fetchFrom({}))).rejects.toThrow('no mail gateway is configured')
  })

  test('what counts as a mail address', () => {
    expect(isMailAddress('alice@gmail.com')).toBe(true)
    expect(isMailAddress('did:web:did.md:gmail.com:alice')).toBe(false)
    expect(isMailAddress('alice@localhost')).toBe(false)
    expect(isMailAddress('@gmail.com')).toBe(false)
  })
})
