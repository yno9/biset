import { describe, expect, test } from 'bun:test'
import {
  parsePath, SmtpIngressCongestionError, SmtpSession, splitCommandLine,
} from '../../../src/mediator/mail-plugin/mail-smtp-protocol.ts'
import type { AcceptIngressInput, SmtpEffect, SmtpRecipientResolution, SmtpSessionDeps } from '../../../src/mediator/mail-plugin/mail-smtp-protocol.ts'

function enc(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function replies(effects: SmtpEffect[]): string[] {
  return effects.filter((e): e is { kind: 'reply'; text: string } => e.kind === 'reply').map(e => e.text)
}

interface Fixture {
  session: SmtpSession
  accepted: AcceptIngressInput[]
  resolveResult: Map<string, SmtpRecipientResolution | 'throw'>
  acceptThrows: Error | undefined
}

function makeSession(overrides: Partial<SmtpSessionDeps> = {}): Fixture {
  const accepted: AcceptIngressInput[] = []
  const resolveResult = new Map<string, SmtpRecipientResolution | 'throw'>()
  const fx: Fixture = { session: undefined as unknown as SmtpSession, accepted, resolveResult, acceptThrows: undefined }
  const deps: SmtpSessionDeps = {
    helloName: 'mail.test.example',
    tlsAdvertised: true,
    sendGreeting: true,
    maxMessageBytes: 1000,
    async resolveRecipient(reference) {
      const result = resolveResult.get(reference.address)
      if (result === 'throw') throw new Error('resolution failed')
      return result
    },
    async acceptIngress(input) {
      if (fx.acceptThrows) throw fx.acceptThrows
      accepted.push(input)
    },
    ...overrides,
  }
  fx.session = new SmtpSession(deps)
  return fx
}

const ALICE: SmtpRecipientResolution = { identityId: 'did:webvh:x:alice.test.example', deviceIds: ['device-a'] }

async function transaction(fx: Fixture, rcpts: string[]): Promise<string[]> {
  const out: string[] = []
  out.push(...replies(await fx.session.feed(enc('EHLO client.example\r\n'))))
  out.push(...replies(await fx.session.feed(enc('MAIL FROM:<sender@example.test>\r\n'))))
  for (const rcpt of rcpts) out.push(...replies(await fx.session.feed(enc(`RCPT TO:<${rcpt}>\r\n`))))
  return out
}

describe('SmtpSession: greeting', () => {
  test('sends a 220 banner when sendGreeting is true', () => {
    const fx = makeSession({ sendGreeting: true })
    expect(replies(fx.session.greeting())).toEqual(['220 mail.test.example ESMTP Service Ready\r\n'])
  })
  test('sends no banner for a session resumed post-STARTTLS', () => {
    const fx = makeSession({ sendGreeting: false })
    expect(fx.session.greeting()).toEqual([])
  })
})

describe('SmtpSession: EHLO/HELO', () => {
  test('EHLO advertises STARTTLS when configured', async () => {
    const fx = makeSession({ tlsAdvertised: true })
    const out = replies(await fx.session.feed(enc('EHLO client.example\r\n')))
    expect(out[0]).toContain('250-Hello client.example')
    expect(out[0]).toContain('STARTTLS')
  })
  test('EHLO does not advertise STARTTLS when not configured', async () => {
    const fx = makeSession({ tlsAdvertised: false })
    const out = replies(await fx.session.feed(enc('EHLO client.example\r\n')))
    expect(out[0]).not.toContain('STARTTLS')
  })
  test('HELO greets without a capability list', async () => {
    const fx = makeSession()
    const out = replies(await fx.session.feed(enc('HELO client.example\r\n')))
    expect(out).toEqual(['250 2.0.0 Hello client.example\r\n'])
  })
})

describe('SmtpSession: command ordering', () => {
  test('MAIL before EHLO is refused', async () => {
    const fx = makeSession()
    const out = replies(await fx.session.feed(enc('MAIL FROM:<a@b>\r\n')))
    expect(out).toEqual(['502 5.5.1 Please introduce yourself first.\r\n'])
  })
  test('RCPT before MAIL is refused', async () => {
    const fx = makeSession()
    await fx.session.feed(enc('EHLO client.example\r\n'))
    const out = replies(await fx.session.feed(enc('RCPT TO:<a@b>\r\n')))
    expect(out).toEqual(['502 5.5.1 Missing MAIL FROM command.\r\n'])
  })
  test('DATA with zero surviving recipients is refused', async () => {
    const fx = makeSession()
    await fx.session.feed(enc('EHLO client.example\r\n'))
    await fx.session.feed(enc('MAIL FROM:<a@b>\r\n'))
    const out = replies(await fx.session.feed(enc('DATA\r\n')))
    expect(out).toEqual(['503 5.5.1 No valid recipients\r\n'])
  })
})

describe('SmtpSession: RCPT resolution', () => {
  test('a resolvable recipient is accepted 250', async () => {
    const fx = makeSession()
    fx.resolveResult.set('alice@mail.test.example', ALICE)
    const out = await transaction(fx, ['alice@mail.test.example'])
    expect(out.at(-1)).toBe("250 2.0.0 I'll make sure <alice@mail.test.example> gets this\r\n")
  })
  test('an unresolvable recipient is rejected 550, not silently dropped', async () => {
    const fx = makeSession()
    const out = await transaction(fx, ['nobody@mail.test.example'])
    expect(out.at(-1)).toBe('550 5.1.1 No such user here\r\n')
  })
  test('a recipient whose resolution throws gets a temporary 451', async () => {
    const fx = makeSession()
    fx.resolveResult.set('alice@mail.test.example', 'throw')
    const out = await transaction(fx, ['alice@mail.test.example'])
    expect(out.at(-1)).toBe('451 4.4.3 Temporary failure resolving recipient, try again later\r\n')
  })
  test('multiple RCPT in one transaction: only resolvable ones survive to DATA', async () => {
    const fx = makeSession()
    fx.resolveResult.set('alice@mail.test.example', ALICE)
    await transaction(fx, ['alice@mail.test.example', 'nobody@mail.test.example'])
    const out = replies(await fx.session.feed(enc('DATA\r\nhello\r\n.\r\n')))
    expect(out[0]).toBe('354 Go ahead. End your data with <CR><LF>.<CR><LF>\r\n')
    expect(fx.accepted).toHaveLength(1)
    expect(fx.accepted[0]!.recipientAddress).toBe('alice@mail.test.example')
  })
  test('non-ASCII recipient address is rejected without calling resolveRecipient', async () => {
    let resolveCalls = 0
    const fx = makeSession({ async resolveRecipient() { resolveCalls += 1; return ALICE } })
    const out = await transaction(fx, ['alïce@mail.test.example'])
    expect(out.at(-1)).toContain('550 5.6.7')
    expect(resolveCalls).toBe(0)
  })
})

describe('SmtpSession: DATA', () => {
  test('dot-unstuffs a leading dot and normalizes line endings', async () => {
    const fx = makeSession()
    fx.resolveResult.set('alice@mail.test.example', ALICE)
    await transaction(fx, ['alice@mail.test.example'])
    await fx.session.feed(enc('DATA\r\n'))
    const out = replies(await fx.session.feed(enc('Subject: hi\r\n..double dot\r\nplain\n.\r\n')))
    expect(out).toEqual(['250 2.0.0 OK: queued\r\n'])
    expect(fx.accepted).toHaveLength(1)
    expect(new TextDecoder().decode(fx.accepted[0]!.rawRfc5322)).toBe('Subject: hi\r\n.double dot\r\nplain\r\n')
  })
  test('calls acceptIngress exactly once per surviving recipient with the same body', async () => {
    const fx = makeSession()
    fx.resolveResult.set('alice@mail.test.example', ALICE)
    fx.resolveResult.set('bob@mail.test.example', { identityId: 'did:webvh:x:bob.test.example', deviceIds: ['device-b'] })
    await transaction(fx, ['alice@mail.test.example', 'bob@mail.test.example'])
    await fx.session.feed(enc('DATA\r\n'))
    await fx.session.feed(enc('body\r\n.\r\n'))
    expect(fx.accepted).toHaveLength(2)
    expect(fx.accepted.map(a => a.recipientAddress).sort()).toEqual(['alice@mail.test.example', 'bob@mail.test.example'])
    expect(fx.accepted[0]!.mailFrom).toBe('sender@example.test')
  })
  test('a body split across multiple feed() calls, mid-line, reassembles correctly', async () => {
    const fx = makeSession()
    fx.resolveResult.set('alice@mail.test.example', ALICE)
    await transaction(fx, ['alice@mail.test.example'])
    await fx.session.feed(enc('DATA\r\n'))
    await fx.session.feed(enc('Subj'))
    await fx.session.feed(enc('ect: hi\r\n\r\nbo'))
    const out = replies(await fx.session.feed(enc('dy\r\n.\r\n')))
    expect(out).toEqual(['250 2.0.0 OK: queued\r\n'])
    expect(new TextDecoder().decode(fx.accepted[0]!.rawRfc5322)).toBe('Subject: hi\r\n\r\nbody\r\n')
  })
  test('multiple pipelined commands in one feed() call are each answered in order', async () => {
    const fx = makeSession()
    fx.resolveResult.set('alice@mail.test.example', ALICE)
    const out = replies(await fx.session.feed(enc(
      'EHLO client.example\r\nMAIL FROM:<a@b>\r\nRCPT TO:<alice@mail.test.example>\r\n',
    )))
    expect(out).toHaveLength(3)
    expect(out[2]).toContain('250 2.0.0')
  })
  test('oversized DATA is rejected 552, calls no acceptIngress, and the session accepts a fresh transaction after', async () => {
    const fx = makeSession({ maxMessageBytes: 10 })
    fx.resolveResult.set('alice@mail.test.example', ALICE)
    await transaction(fx, ['alice@mail.test.example'])
    await fx.session.feed(enc('DATA\r\n'))
    const out = replies(await fx.session.feed(enc('this line alone is already over the ten byte cap\r\n.\r\n')))
    expect(out).toEqual(['552 5.3.4 Message size exceeds fixed limit\r\n'])
    expect(fx.accepted).toHaveLength(0)
    const again = await transaction(fx, ['alice@mail.test.example'])
    expect(again.at(-1)).toContain('250 2.0.0')
  })
  test('acceptIngress throwing SmtpIngressCongestionError for the only recipient replies 452', async () => {
    const fx = makeSession()
    fx.acceptThrows = new SmtpIngressCongestionError('over quota')
    fx.resolveResult.set('alice@mail.test.example', ALICE)
    await transaction(fx, ['alice@mail.test.example'])
    await fx.session.feed(enc('DATA\r\n'))
    const out = replies(await fx.session.feed(enc('body\r\n.\r\n')))
    expect(out).toEqual(['452 4.2.2 Insufficient system storage, try again later\r\n'])
  })
  test('acceptIngress throwing a generic error for the only recipient replies 451', async () => {
    const fx = makeSession()
    fx.acceptThrows = new Error('boom')
    fx.resolveResult.set('alice@mail.test.example', ALICE)
    await transaction(fx, ['alice@mail.test.example'])
    await fx.session.feed(enc('DATA\r\n'))
    const out = replies(await fx.session.feed(enc('body\r\n.\r\n')))
    expect(out).toEqual(['451 4.3.0 Requested action aborted: local error in processing\r\n'])
  })
})

describe('SmtpSession: STARTTLS', () => {
  test('replies 220 and returns a starttls effect, and stops processing further input on this session', async () => {
    const fx = makeSession({ tlsAdvertised: true })
    const effects = await fx.session.feed(enc('STARTTLS\r\nEHLO sneaky\r\n'))
    expect(effects).toEqual([{ kind: 'reply', text: '220 2.0.0 Ready to start TLS\r\n' }, { kind: 'starttls' }])
    const followUp = await fx.session.feed(enc('NOOP\r\n'))
    expect(followUp).toEqual([])
  })
  test('is refused 454 when not configured', async () => {
    const fx = makeSession({ tlsAdvertised: false })
    const out = replies(await fx.session.feed(enc('STARTTLS\r\n')))
    expect(out).toEqual(['454 4.7.0 TLS not available on this connection\r\n'])
  })
  test('a session resumed post-upgrade does not re-advertise STARTTLS and rejects MAIL before a fresh EHLO', async () => {
    const fx = makeSession({ tlsAdvertised: false, sendGreeting: false })
    expect(fx.session.greeting()).toEqual([])
    const out = replies(await fx.session.feed(enc('MAIL FROM:<a@b>\r\n')))
    expect(out).toEqual(['502 5.5.1 Please introduce yourself first.\r\n'])
  })
})

describe('SmtpSession: RSET/NOOP/QUIT/VRFY/AUTH', () => {
  test('RSET clears the transaction', async () => {
    const fx = makeSession()
    fx.resolveResult.set('alice@mail.test.example', ALICE)
    await transaction(fx, ['alice@mail.test.example'])
    await fx.session.feed(enc('RSET\r\n'))
    const out = replies(await fx.session.feed(enc('DATA\r\n')))
    expect(out).toEqual(['503 5.5.1 No valid recipients\r\n'])
  })
  test('NOOP is a no-op', async () => {
    const fx = makeSession()
    expect(replies(await fx.session.feed(enc('NOOP\r\n')))).toEqual(['250 2.0.0 I have successfully done nothing\r\n'])
  })
  test('QUIT replies 221 and closes', async () => {
    const fx = makeSession()
    const effects = await fx.session.feed(enc('QUIT\r\n'))
    expect(effects).toEqual([{ kind: 'reply', text: '221 2.0.0 Bye\r\n' }, { kind: 'close' }])
  })
  test('VRFY is refused politely, not treated as unknown', async () => {
    const fx = makeSession()
    expect(replies(await fx.session.feed(enc('VRFY\r\n')))).toEqual(['252 2.5.0 Cannot VRFY user, but will accept message\r\n'])
  })
  test('AUTH is refused: public MX, no authentication offered', async () => {
    const fx = makeSession()
    expect(replies(await fx.session.feed(enc('AUTH LOGIN\r\n')))).toEqual(['502 5.5.1 This is a public MX; no authentication is offered.\r\n'])
  })
})

describe('SmtpSession: malformed input and the 3-strikes rule', () => {
  test('a bad command shape gets 501, an unknown 4-letter verb gets 500', async () => {
    const fx = makeSession()
    expect(replies(await fx.session.feed(enc('AB\r\n')))).toEqual(['501 5.5.2 Bad command\r\n'])
    expect(replies(await fx.session.feed(enc('ABCDE\r\n')))).toEqual(['501 5.5.2 Bad command\r\n'])
    const out = replies(await fx.session.feed(enc('WXYZ\r\n')))
    expect(out[0]).toContain('500 5.5.2 Syntax errors, WXYZ command unrecognized')
  })
  test('more than 3 protocol errors closes the connection', async () => {
    const fx = makeSession()
    const effects = await fx.session.feed(enc('A\r\nA\r\nA\r\nA\r\n'))
    expect(effects.at(-1)).toEqual({ kind: 'close' })
    expect(effects.filter(e => e.kind === 'reply')).toHaveLength(4)
  })
  test('a malformed MAIL FROM does not count as a strike', async () => {
    const fx = makeSession()
    await fx.session.feed(enc('EHLO client.example\r\n'))
    await fx.session.feed(enc('MAIL bogus\r\n'))
    await fx.session.feed(enc('MAIL bogus\r\n'))
    await fx.session.feed(enc('MAIL bogus\r\n'))
    const effects = await fx.session.feed(enc('MAIL bogus\r\n'))
    expect(effects.at(-1)).not.toEqual({ kind: 'close' })
  })
})

describe('splitCommandLine', () => {
  test.each([
    ['EHLO x', { verb: 'EHLO', rest: 'x' }],
    ['ehlo x', { verb: 'EHLO', rest: 'x' }],
    ['NOOP', { verb: 'NOOP', rest: '' }],
    ['', { verb: '', rest: '' }],
    ['starttls', { verb: 'STARTTLS', rest: '' }],
  ])('%s', (input, expected) => {
    expect(splitCommandLine(input)).toEqual(expected)
  })
  test.each(['AB', 'ABCDE', 'ABCD-x'])('%s is malformed', input => {
    expect(splitCommandLine(input)).toBeUndefined()
  })
})

describe('parsePath', () => {
  test('bracketed address', () => {
    expect(parsePath('FROM:<a@b.com>', 'FROM:')).toBe('a@b.com')
  })
  test('unbracketed address, trailing ESMTP params ignored', () => {
    expect(parsePath('FROM:a@b.com SIZE=100', 'FROM:')).toBe('a@b.com')
  })
  test('wrong prefix', () => {
    expect(parsePath('TO:<a@b.com>', 'FROM:')).toBeUndefined()
  })
  test('missing closing bracket', () => {
    expect(parsePath('FROM:<a@b.com', 'FROM:')).toBeUndefined()
  })
})
