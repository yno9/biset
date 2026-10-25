// Mock data for mock.html: seeds the stores the real UI reads, so it renders without an identity, a vault or a network.
import { mountApp } from './ui/app.tsx'
import { configureCompose } from './ui/reply-box.tsx'
import { mail, patchShell } from './ui/stores.ts'
import type { MailMessageView, ProcessedMessage } from './ui/message/message-view.ts'

const SELF = 'did:web:me.example'
const ALICE = 'did:web:alice.example'
const BOB = 'bob@example.com'
const now = Date.now()

let n = 0
const msg = (thread: string, from: string, from_name: string, body: string, minutesAgo: number, extra: Partial<MailMessageView> = {}): ProcessedMessage => {
  n++
  return {
    bodyText: body,
    msg: {
      from, from_name, body, subject: thread === 't1' ? 'UIのリニューアルについて' : 'Meeting schedule', ts: now - minutesAgo * 60_000, message_id: `<m${n}@mock>`, jmap_id: `m${n}`,
      in_reply_to: '', thread_id: thread, to_addrs: from === SELF ? [thread === 't1' ? ALICE : BOB] : [SELF], seen: true, ...extra,
    },
  }
}

mail.set({
  messages: [
    msg('t1', ALICE, 'alice', 'こんにちは。UIの件、見ました？', 95),
    msg('t1', SELF, 'me', 'はい、吹き出しタイプにしてみています。', 93),
    msg('t1', ALICE, 'alice', '短い返事。', 90),
    msg('t1', ALICE, 'alice', '長い文章の例です。'.repeat(14) + '\nhttps://muse.ai/ のようなリンクも入れてみる。', 88, { edited: true }),
    msg('t1', SELF, 'me', '了解です！\n改行も\nこの通り。', 12),
    msg('t1', ALICE, 'alice', '👍', 3, { reactions: [{ from: SELF, emoji: '🎉' }] }),
    msg('t2', BOB, 'Bob', 'Meeting moved to 3pm.', 600, { auth: { dmarc: 'fail', domain: 'example.com' } as MailMessageView['auth'] }),
    msg('t2', SELF, 'me', 'OK, thanks.', 590),
  ],
})
configureCompose({ selfAddress: 'me@example.com', selfDid: SELF, sendReply: async () => {} })
patchShell({ appShown: true, focusedThreadKey: 't1' })
mountApp()
