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
const SUBJECTS: Record<string, string> = { t1: 'UIのリニューアルについて', t2: 'Meeting schedule', t3: '先週の打ち合わせメモ', t4: 'ランチどうしますか' }
const msg = (thread: string, from: string, from_name: string, body: string, minutesAgo: number, extra: Partial<MailMessageView> = {}): ProcessedMessage => {
  n++
  return {
    bodyText: body,
    msg: {
      from, from_name, body, subject: SUBJECTS[thread] ?? '', ts: now - minutesAgo * 60_000, message_id: `<m${n}@mock>`, jmap_id: `m${n}`,
      in_reply_to: '', thread_id: thread, to_addrs: from === SELF ? [thread === 't2' ? BOB : ALICE] : [SELF], seen: true, ...extra,
    },
  }
}

mail.set({
  messages: [
    msg('t1', ALICE, 'alice', 'こんにちは。UIの件、見ました？', 95),
    msg('t1', SELF, 'me', 'はい、吹き出しタイプにしてみています。', 93),
    msg('t1', ALICE, 'alice', '短い返事。', 90),
    msg('t1', ALICE, 'alice', '長い文章の例です。'.repeat(14) + '\nhttps://muse.ai/ のようなリンクも入れてみる。', 88, { edited: true }),
    msg('t1', ALICE, 'alice', 'そういえば、ヘッダーはスクロールしても残るようにしました。', 80),
    msg('t1', SELF, 'me', 'いいですね。メッセージが上に流れるときの見え方も確認したいです。', 78),
    msg('t1', ALICE, 'alice', '背景のグラデーションで、文字が薄く消えていくはずです。', 75),
    msg('t1', ALICE, 'alice', 'もう一通。連続して届いたメッセージの間隔も見てください。', 74),
    msg('t1', SELF, 'me', '間隔は少し広げました。\n吹き出しの余白も。', 70),
    msg('t1', ALICE, 'alice', '右側の吹き出しは水色、左側はグレーです。', 66),
    msg('t1', SELF, 'me', 'ホバーすると「⋯」が出て、時刻が見られます。', 60),
    msg('t1', ALICE, 'alice', 'https://example.com/a/very/long/link/that/should/wrap/or/break/somewhere/in/the/bubble', 55),
    msg('t1', SELF, 'me', 'リンクが長いときの折り返しも確認。', 50),
    msg('t1', ALICE, 'alice', '短い。', 45),
    msg('t1', SELF, 'me', 'はい。', 44),
    msg('t1', ALICE, 'alice', 'ここまでで、スクロールが必要な量になったと思います。', 40),
    msg('t1', SELF, 'me', '了解です！\n改行も\nこの通り。', 12),
    msg('t1', ALICE, 'alice', '👍', 3, { reactions: [{ from: SELF, emoji: '🎉' }] }),
    msg('t3', ALICE, 'alice', 'お疲れさまです。先週のメモを共有します。', 4000),
    msg('t3', SELF, 'me', 'ありがとうございます、確認します。', 3990),
    msg('t3', ALICE, 'alice', '次回は木曜の午後でどうでしょう？', 3980),
    msg('t4', ALICE, 'alice', '明日のお昼、駅前のカフェはどうですか？', 1500),
    msg('t4', SELF, 'me', 'いいですね、12時に行きます。', 1490),
    msg('t2', BOB, 'Bob', 'Meeting moved to 3pm.', 600, { auth: { dmarc: 'fail', domain: 'example.com' } as MailMessageView['auth'] }),
    msg('t2', SELF, 'me', 'OK, thanks.', 590),
  ],
})
configureCompose({ selfAddress: 'me@example.com', selfDid: SELF, sendReply: async () => {} })
patchShell({ appShown: true, focusedThreadKey: 't1' })
mountApp()
