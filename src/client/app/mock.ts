// Mock data for mock.html: seeds the stores the real UI reads, so it renders without an identity, a vault or a network.
import { mountApp } from './ui/app.tsx'
import { startRouting } from './ui/route.ts'
import { mountNetworkActivity } from 'lft/net-activity-ui'
import { networkNotes, networkRules } from './ui/network-declaration.ts'
import { configureCompose } from './ui/reply-box.tsx'
import { configureAccountPage, configureComposePage } from './ui/pages/index.ts'
import { mail, patchShell } from './ui/stores.ts'
import type { MailMessageView, ProcessedMessage } from './ui/message/message-view.ts'

// What the account's footer shows besides Delta Chat (which needs a PGP identity this mock does not have).
;(window as unknown as { __BISET_CONFIG__?: unknown }).__BISET_CONFIG__ = { appOnionUrl: 'http://example.onion', mailGateways: ['did.md'], mediatorUrls: ['https://mediator.biset.md'], identityDomain: '002053.xyz', vhWatchers: ['https://did.md'] }

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
    msg('notepad', SELF, 'me', '買うもの: 牛乳、パン、コーヒー豆', 300, { to_addrs: [SELF] }),
    msg('notepad', SELF, 'me', 'did.md のメモ\nhttps://did.md/', 200, { to_addrs: [SELF] }),
    msg('t2', BOB, 'Bob', 'Meeting moved to 3pm.', 600, { auth: { dmarc: 'fail', domain: 'example.com' } as MailMessageView['auth'] }),
    msg('t2', SELF, 'me', 'OK, thanks.', 590),
  ],
})
// ?notes=40 makes the Notepad long enough to scroll (for trying the account page scrolled).
const noteCount = Number(new URLSearchParams(location.search).get('notes') ?? 0)
if (noteCount > 0) mail.set(current => ({ messages: [...current.messages, ...Array.from({ length: noteCount }, (_, index) => msg('notepad', SELF, 'me', `note ${index + 1}`, 1000 + index))] }))
const noAccount = new URLSearchParams(location.search).has('noaccount') // ?noaccount: as when nobody has signed in
if (noAccount) configureAccountPage({ did: null, showMessage: text => { (window as unknown as { __said?: string }).__said = text } })
else configureComposePage({ selfAddress: 'me@example.com', selfDid: SELF, sendMessage: async input => {
  if (new URLSearchParams(location.search).has('failsend')) throw new Error('A DIDComm message needs a recipient')
  ;(window as unknown as { __sent?: unknown }).__sent = input
  // The helper answers in its own conversation, a moment later (as didmail does for /help).
  if (input.toAddrs[0]?.startsWith('didmail@')) {
    setTimeout(() => mail.set(current => ({ messages: [...current.messages,
      msg('t5', SELF, 'me', input.body, 0, { to_addrs: [input.toAddrs[0]!] }),
      msg('t5', input.toAddrs[0]!, 'didmail', 'I am the mail bridge. You can send me:\n/help – this list', -0.01),
    ] })), 300)
  }
} })
if (!noAccount) configureAccountPage({ did: SELF, showMessage: () => {}, pgp: { address: 'me@example.com', current: async () => undefined, onCopyPublic: async () => '', inviteLink: async () => 'https://i.delta.chat/#mock', joinInvite: async () => ({ name: 'x', address: 'x@example.com' }) } })
if (!noAccount) configureCompose({ selfAddress: 'me@example.com', selfDid: SELF, sendReply: async () => {}, sendNote: async body => { mail.set(current => ({ messages: [...current.messages, msg('notepad', SELF, 'me', body, 0, { to_addrs: [SELF] })] })) } })
if (noAccount) mail.set({ messages: [] })
patchShell({ appShown: true, focusedThreadKey: 't1' })
mountApp()
// ?route=/alice@gmail.com stands in for the address bar's path, which on mock.html is /mock.html.
startRouting(new URLSearchParams(location.search).get('route') ?? '/')

// ?signup shows the sign-up (as after Send with no account); ?held makes the wallet hold an identity (the log-in form).
if (new URLSearchParams(location.search).has('signup')) {
  const { signingUp } = await import('./ui/pages/compose-page.tsx')
  const { walletKnown, heldIdentity } = await import('./ui/signup-preload.ts')
  walletKnown.set(true)
  if (new URLSearchParams(location.search).has('held')) heldIdentity.set('485c@002053.xyz')
  signingUp.set(true)
}

// The network indicator, as in the app; ?ping makes a request so it can be seen.
mountNetworkActivity({ label: 'top-right', rules: networkRules(), notes: networkNotes })
if (new URLSearchParams(location.search).has('ping')) {
  // A few requests of the kinds the app makes, and one it did not declare.
  for (const [url, init] of [['https://did.md/log?scid=QmExample', undefined], ['https://alice.002053.xyz/.well-known/did.jsonl', undefined], ['https://mediator.biset.md/', { method: 'POST', body: 'x'.repeat(2400) }], ['https://example.org/.well-known/webfinger?resource=acct:bob@example.org', undefined], ['https://tracker.example/collect', { method: 'POST', body: 'id=1' }]] as const) void fetch(url, init).catch(() => {})
}
