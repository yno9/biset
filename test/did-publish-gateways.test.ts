// didCommGateways (publish.ts) is the one place that decides which gateways
// a DIDComm publish/resolve goes through — extracted after three near-
// identical, independently-maintained constructions (this file's own
// buildOwnDocument, and two spots in create-standalone.ts) drifted apart:
// buildOwnDocument's routine republish (the most frequently run of the
// three, once per boot) was the one missing the public fallbacks, which is
// exactly why they went stale in production despite the identity's own
// anchor always being current. This test locks in the merged behavior so it
// can't quietly narrow again in only one caller.
import { didCommGateways, gatewayUrl } from '../src/did/publish.ts'
import { PUBLIC_PKARR_FALLBACKS } from '../src/did/resolver.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

console.log('\n=== didCommGateways ===')

{
  const gws = didCommGateways([], undefined)
  ok('relayもmediatorも無ければ公開fallbackだけ', gws.length === PUBLIC_PKARR_FALLBACKS.length && PUBLIC_PKARR_FALLBACKS.every(g => gws.includes(g)), JSON.stringify(gws))
}

{
  const relaySessions = [{ account: { serverUrl: 'https://mail.example.com' } }, { account: { serverUrl: 'https://ap.example.com/' } }]
  const gws = didCommGateways(relaySessions, 'https://anchor.example.com')
  ok('relay2つのgatewayが両方入る', gws.includes(gatewayUrl('https://mail.example.com')) && gws.includes(gatewayUrl('https://ap.example.com/')), JSON.stringify(gws))
  ok('mediator自身のgatewayも入る（トークン不要、直接/pkarr）', gws.includes('https://anchor.example.com/pkarr'), JSON.stringify(gws))
  ok('公開fallbackも常に入る', PUBLIC_PKARR_FALLBACKS.every(g => gws.includes(g)), JSON.stringify(gws))
  ok('重複しない', new Set(gws).size === gws.length, JSON.stringify(gws))
}

{
  // 同じmediatorが偶然relayのgatewayと同一URLを生成するケース（末尾スラッシュ違い等）でも重複しない
  const relaySessions = [{ account: { serverUrl: 'https://anchor.example.com' } }]
  const gws = didCommGateways(relaySessions, 'https://anchor.example.com/')
  ok('同一gatewayが重複しない', gws.filter(g => g === 'https://anchor.example.com/pkarr').length === 1, JSON.stringify(gws))
}

console.log(fails === 0 ? '\n  全て通過 — DIDComm gateway一覧はどの呼び出し元でも同じ\n' : `\n  ${fails} 件失敗\n`)
process.exit(fails === 0 ? 0 : 1)
