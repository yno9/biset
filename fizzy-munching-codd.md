# DIDComm フロントドア方式（Option ②）実装計画

## Context

ARC.md の DIDComm mediator 再設計（2026-08-27, Phase 1-5）で、mediator は roster/vault-delivery を一切知らない blind な存在になった。しかし議論の中で構造的な壁が判明した：Alice の公開 `routing.json` に書かれる `keyAgreementVerificationMethod` の kid が、そのまま mediator への Forward 配送先としても使われる。この **同一識別子の兼務** により、mediator（あるいは routing.json を解決できる誰でも）が「kid K = Alice」を受動的に相関できてしまう。SimpleX がこれを回避できるのは、queue アドレスが二者間だけで exchange され、どこにも公開されないから。

この計画は、Alice の公開・discoverable な身元（front-door kid、既存の `credential.didcomm.set`）と、実際の継続的なメッセージ配送に使う kid（relationship kid）を分離する。front-door kid は初回接触にのみ使い、初回接触が成立した時点で相手ごとに新しい非公開の kid を確立し、以降のやり取りは全てそちらを使う。

ユーザーとの検討の結果、relationship kid の mediator 登録は **relationship 専用の使い捨て did:peer 身元で認証する**（mediator 自身も「このkidが誰のものか」を知らない状態を達成する）方式を採用する。front-door credential で認証する簡易版は、mediator 自身には Alice の実DIDが見えてしまうため、今回の目的（mediator が完全に不知）を満たさないと判断した。

## 設計

### 用語

- **front-door credential**: 既存の `credential.didcomm.set`（identity 全体で 1 個、`routing.json` に公開）。無改造。初回接触の送受信にのみ使う。
- **relationship credential**: 新規。相手ごとに 1 個、非公開。X25519（内容の authcrypt 用）+ Ed25519（mediator への did:peer:2 登録用）のペア。`contact-key.set`（`protocol/vault.ts` に既に予約されているが未実装の kind）として vault に保存し、identity 内の全信頼端末に同期する。

### ハンドシェイクの流れ

1. **Bob → Alice（初回接触）**: Bob が relationship 用の X25519+Ed25519 鍵を新規生成し、`RELATIONSHIP_INIT` メッセージ（body に Bob 側 relationship kid の公開鍵）を、Bob の front-door credential で authcrypt → Alice の front-door kid 宛に Forward-wrap して送る。既存の `send-message.ts` の経路をそのまま流用（body/type が違うだけ）。
2. **Alice が受信**: 既存の front-door pickup 経路（`DidCommIngressProjector`）で復号。`RELATIONSHIP_INIT` と認識したら、Alice 自身の relationship 用鍵ペアを新規生成し、`contact-key.set` を vault に commit（vault-delivery で全端末に同期）。
3. **Alice が Bob の relationship kid を認証情報として mediator に登録**: **Alice 自身の relationship 用 Ed25519+X25519 鍵から作った使い捨て did:peer:2 身元**で `mediate-request`＋`keylist-update` を送る（mediator は「見知らぬ did:peer クライアントが登録してきた」としか見えない。alice.did は一切登場しない）。
4. **Alice → Bob（RELATIONSHIP_ACCEPT）**: Alice の relationship 鍵で authcrypt（sender = alice の relationship kid）、Bob の relationship kid 宛に Forward-wrap して返信。
5. **Bob が受信**: 同様に `contact-key.set` を自分の vault に commit、Bob 側も自分の relationship kid 用 did:peer 身元で mediator に登録。
6. **以降**: 両者とも、この相手宛のメッセージは常に relationship credential（authcrypt の宛先も送信元も relationship kid）を使い、front-door kid には一切触れない。mediator への登録・pickup も relationship 専用 did:peer 身元で行う。

front-door 経由のトラフィックは「初回接触の瞬間」のみに限定される——これは Signal の X3DH や SimpleX の招待リンクにも共通する残存点であり、これ以上崩すのは費用対効果が悪いと既に合意済み。

## 変更するファイル

### 1. Vault credential 層（新規）

- `src/vault/contact-key.ts` — `ContactKeyV1` 型（`identityId`, `counterpartyDid`, `ownRelationshipKid`, `ownX25519PrivateKey`, `ownEd25519PrivateKey`, `counterpartyRelationshipKid`, `counterpartyPublicKey`, `createdAt`, `supersedesKid?`）+ encode/decode/build/assert 関数。`vault/didcomm-credential.ts` と全く同じパターンで実装（`canonicalBytes`/`createVaultEvent`/`encryptVaultObject` の使い方をそのまま踏襲）。`targetIds` は `contact-key:${counterpartyDid}:${ownRelationshipKid}` のような形にして、同一相手との複数世代（rotation）を区別できるようにする。
- `src/vault/contact-key-reader.ts` — `DidCommCredentialReader` と同じ形。`readAll()`、`forCounterparty(did): ContactKeyV1[]`（相手ごとに全世代）、`currentFor(did): ContactKeyV1 | null`（null は「まだ関係が無い」、正常状態。同一相手に複数の unsuperseded credential があれば `DidCommCredentialReader.readCurrent()` と同じ fail-closed）、`forOwnKid(kid): ContactKeyV1 | null`（受信時の逆引き用）。
- `src/vault/contact-key-sink.ts` — `DidCommCredentialVaultSink` と同じ形。

### 2. Vault event kind の実装

- `src/protocol/vault.ts` — `'contact-key.set'` は既に union に存在（未実装のまま予約されていた）。変更不要。
- `src/local-jmap/reducer.ts` — `'contact-key.set'` の no-op case を追加（`'credential.didcomm.set'` と全く同じパターン）。**これを忘れると、このセッションで 2 回踏んだのと同じクラスのバグ（同期先デバイスで `has no Local JMAP projection rule` エラー）になる**。
- `src/vault/delivery-pack.ts` — 型ガード関数は既に `'contact-key.set'` を含んでいる。変更不要（確認のみ）。

### 3. DIDComm メッセージ型（新規）

- `src/didcomm/relationship.ts` — `RELATIONSHIP_INIT`/`RELATIONSHIP_ACCEPT` の type URI 定数（`https://biset.md/relationship/1.0/{init,accept}`、既存の `PUSH_SUBSCRIBE` 等と同じ biset 拡張 namespace）+ body の型・パース関数（`basicmessage.ts` と同じ形）。

### 4. relationship 専用 did:peer 身元

- `src/didcomm/mediator-transport.ts` の `DidCommSender` — 現状 `{did, xKid, xPriv}` で `did` は暗黙に did:webvh を想定していないが、実際には `sendAndUnpack` は `own.did` を plaintext の `from` に入れるだけなので、**型・実装ともに無改造で did:peer の did をそのまま渡せる**（確認が必要だが、恐らく変更不要）。
- relationship 用 did:peer 身元の生成は `src/didcomm/peer.ts` の既存 `generatePeerIdentity()` をそのまま使う。

### 5. 送信側 (`send-message.ts`)

- `sendDidCommMessage` を拡張: 送信前に `ContactKeyReader.currentFor(toDid)` を確認。
  - 既存の relationship があれば: relationship credential で authcrypt（宛先 kid も送信元 kid も relationship 用）、relationship 専用の登録済み mediator へ Forward-wrap。
  - 無ければ: 現状通り front-door 経由で `RELATIONSHIP_INIT` を送る新しい関数（例: `initiateRelationship(toDid, opts)`）を新設。既存のプレーンな `sendDidCommMessage`（basicmessage 送信）とは呼び分ける——チャット送信 UI 側が「初回か継続か」を意識しなくて済むよう、上位に「relationship があれば使う、無ければ確立してからretry」というラッパー関数を 1 つ用意する。

### 6. 受信側 (`DidCommIngressProjector`)

- 現状 `selfKeys: SelfKeys`（1 個固定）→ 複数鍵に対応させる必要がある。`DidCommJWE.recipients[0].header.kid` から宛先 kid を読み、front-door kid か relationship kid かで使う鍵を切り替える callback (`resolveOwnKey(kid): SelfKeys | null`) に変更。
- `RELATIONSHIP_INIT`/`RELATIONSHIP_ACCEPT` のディスパッチケースを追加。ただしハンドシェイクの副作用（鍵生成・vault commit・mediator 登録・返信送信）は `verifyAndProject` の「復号して vault commit するだけ」という既存の契約を超えるので、**`DidCommIngressProjector` 自体は「認識して audit event を作るだけ」にとどめ、実際のハンドシェイク処理は呼び出し側（`main.ts` の `onMessage`）に持たせる**——`didcomm.control` の扱いと同じ切り分け方。

### 7. main.ts の配線

- `mediator-sync.ts` の `registerWithMediator`/`startMediatorPolling` は現状 1 mediator につき 1 kid（`own.xKid`）決め打ち。relationship kid はそれぞれ別の (mediator URL, did:peer 身元, kid) の組で個別に登録・poll する必要がある——front-door の登録/poll ループとは別に、確立済み relationship ごとに同様のループを回す。
- `onMessage` 内で `RELATIONSHIP_INIT` を検出したら: 新しい relationship 鍵生成 → `ContactKeyVaultSink.store()` → relationship 専用 did:peer 身元で mediator 登録 → `RELATIONSHIP_ACCEPT` 送信 → 以後この relationship 用の poll ループを起動。

## 検証

- `test/contact-key.test.ts`（新規）: `contact-key.ts`/reader/sink の単体テスト。`didcomm-credential.test.ts` 相当のパターンを踏襲。
- `test/mediator-relationship-handshake.test.ts`（新規）: Alice/Bob 両者が did:webvh identity を持ち、front-door 経由で `RELATIONSHIP_INIT`→`RELATIONSHIP_ACCEPT` が成立し、以後のメッセージが **front-door kid を一切使わず** relationship kid だけで届くことを end-to-end で確認。加えて、mediator 側の `connections.ts` の状態を検査し、**relationship kid の登録が alice.did/bob.did と一切紐付いていない**（did:peer クライアントとしてしか記録されていない）ことをアサートする——これが今回の設計の核心的な検証点。
- 既存スイート全体（`bun run typecheck && bun run build && bun run test`）が green であることを維持。特に `reducer.ts` の no-op case 忘れがないか、`bun run test` のフル実行で確認する。

## 実装順序

1. Vault credential 層（`contact-key.ts` + reader/sink + reducer no-op case）+ 単体テスト
2. relationship メッセージ型（`relationship.ts`）
3. `DidCommIngressProjector` の複数鍵対応 + `RELATIONSHIP_INIT`/`ACCEPT` の audit-only 認識
4. `main.ts` のハンドシェイク副作用オーケストレーション + 複数 mediator-poll ループ対応
5. `send-message.ts` の relationship-aware 送信ラッパー
6. end-to-end ハンドシェイクテスト

各段階で `bunx tsc --noEmit && bun run build`（`init_main` カウント 0 確認）を通し、最後にフルテストスイートを走らせる。
