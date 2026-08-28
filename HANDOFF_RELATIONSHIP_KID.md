# 引き継ぎ資料 — DIDCommフロントドア方式（relationship kid）実装

*このセッションの会話履歴を持たない別のagent向け。一緒に渡される `fizzy-munching-codd.md` が実装計画そのもの——このファイルは「なぜそこに至ったか」「今のコードベースが何を前提にしているか」「踏むと分かってる罠」を埋めるためのもの。実装計画を読む前に、まずこれを読むこと。*

## 1. bisetとは何か

JMAPメール + DIDComm チャットクライアントのTypeScriptリライト。アーキテクチャの柱は3つ:

- **did:webvh** — ポータブルな身元(ドメイン移動可能)。identityのDID文書(`did.jsonl`)とDIDComm用の付随文書(`routing.json`)は、どこかの常時稼働HTTPサーバーがホストする(通常は`biset-core`だが、原理的には誰でも自分のドメインでホストできる)。
- **MLS (RFC 9420) self-group** — 同一identityの複数端末間の鍵世代・roster管理。vault-deliveryの配送権限を決めるゲート。
- **Vault Core** — 正本は各端末が持つ暗号化vault。サーバー(`biset-core`)は短命bufferとACK/cursor管理しかしない、永続メールストアにはならない。

作業ディレクトリ: `/Users/n/biset`

## 2. 検証儀式(必須・毎フェーズ後に実行)

このセッション全体を通して徹底してきたやり方。これを飛ばして「動くはず」で次に進まないこと。

```bash
bunx tsc --noEmit                              # 軽量check
bun run typecheck                              # 3つのtsconfig全部(下記参照)
bun run build                                  # クライアントバンドル
grep -o "init_main" dist/app.js | wc -l         # 0でなければcircular import regression、即修正
bun run test                                   # test/**/*.test.ts を1ファイルずつ実行、最初の失敗で停止
bun run knip                                   # dead code検出(下記の既知の許容分は無視してよい)
```

**3つのtsconfig**: `tsconfig.json`(ブラウザ、DOM lib、`src/core`と`src/mediator`を除外)、`tsconfig.core.json`(biset-core、Bun/node、DOM無し)、`tsconfig.mediator.json`(独立mediator、Bun/node、DOM無し、今セッションで新設)。新しいファイルが「クライアント用」か「サーバー用(core/mediator)」かで、どのtsconfigの`include`に入るか変わる——`node:fs`等を使うコードをDOM lib側に置くとtypecheckで弾かれる(これは意図的な設計)。

**knipの既知の許容ノイズ**: `Unused files (6)`(`src/context.ts`, `src/mls/vendor/codec/json.ts`, `src/mls/vendor/customCredential.ts`, `src/route.ts`, `src/state.ts`, `src/types.ts`)は今回のセッション以前からの既存debtで、今回の作業と無関係。新しいunused exportが増えていないかだけ気にすればいい。

## 3. gitの状態について(重要)

このセッション全体(前段のPhase 1-5含む)の変更は**一切コミットされていない**。`git status --short`で90件以上の変更・削除・新規ファイルが積み上がっている状態。

- **ユーザーから明示的に頼まれない限りcommitしない**。
- 破壊的なgit操作(`git checkout .`、`git reset --hard`等)は絶対に実行しない——このセッションの全実装が消える。
- 作業前に`git status`で現状を必ず確認すること。

## 4. なぜこの実装をするのか(経緯)

### 4.1 DIDComm mediator再設計(ARC.md, 2026-08-27, Phase 1-5 — 実装済み)

もともとbisetのDIDComm実装は「biset-core自身がDIDCommの受信endpoint(`POST /v1/didcomm/ingress`)を持つ、中央集権的な設計」だった。これはsrc.bak(旧実装)にあった本来のDIDComm仕様(Mediator Coordination Protocol 2.0、Routing 2.0のForward、Pickup Protocol 3.0、blind queue)を、このリライトの際に意図的に落とした結果だった。

ユーザーが「いつからDIDCommの仕様を無視してるのか」「まず既存のdidcommの設計を全部もどせ」と明確に指示し、「mediatorをroster/vault-deliveryを一切見ないblindな存在にし、複数の独立したmediatorに同じidentityが同時登録できるようにする」という再設計方針が確定した。

**核心のアイデア**: DIDComm keyAgreement鍵を「端末ごと」から「identity全体で1つを共有(vault delivery経由で全信頼端末に同期)」に変える。これにより、blind mediatorのままでも「1つの宛先に送れば、どの端末が受信してもいい」という性質を維持できる(OpenPGPメールcredentialが既にこのパターンの前例)。

この再設計は5フェーズで実装済み、全テストgreen:

| Phase | 内容 | 主なファイル |
|---|---|---|
| 1 | identity共有DIDComm鍵(vault credential化) | `src/vault/didcomm-credential.ts` + `-reader.ts` + `-sink.ts`、`src/identity/bootstrap.ts`の`enableDidComm` |
| 2 | Forward/anoncrypt暗号プリミティブの復元 | `src/didcomm/crypto.ts`(`packAnoncrypt`/`unpackAnoncrypt`) |
| 3 | 独立mediatorサービス(biset-coreとは別デプロイ単位) | `src/mediator/`(`server.ts`, `peer.ts`→後に`src/didcomm/peer.ts`へ移動, `queue.ts`, `connections.ts`, `identity.ts`, `index.ts`) |
| 4 | クライアント側mediatorライブラリ | `src/didcomm/mediator-transport.ts`, `mediator-coordinate.ts`, `mediator-pickup.ts`, `mediator-sync.ts` |
| 5 | 本番配線(すべて`mediatorUrls`設定でopt-in、デフォルト空で無害) | `src/didcomm/webvh-routing.ts`(`mediators`/`routingKeys`)、`send-message.ts`(Forward-wrap)、`enableDidComm`(二段階publish)、`main.ts`(受信bridge)、`src/ui/config.ts`(`mediatorUrls`) |

**ARC.md**と**PLANIMPLEMENTATION.md §2**(このセッションで書き直した)に、現在のアーキテクチャ全体像がまとまっている。実装に入る前に一読を強く推奨する。

### 4.2 匿名性の議論 → 構造的な壁の発見

Phase 5完了後、「biset-coreは今回の設計でどこまでDIDCommのやり取りに対して不知でいられるか」を検討した。結論:

- **達成できてること**: 中身(常にauthcrypt、mediatorは復号不能)、送信者(Forwardはanoncrypt、mediatorは送信者を知らない)
- **達成できていないこと**: **受信者が誰か**。Aliceの公開`routing.json`に書かれる`keyAgreementVerificationMethod`のkidが、そのままmediatorへのForward配送先(`next`)としても使われる。この**同一識別子の兼務**のせいで、mediator(あるいはrouting.jsonを解決できる誰でも)が「kid K = Alice」を受動的に相関できてしまう。

SimpleXがこれを回避できるのは、queueアドレスが二者間だけでexchangeされ、どこにも公開されないから。bisetは「身元は公開・ポータブル、でも関係性(誰と話したか)は隠す」という立ち位置を取りたい——これがbisetのSimpleXに対する差別化軸だとユーザーと確認した。

### 4.3 対策の比較 → Option ②採用

5つの対策(①kid rotation、②フロントドア方式、③フルX3DH、④多段Forward、⑤PIR pickup)を比較し、**費用対効果で②(フロントドア方式)を採用**。①は時間を稼ぐだけで構造は崩れない。③はbisetの脅威モデルに対して過剰。④⑤は別の脅威(timing相関・端末フィンガープリンティング)向けで今回の問題を解決しない。

さらに、relationship kidのmediator登録をどう認証するかで2案を比較し(front-door credentialで認証する簡易版 vs relationship専用の使い捨てdid:peer身元で認証する版)、**後者を採用**——前者だとmediator自身には「alice.didがこのkidを持ってる」と分かってしまい、「mediatorが完全に不知」という目的を満たさないため。

## 5. 承認済み実装計画

`fizzy-munching-codd.md`(このファイルと一緒に渡される)を読むこと。設計・変更ファイル一覧・検証方法・実装順序がすべて書かれている。**この資料はその前提知識を埋めるためのもので、計画自体はそちらが正**。

## 6. 実装時に踏むと分かってる罠

### 6.1 `local-jmap/reducer.ts`の no-op case忘れ

**このセッションで2回踏んだバグ**。新しいvault event kindを追加したら、`reduceLocalJmapProjection`(`src/local-jmap/reducer.ts`)に対応するno-op caseを必ず足すこと。忘れると、その event を同期で受け取った他端末が `vault mutation kind '...' has no Local JMAP projection rule` で例外を投げる(mailboxに関係ない種類のeventでもfail-closedなので)。

計画で使う`'contact-key.set'`は**`src/protocol/vault.ts`の`VaultEventKind`union に既に予約されている**(未実装のまま)。reducerへのno-op case追加を忘れないこと。既存の`'credential.didcomm.set'`のcase(84-91行目あたり)がそのままテンプレートになる。

### 6.2 vault credentialパターンの模倣元

`src/vault/didcomm-credential.ts` + `-reader.ts` + `-sink.ts`が、今回作る`contact-key.ts`系の完全なテンプレート。`canonicalBytes`/`createVaultEvent`/`encryptVaultObject`の使い方、`assertXxx`での自己検証(kidが公開鍵から正しく導出されているかのチェック)、`readCurrent()`のfail-closedなambiguity処理——全部同じ形で書く。車輪の再発明をしないこと。

### 6.3 mediatorはすでにdid:peerクライアントを一級市民として扱っている

`src/mediator/server.ts`のdispatchロジックは、did:webvhクライアントとdid:peerクライアントを区別なく扱える設計になっている(`resolveSenderKey`が`did:peer:2.`prefixなら`decodePeerDid2`で自己証明的に解決、そうでなければ`resolveDidWebvh`で外部解決)。`test/mediator-server.test.ts`・`test/mediator-client.test.ts`で、did:peer身元同士の完全なend-to-endを既に実証済み。**relationship専用のdid:peer身元を使う設計変更は、mediatorサーバー側の無改造で成立するはず**——変更が要るのはクライアント側(`mediator-transport.ts`の`DidCommSender`型が暗黙にdid:webvhを想定していないか)だけ。

### 6.4 `src/didcomm/peer.ts`の場所に注意

did:peer:2のエンコード/デコード(`generatePeerIdentity`, `decodePeerDid2`, `publicKeyOf`等)は、最初`src/mediator/peer.ts`に書いたが、クライアント側(ブラウザバンドル)も使う必要が分かったので**`src/didcomm/peer.ts`に移動済み**。`src/mediator/`配下はnode:fsを使うサーバー専用コード(`identity.ts`, `queue.ts`, `connections.ts`)だけが残っている。新しいコードはこの層分けを崩さないこと——クライアントから使う可能性があるものは`src/didcomm/`に置く。

### 6.5 `main.ts`は巨大かつこのセッションで頻繁に触っている

`bootClient()`という1関数が非常に大きい(600行超)。DIDComm関連の状態(`mediatorPollHandles`という module-level配列でpoll handleを追跡、`bootClient()`冒頭でクリア)、`enableDidComm`呼び出し、`syncMailIngress`のprojector構築、mediator登録・pollループが全部この中にある。編集時は既存の変数スコープ(`boundary`, `sequencer`, `deviceKid`, `vaultStore`, `readModel`)を注意深く追うこと。TypeScriptの型narrowing対策で`const deviceKid = identity.deviceKid`のように一度だけ変数に捕まえてから使う書き方が随所にある——`enableDidComm`の`identity = await enableDidComm(...)`という再代入がnarrowingを壊すため。

### 6.6 fetch注入パターン

すべてのネットワークI/O関数(`fetchMediatorInfo`, `sendAndUnpack`, `registerWithMediator`, `pickupDeliver`等)は`fetchImpl: typeof fetch = defaultFetch()`という最後の引数パターンで統一されている(`src/net-fetch.ts`の`defaultFetch()`)。新しい関数もこのパターンを踏襲すること——**引数を追加した時に、呼び出し元すべてに`fetchImpl`を配線し忘れると、テストで注入したfetchスタブが無視されて実ネットワークに飛ぼうとして落ちる**(このセッションでPhase 4で実際に踏んだバグ)。

### 6.7 `fetchMediatorInfo`のin-memoryキャッシュとテスト分離

`mediator-transport.ts`の`fetchMediatorInfo`はmediator URLをキーにした**モジュールレベルの**in-memoryキャッシュを持つ。テストで同じURL文字列を複数テストにまたがって使い回すと、前のテストの(別の)mediator身元が誤って返る。テストごとに`https://mediator-${crypto.randomUUID()}.test.example`のようなユニークなURLを使うこと(`test/mediator-client.test.ts`の`freshMediatorFetch()`参照)。

### 6.8 `identity/webvh/resolver.ts`の`resolve()`はfetch注入を受け付けない

did:webvh解決の読み取り側(`resolve()`)は常に**実際のglobalThis.fetch**を使う設計(注入ポイントが無い、意図的)。mediatorがdid:webvhクライアントを認証するテストを書くときは、`globalThis.fetch`をテスト用スタブに差し替える必要がある(`test/protocol/enable-didcomm.test.ts`の`withGlobalFetch`ヘルパー参照)。今回の計画ではrelationship kidの登録はdid:peerベースなのでこの問題自体は避けられるはずだが、front-door経由の`RELATIONSHIP_INIT`送受信テストではこの罠に当たる。

### 6.9 コミットメッセージ規約

ユーザーから明示的に指示されるまで**commitしない**。commitする場合は`Co-Authored-By`等のトレーラーを付けない(このユーザーの既存の指示)。

## 7. このセッションで実装済みの周辺テストパターン(再利用推奨)

- `test/mediator-server.test.ts` — mediatorサーバーの直接テスト(did:peerクライアント同士)
- `test/mediator-client.test.ts` — クライアントライブラリ経由のend-to-end、`freshMediatorFetch()`ヘルパー(mediator handleをfetchスタブとして扱う)
- `test/protocol/enable-didcomm.test.ts` — `combinedFetch()`ヘルパー(複数のURL originを1つのfetchImplに束ねる)、`withGlobalFetch()`ヘルパー
- `test/protocol/didcomm-send-message.test.ts` — Forward-wrap送信の検証パターン(mediator側でanoncrypt→Forward→内側authcryptを剥がして検証)

これらのヘルパー関数は、今回のrelationship kidのend-to-endテストでもほぼそのまま使い回せるはず。
