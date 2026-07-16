# biset DIDComm relay — Implementation PLAN

Status: **draft** 2026-07-15 (design only; whether to implement at all is undecided)

Scope note: this plan covers "DID-based messaging" (DIDDISCUSSION.md §3–6), i.e. a new
`jmapdidcomm` relay for lightweight biset↔biset direct messages — distinct from the
Pkarr/did:dht identity layer itself, which is already implemented (see [DID.md](DID.md)).
Background/tradeoffs: [DIDDISCUSSION.md](DIDDISCUSSION.md).

**Guiding principle (added mid-session, overrides earlier framing below where they conflict):**
biset ユーザーが真にDIDCommという普遍的なエコシステムの住人になること。biset固有の
簡略化に逃げず、標準準拠・相互運用性を最優先する。この結果、当初の一部決定(mediator
なし、JMAP Emailモデル流用)は覆り、下記の通りDIDComm標準のMediator機構をフル採用する
方向に転換した。

## Motivation

AP(ActivityPub)経由は federation full-stack(service解決 + MLS group crypto)を要求する。
biset ユーザー同士だけなら、もっと軽いダイレクトチャンネルが引ける — 既存の
「DID Documentのserviceで相手を発見する」「1 relay = 1 protocol」設計をそのまま伸ばす形で。

## Decisions

### Protocol: DIDComm Messaging v2.1, standard-compliant (decided)

Nostr NIP-17(低コスト代替)より先にこちらを本採用として検証する。理由:
biset の既存資産(`resolver.ts` の `resolve(did)`、service配列でのrelay発見、
relay=protocolのバイナリ分割)と設計思想が直接一致するため、迂回コストが最小。
Nostr NIP-17 は non-goal(下記)として一旦保留 — 将来、実装コストの安さを理由に
再検討する余地は残す。

**ターゲットバージョンはv2.1**(2026-07-15確認: DIF Approved Status、v3という
次バージョンは存在しない。`decentralized-identity/didcomm-messaging` が正式仕様
repo)。相互運用性を最優先事項とするため、独自拡張は最小限にとどめ、
標準アルゴリズム・標準メッセージ構造(JWM plaintext → JWE)に厳密に従う:

| 用途 | Key Agreement | Content Encryption |
|---|---|---|
| anoncrypt(匿名暗号化) | `ECDH-ES+A256KW` | `A256GCM`(推奨)または`A256CBC-HS512`(必須) |
| authcrypt(送信者認証付き) | `ECDH-1PU+A256KW` | `A256CBC-HS512`(必須、ECDH-1PU仕様上) |

biset の用途(既知の相手DIDへの直接送信)は送信者を隠す理由がないため、
**authcrypt(`ECDH-1PU+A256KW`)をデフォルトとする**(送信者なりすまし防止の
恩恵の方が大きい)。anoncryptは将来必要になれば追加検討。

### Key material: new X25519 key, seed-derived (決定・実装再開 — 2026-07-15、経緯は下記)

**一度撤回しかけたが、最終的に復活・実装する。** 経緯: 「DIDCommは常に
did:peer経由、did:dhtには依存しない」に一本化しかけたが、その場合
「相手のdid:dhtしか知らない状態からのコールドスタートDIDCommが原理的に
不可能」という欠落が判明した(did:dht文書にDIDComm用の鍵・情報が一切
無いため)。**結論: did:peer経路(mail/AP経由で接触した相手向け)と
did:dht直接経路(お互いdid:dht対応mediatorを持つ場合のコールドスタート
向け)を両立させる。** 本節はdid:dht直接経路のための鍵material決定として
実装を再開する。

既存の派生パターン(root/Nostr/PGPそれぞれ専用path、`keys.ts`)をそのまま伸ばし、
**DIDComm用に新規X25519鍵を一本、masterSeedから決定的に派生する**。

検討した他の2案とも却下:
- **root ed25519をX25519に変換して流用** — birational conversionで技術的には可能だが、
  同一秘密鍵を署名(Pkarr put)と鍵合意(JWE ECDH-ES/1PU)の両方に使うのは鍵separation
  原則に反する(cross-protocol攻撃面 — 片方のプロトコルの脆弱性がもう片方に波及しうる)。
- **MLS per-device leafを転用** — leafは意図的に device-local・非バックアップ設計
  (`ARC.md` MLS節)。DIDCommは「seed一本で全識別子・全メッセージ回復可能」という
  既存哲学(`DID.md` 全体)に合わせたいので、device-localな鍵を混ぜると哲学が崩れる。

**Path**: 次の空きprivate path `m/1'` を割り当てる(root=`m/0'`、PGP=`m/2'`[予約、
`keys.ts`未実装]、Nostrは別ツリーのNIP-06)。

**DID Document verification method: `_k1`、key-type-index = `3`(確定)。**
did:dht公式registry(`decentralized-identity/did-dht` の `spec/registry/spec.md`、
2026-07-15確認)で X25519 は index `3`、デフォルトアルゴリズム
`ECDH-ES+A256KW` と明記されている(root Ed25519は既存の `_k0` = index `0` と
同一パターン)。

**Rotation policy: rotation-less(検討の上で確定、FSは意図的に持たない)。**

一度「rootと同じ思想だから」で決定しかけたが、それは正当化として不十分だった
(root鍵漏洩=なりすましという単一イベントに対し、鍵合意用X25519鍵の漏洩は
過去に傍受・記録済みの暗号文を遡って全復号されるという質的に異なる被害を生む)。
そこでSignal的なX3DH(Identity Key + Signed PreKey + One-Time PreKeyの3層)による
forward secrecy導入を検討したが、以下の理由で見送った:

- X3DHがFSを生む本質は「使い終わった鍵の秘密鍵を非可逆的に破棄する」こと。
- ところがbiset全体の鍵設計原則は「masterSeedから全鍵を決定的導出、backup=
  24-word mnemonic一本で全識別子・全鍵を復元可能」(`DID.md` 全体)。
- SPK/OPKをこの原則どおりseedから決定的導出すると、「破棄」しても`path`から
  常に再導出できてしまい、`masterSeed`漏洩時に過去の全SPK/OPKが再現される
  ため、真のFSは崩壊する(SPK/OPK単体の漏洩に対する限定的FSは得られるが)。
- 真のFSにはSPK/OPKを**seed非導出・ランダム生成・使い捨て**にする必要があるが、
  これは「seed一本で全復元」という一貫した設計原則の例外を持ち込むことになる。
- 検討の結果、**seed一本復元の原則を優先し、この例外は受け入れない**と決定。
  よってDIDComm用X25519鍵はIK相当の一本のみ、rotation-less、FSなし。

**この判断の裏返しとして、用途制限方針を明文化する**: jmapdidcommは軽量な
短文連絡用途に限定し、機密性の高いやり取りは引き続きAP側(MLS、FS+PCSあり)
に誘導する。同一ユーザーの2つのE2EEチャンネルでセキュリティ水準が異なる状態を
意図して受け入れる、という明示的なトレードオフ。

**仕様側の裏付け(2026-07-15確認)**: DIDComm v2.1仕様自体が
"perfect forward secrecy is not formally required due to the lack of a
session construct, but similar outcomes must be achievable"と明記しており、
詳細はDIDComm Guidebook任せにしている。標準のstatic鍵JWE(ECDH-ES/1PU)を
そのまま使うこの決定は、仕様の想定範囲内であり、相互運用性を損なわない
(独自にX3DH/Double Ratchetを載せていた場合の方がむしろ標準逸脱だった)。

### DIDComm transport identity: did:peer(相手ごと)とdid:dht直接、両方式併用(最終決定、2026-07-15)

**一度「常にdid:peer、did:dhtには依存しない」に一本化しかけたが、それだと
致命的な欠落がある——相手のdid:dhtしか知らない状態からのコールドスタート
DIDCommが原理的に不可能になる**(did:dht文書にDIDComm用の鍵・情報が
一切無いため、`sendDidComm`が「no DIDCommMessaging service」で即失敗する)。
検討の結果、**2経路を両立させる**方針に最終決定:

1. **did:peer経路(相手ごと)** — mail/AP経由で既に接触した相手向け。
   「相手ごとにdid:peer」という発想自体は一度却下したが
   (名寄せ防止の効能がbisetの脅威モデル上薄い、[[project_biset_didcomm]])、
   今回の動機は名寄せ防止ではなく**did:dhtを解決できるmediatorがまだ
   普及していない実務上の制約への対応**。ルート: mail/APで接触 →
   その相手用にdid:peerを生成・交換 → 以後のDIDCommはそのdid:peer経由。
   biset自身のidentifierを増やす話ではない(did:peerは常にDIDComm専用の
   補助的な鍵で、「あなたが誰か」を主張する識別子ではない)。
2. **did:dht直接経路** — 相手のdid:dhtしか知らない状態からの
   コールドスタート向け。お互いdid:dht対応mediator(将来のdidmediator/
   biset serve)を持つ場合に有効。上記「Key material」節の`_k1`実装を
   これに向けて再開する。

**biset自身の恒常的な身元(mail/AP発見用)は`did:dht`のまま不変**——今回の
決定はDIDCommの「輸送経路」の話であり、identifierそのものの話ではない。

**未設計(次の課題): mail/AP経由でのdid:peer交換の具体的な方法。**
相手の初回メッセージ本体に埋め込むのか、JSContact Card(`did/contacts.ts`の
`ContactCache`/`Card`)の追加フィールドとして同期するのか、まだ決めていない。

### Mediator model: 正式なDIDCommMediatorをフル採用(方針転換、2026-07-15)

**当初「third-party mediatorなし、直接POST」と決定したが、これは覆った。**
きっかけは「biset ユーザー同士がDIDエージェントとして直接やり取りする」という
理想を検討したこと — biset のクライアントはブラウザであり、常時稼働のHTTP
サーバーになれない(スマホと全く同じ制約: 電源off、タブを閉じる、NAT内)。
非同期メッセージングを実現する以上、どこかに常時稼働の預かり所は必要で、
これはまさにDIDComm標準のMediatorが解決する問題そのもの。

**relay=recipient自身の一部(mail/APと同型)モデルと、relay=純粋なMediator
モデルの違いは「relayが中身を読めるか」ではなく「relayが宛先の人物(メタ
データ)を知っているかどうか」。** 前者(当初案)はrelayがアカウントを持ち、
「これは誰某のアカウント宛だ」と知っている。後者(採用案)はrelayが鍵IDしか
知らず、forward wrapping(二段階暗号化)で「誰の鍵宛か」だけを扱い、recipient
が誰かを知らない。

**決定: 各ユーザーの `jmapdidcomm` relay自体が、他人のMediatorとしても
機能する。** DID.mdの既存gateway哲学("The gateway holds zero authority"、
"any Pkarr gateway on earth resolves the same records" — fungibleな
commodity)と同じ発想をそのまま踏襲する。専用の共有Mediatorインフラを新設
する必要はなく、`jmapdidcomm` 単体プロセスに標準機能として組み込む。
(実装言語はGoではなくTypeScript/Node.js — 下記「Server-side language」節
参照。よって既存Go relay群との"share libraries, not state"はここでは
適用されない — 元々永続化も専用の鍵ID→キューモデルにする決定だったため、
Go共有ライブラリへの依存自体が薄かった。)

**認証・永続化: DIDComm標準の Mediator Coordination Protocol(2.0)+
Pickup Protocol(3.0)を正式採用(既存`provision.go`/JMAP Emailモデルの
流用は撤回)。**

- **Mediator Coordination Protocol**: BobがMediator(=誰かのjmapdidcomm
  relay、自分のものでも他人のものでもよい)の利用を登録する手続き。
  やり取りはDIDCommメッセージそのもの(Bobの鍵で署名・暗号化)。
- **Pickup Protocol**: Bobが「新着ある?」(`status-request`)→ 受け取る
  (`delivery-request`/`delivery`)→ 既読にする(`messages-received`)を
  DIDCommメッセージとして行う。Live Mode(WebSocket等でのpush)もある。
- **認証はパスワード/envelopeではなく鍵ベース**: 「この鍵の持ち主である
  ことを暗号的に証明できるか」だけで完結する。Mediatorは「これは誰の
  アカウントか」を知る必要がない — アカウントという概念自体が薄れる。
- **永続化は「鍵ID→溜まった暗号化メッセージのキュー」**。既存JMAP Email
  モデル(`go-jmapserver` の `Store`)への流用は撤回 — Mediatorはアカウント
  もMailboxも持たない、鍵IDでスコープされた単純なキューだけを持つ。

**Mediator自身の鍵ペアが新規に必要(Open design question、下記)。**
forward wrappingの外側の封筒を復号するのは、Bob個人の鍵ではなく
**relay(Mediator)自身の鍵ペア**。これはbiset既存relay群(jmapsmtp/jmapap)
には存在しない概念(今はTLS証明書はあってもDIDComm的な鍵ペアはない)。

**送信ルーティングモデル: forward wrapping(DIDComm Routing 2.0 protocol)
を正式実装(決定)。** Aliceのクライアントは:
1. Bobの`_k1`鍵でメッセージを暗号化(inner message)
2. inner messageを、MediatorのX25519鍵で**forward wrapping**(外側の封筒)
3. MediatorのエンドポイントへforwardメッセージとしてPOST
4. Mediator(relay)は外側だけを復号し、「鍵ID宛」のinner messageをキューに保存
   (中身は読めない、E2EEは保たれる)
5. Bobが後でPickup Protocolで取りに行く

### Server-side language: TypeScript/Node.js(決定、Go前提を覆す、2026-07-15)

`jmapdidcomm` は当初、既存relay群(jmapsmtp/jmapap/go-jmapserver)と同じGoで
書く前提だった("share libraries, not state")。実地検証(下記)の過程で、
**Go向けの現役・実績ありなDIDComm v2ライブラリが実質存在しない**ことが
判明し、前提を覆した。

- TS/JS向けには `didcomm`/`didcomm-node`(sicpa-dlab製、Rust実装をwasm-bindgen
  でコンパイル)という実績あるライブラリがあり、実際にbiset環境(bun)で
  pack_encrypted/unpack/forward wrappingの動作を確認済み(下記「実地検証」参照)。
  `enc_alg_auth`のデフォルトが `A256cbcHs512Ecdh1puA256kw`
  (`ECDH-1PU+A256KW`/`A256CBC-HS512`)と、既に決定していたauthcryptの
  デフォルトとそのまま一致していた。
- Go向けで唯一有力だった `hyperledger/aries-framework-go` は
  **2024-03-27にアーカイブ済み(read-only、メンテナンス終了)**。フォーク
  (`scoir/aries-framework-go`等)の生死は未確認だが、少なくとも「安心して
  乗れる現役ライブラリ」ではない。
- 暗号実装(JWE/ECDH-1PU/forward wrapping)の自前実装は、前段の決定
  (「車輪の再発明は避ける、暗号バグは深刻な脆弱性に直結する」)と真正面から
  矛盾するため、Goで自前実装するくらいなら実績あるライブラリに乗れる言語を
  選ぶ方が「標準準拠・相互運用性最優先」というガイディング原則に忠実。

**トレードオフとして受け入れる点:**
- 既存relay群(Go、シングルバイナリ配布)とは異なり、`jmapdidcomm` は
  Node.jsランタイムが必要になる — デプロイ・運用の型が既存relayと変わる。
- "1 relay = 1 protocol"というバイナリ分割パターン自体は維持されるが、
  言語が混在することになる(Go群 + jmapdidcommのみTS)。
- 将来Go向けの現役DIDCommライブラリが登場すれば移植を再検討する余地はある
  が、v1はこの前提を覆さない。

**再検討・再確認(2026-07-15、Rustとの比較後):** 実地検証で
`adorsys/didcomm-mediator-rs` という実際に動くRust製Mediator実装を発見した
後、改めてTS/Rustを比較した。TS/JS向け`didcomm`パッケージとRust版
`didcomm-rust`(sicpa-dlab)は同一の暗号実装(wasm-bindgen経由か、ネイティブ
かの違いのみ)なので、暗号信頼性の観点では両者に差がない。争点は
「Mediatorのビジネスロジック(Coordination/Pickup/Routing Protocolの処理、
キュー管理)をゼロから自分たちで書く(TS)か、adorsysの実装をforkして土台に
する(Rust)か」に絞られた。

**決定: TSを維持、ゼロから自分たちで書く。** 理由:
- adorsys forkは実装コストを下げるが、上流追従・fork管理という継続的な
  保守コストと、bisetの技術スタックにRustという新言語を持ち込む学習コスト
  を伴う(現状biset は Go+TSのみ)。
- TSはbisetクライアント本体と言語が統一され、did:dht resolverやdid:peer
  エンコード/デコードロジック(今回のscratchコードで実装済み)をそのまま
  共有できる。
- 実装量は増えるが、全体を自分たちでコントロールできる。

### 命名の再検討: `jmapdidcomm` → `didmediator`案(未確定、2026-07-15)

`jmapdidcomm`という名前は、既存relay群(jmapsmtp/jmapap)の命名規則
("jmap" + プロトコル名 = "外部プロトコルをJMAPに翻訳するアダプタ")を
踏襲しているが、実態と食い違うと判明した。既存relayは全て「JMAPサーバー
として実装され、JMAP Email/Mailboxのデータモデルで動く」のに対し、今回の
Mediatorは**JMAPを一切話さない**(永続化は専用の「鍵ID→キュー」モデル、
既存Go relay群のJMAP Storeは使わない、上記Mediator model節で既に決定済み)。

代替案として`didmediator`が挙がっている — bisetの既存先例
`go-didanchor`("did" + 機能名そのまま、mail/AP relayとは別枠のDID専用
補助サービス)と同じ命名パターンで、DIDComm仕様の正式用語(Mediator
Coordination Protocol等)にも対応する。`didnode`案(P2P/DHT文脈の"node"を
連想させ、機能が伝わりにくい)より明確という評価。**まだ最終決定していない**
— 実装着手時に確定させる。

**anchor(`go-didanchor`)との統合は保留、念頭に置くのみ。** 「同じDID専用
補助サービス系統としてまとめる」という発想自体は一貫性があるが、
`go-didanchor`はGo実装であり、今回Mediatorの実装言語をTS/Node.jsに
決定した(下記「Server-side language」節)ため、今すぐの統合は言語の面で
矛盾する。将来的に(a) anchorをTS/Node.jsに移植して統合する、(b) 言語は
分けたまま運用上の括り(呼称・モノレポ等)だけ揃える、のいずれかを検討する
余地を残す — v1のスコープには含めない。

### Multi-method resolution: biset自身のDIDは`did:dht`一本を堅持(決定)

**節末尾の「biset自作Mediatorのresolverはdid:dht+did:peer両対応にする」は
優先度復活(2026-07-15、上記「DIDComm transport identity」参照)。**
一時「DIDComm自体が常にdid:peer経由」に一本化しかけて優先度を下げたが、
did:dht直接経路(コールドスタート向け)も併用する最終決定により、
mediator側のdid:dht解決対応は再び必要——節本体(biset自身のidentifierは
did:dht一本)の結論は終始不変。

「他のDIDComm実装との相互運用を最大化したいなら、他のDID method(did:webvh等)
にも対応すべきでは」という提起があったが、**biset自身が複数のDIDを持つのは
却下**。同一人物が`did:dht:xxx`と`did:webvh:yyy`という2つの独立したDIDを
持つと、「両者が同一人物である」ことを外部に証明する手段が別途必要になり、
これはDID.mdが解決した「同一idの分裂」問題([[project_biset_identity_split]]
と同型)がDIDそのもののレベルで再燃する — 解決したい問題より新しく作る問題
の方が大きい。

**分けて考えるべき2つの話:**
1. **biset自身のidentifier** — `did:dht`一本のまま(DID.mdの既存原則
   "multi-method support is YAGNI"を維持)。ここは触らない。
2. **相手(他のDIDComm実装ユーザー)のDIDを解決する能力** — `resolve(did)`の
   内部実装をDIDのprefixで分岐させ、`did:webvh`等も解決できるようにする
   ことは、biset自身のidentifierを増やすことにはならない。これは
   「送信側の相互運用性」(bisetユーザーが他実装ユーザーへ送れるように
   する)には効くが、「受信側の相互運用性」(相手がbisetの`did:dht`を
   解決できるか)には直接効かない — 後者は引き続きdid:dht仕様側の普及や
   下記のAdditional Properties Registryへの貢献が本筋。

DID.mdの原則「multi-method support is YAGNI」は「biset自身のidentifierの
methodについて」に限定再解釈する — 相手のDIDを読む側のresolverが複数
method対応になることとは矛盾しない。

**この原則の直接的な帰結: `jmapdidcomm`(自作Mediator)のresolverは
`did:dht` + `did:peer` 両対応にする(決定、2026-07-15)。** 実地検証で
RootsID/adorsysどちらも送信者DIDとしてdid:dhtを拒否した("Unsupported DID")
のは、**DIDComm仕様がdid:peerを要求しているからではなく、相手のresolver実装
がdid:dhtを知らないだけ**という区別が重要 — これは実装の狭さの問題であり、
仕様上resolverはmethod非依存であるべき。この区別を踏まえ:

- **biset自作Mediatorのresolverにdid:dht解決(既存`resolver.ts`のDHT問い合わせ
  ロジックを流用)とdid:peer解決(自己記述デコード、ネットワーク不要)の両方を
  実装する。**
- **効果**: biset↔biset間の通信は、双方とも`did:dht`のまま変換ゼロで
  Mediatorと直接やり取りできる — 「Mediator接続用の一時did:peer生成」という
  迂回(下記Open design questionsに残す)は、**biset↔他実装間の通信でのみ**
  必要になる(相手側resolverの制約に依存するため、biset側だけでは解消できない)。
  さらに、biset MediatorがDID method解決の対応範囲を広く持つことで、
  他のDIDComm実装のユーザー(did:peer使い)もbiset Mediatorに接続できる、
  という非対称的な優位性が生まれる — 自分たちが同じ失敗(method決め打ちで
  他実装を拒否する)を繰り返さないための設計。

### DID Document encoding: decided (2026-07-15, verified against upstream specs)

新規 verification method `_k1`(X25519、key-type-index `3`)+ 新規service
`_s2`(`type=DIDCommMessaging`)。

**serviceEndpoint構造には仕様間のギャップがあった。** DIDCommMessaging serviceは
標準では `serviceEndpoint` がオブジェクト(`{uri, accept, routingKeys}`)を要求する
(W3C DID Specification Registriesにも`routingKeys`/`DIDCommMessaging`は正式登録
済み — Section 6.2.3)。一方did:dht本体仕様(`spec/spec.md` のtest vector群、
2026-07-15確認)は`se=` フィールドをURI文字列のリストとしてのみ規定しており、
オブジェクト構造の格納方法を定義していない。ただしW3Cレジストリは
JSON-LDレベルの意味論だけを定義し、method固有のwire encodingは範囲外 —
did:dhtがどうDNSに落とすかは、did:dht自身が決める話。

**発見: did:dht仕様には「Additional Properties Registry」という正式な拡張
窓口がある(`spec/registry/spec.md`)。** 既に`sig`/`enc`という2つのService用
プロパティが登録済み(形式: `id=M;t=N;se=O;sig=S;enc=E`、"String or array of
strings")。仕様自体が「追加したければ`TBD54566975/did-dht`へPRを送ってくれ」
と明記している。

**決定: `accept`/`routingKeys`のDNS表現を、`sig`/`enc`と同じパターンで
did:dht公式Additional Properties Registryへ正式にPR提案する。**

```
id=M;t=DIDCommMessaging;se=O;ac=A;rk=R
```
- `ac` = `accept`(profile文字列、複数ならカンマ区切り) 例: `ac=didcomm/v2`
- `rk` = `routingKeys`(DID URL、複数ならカンマ区切り) 例: `rk=did:dht:xxx#k1`

これは新概念の発明ではなく、「W3Cで既に標準化された`routingKeys`
(DIDCommMessaging serviceの一部)を、did:dhtのDNS表現にマッピングするだけ」
の提案であり、`sig`/`enc`の前例と同じ筋の拡張として説得力がある。biset の
実装はこの形式を先行採用する(PRのマージ有無に関わらず動作は変わらない —
マージされれば他のdid:dht実装からも解釈可能になり相互運用性が上がる)。

**実装完了・検証済み(2026-07-15)。** `src/did/keys.ts`に`deriveDidCommKey`
(X25519、`m/1'`、seed導出——root ed25519からの変換ではなく独立path、
決定論性・独立性をscratchで確認済み)、`src/did/document.ts`に`_k1`
verification method + `DidService.accept`/`routingKeys`(`ac=`/`rk=`)を
追加。**`TBD54566975/did-dht`のspec.md本文を直接取得し、`agm=`(keyAgreement
relationship略称)と、その配置順を含むroot recordの実例
(`v=0;vm=k0,k1;auth=k0;asm=k0;agm=k1;inv=k0;del=k0;svc=s0`)をそのまま
参照して実装**——記憶からの再構成ではない。往復テスト
(`scratch-k1-document-check.mjs`)でroot record文字列がspec.mdの実例と
完全一致することを確認、既存の`_k1`なし文書への非破壊性も回帰確認済み。
`buildBisetDocument`(既存のdocument builder helper)は未変更のまま。

**mediator登録・publish連動の呼び出し側、実装完了(2026-07-15)。**
新規`src/did/didcomm/register.ts`の`registerDidCommViaDht`——`_k1`派生→
mediate-request/keylist-update→`keyAgreementKey`+DIDCommMessaging
serviceを追加した文書をrepublish、まで一気通貫。実装にあたり
`coordinate.ts`/`message.ts`の`own`パラメータ型を`PeerIdentity`から
最小限の構造的interface `DidCommSender {did,xKid,xPriv}` に一般化
(did:peerとdid:dht、両方のアイデンティティが同じmediator調整コードを
共有——既存のdid:peer呼び出し側は構造的型付けによりノータッチで動作継続、
回帰なしを確認済み)。

**既知の制約に、実際にちょうどそこでぶつかることを確認済み
(`scratch-k1-mediator-register-check.mjs`)。** 実際に動いている
`~/didmediator`へ`registerDidCommViaDht`を投げると、mediate-requestの
送信自体は成功するが、mediator側が`packReplyTo`でこちらのdid:dhtを
解決しようとした瞬間に失敗する——エラーメッセージも
"did:dht resolution not yet implemented ... see PLAN.md Multi-method
resolution"と、こちらが書いたTODOスタブの文言そのまま返ってくる。
**呼び出し側のコードは正しく、想定通りの一点でのみブロックされている**
ことを確認——didmediator側のdid:dht resolver実装が次の依存。

## `~/didmediator`側のdid:dht resolver実装完了、実物のMainline DHT相手にend-to-end成功(2026-07-15)

**Pkarrゲートウェイの自前実装は不要だった。** 以前保留にした「Pkarrゲート
ウェイをゼロから実装」はDHTを自分で話すサーバー側の話——今回必要だったのは
「既存の公開ゲートウェイにHTTPで問い合わせるだけ」のクライアント側で、
これはbiset本体の`src/did/resolver.ts`が既にやっている。DHTクライアントの
新規実装は一切不要と判明。

**`~/didmediator/src/diddht/`(新規)** に、biset本体の
`resolver.ts`/`packet.ts`/`dns.ts`/`zbase32.ts`/`document.ts`から
resolve専用の部分(publish側は不要——mediatorは自分のdid:dhtを持たない)を
移植。`freshness.ts`の巻き戻り防止だけ`localStorage`(ブラウザ専用API、
Bunに無い)からin-memory Mapに変更(`queue.ts`/`connections.ts`と同じ
「揮発性でv1としては十分」判断)。`src/resolver.ts`の`createResolver`に
did:dht分岐を接続、did:dht文書→didcomm-node向け`DidDoc`形式への変換
(`toDidDoc`)を追加。

**実際のMainline DHT(localhostではなく本物の`relay.pkarr.org`/
`pkarr.pubky.org`)相手にend-to-end動作確認(`scratch-k1-live-dht-check.mjs`)**:
新規did:dht identityを実際に公開ゲートウェイへpublish → `~/didmediator`が
新実装のresolverでそれを解決 → mediate-request/keylist-update成功 →
`_k1`+DIDCommMessagingサービス入りの文書を再publish、まで完走。

**この過程で発見・修正したバグ: `register.ts`の発行順序が逆だった。**
`_k1`をmediatorに登録する前に、そもそも`_k1`入りの文書をDHTにpublishして
いなかった——mediatorが「解決先にまだ存在しないkid」でauthcryptしようと
して"Sender kid not found in did"で失敗。**2段publishに修正**: (1)`_k1`
だけ先にpublish→解決可能にする、(2)mediate-request/keylist-update、
(3)DIDCommMessagingサービスを足して再publish。この順序性の必然は
一発検証では見えず、実際に実DHTへ通してみて初めて表面化した——
`~/didmediator/ARC.md`にも「呼び出し側の落とし穴」として記録済み。

`pickup.ts`も`coordinate.ts`/`message.ts`と同様に`DidCommSender`型へ
一般化(did:peer/did:dht双方が同じPickup Protocolクライアントを共有)。
既存のdid:peer経路の全チェック、回帰なしを再確認。

## UI(`/didcomm`デバッグページ)、did:dht経路も送受信対応完了(2026-07-15)

**新規`src/did/didcomm/resolve.ts`**: `resolveDidCommDoc(did)`——相手の
DIDがdid:peerかdid:dhtかをprefixで判定し、どちらも同じ`PeerDidDoc`形状に
変換して返す統一resolver(didmediator側`resolver.ts`の`toDidDoc`と同じ
変換ロジックをbisetクライアント側にも用意)。`resolveSenderPublicKey`
(pickup.tsの`resolveSenderKey`形状、method非依存)も追加。

**`send.ts`も`DidCommSender`型へ一般化完了**——did:peer専用だった
`sender`パラメータ、forward-wrap時のmediator解決(旧: `decodePeerDid2`
決め打ち→新: `resolveDidCommDoc`)を両方直した。これで`coordinate.ts`/
`message.ts`/`pickup.ts`/`send.ts`の全てがdid:peer/did:dht両対応に統一。

**`register.ts`の戻り値に`mediator`/`own`を追加**——呼び出し側が続けて
pickupを呼べるように。

**`/didcomm`ページ、「Identity method」セレクタ(did:peer / did:dht)を追加**。
did:dht側は当初、専用の使い捨てseedを使っていたが、**ユーザー要求により
実アカウントのdid:dht(既にログイン中の身元)を使う方式に変更(2026-07-16)**——
下記「_k1の永続化」参照。SendのRecipient欄は`resolveDidCommDoc`経由で
did:peer/did:dht両方を透過的に解決。

## `_k1`の永続化 + 実アカウント連動(2026-07-16)

**きっかけ**: `/didcomm`のdid:dht経路が使い捨てseedで新規did:dhtを発行
していたが、ユーザーが望んでいたのは「biset本体が既に持っているdid:dht
でのダイレクトメッセージ」——別人格ではなく、本人の既存識別子。

**`DidRecord`(`src/did/store.ts`)に`didCommPublicKey`/`didCommPrivateKey`
を追加(hex、optional)。** `root`/`nostr`鍵と全く同じパターンで
`src/did/index.ts`の`initDid`が導出・永続化する——**masterSeedは
IndexedDBに一切保存しない**という既存原則([[project_biset_did]])は
崩さず、root/nostr鍵と同様に「導出済みの結果だけ」を保存。

**lazy migration、既存の仕組みと完全に同型。** `initDid`が呼ばれる瞬間
(=パスワード入力でmasterSecretが手に入る瞬間)は「新規アカウント作成時」
だけでなく「毎回のログイン時」でもある(left-pane.tsの既存コメント:
「a password entry is exactly the moment masterSecret is available」)。
これを利用し、既存の`DidRecord`に`didCommPrivateKey`が無ければその場で
追加導出・再保存——DID.mdの他のlazy migrationと同じ形。新規に別の
UI/パスワード再入力フローを作る必要は一切なかった。

**`register.ts`のシグネチャを`masterSeed`→`didCommPrivateKey`(既に導出
済みの鍵そのもの)に変更。** masterSeedをこの層まで持ち回らない方が
安全(store.tsの「seedは一時利用のみで保存しない」という既存の衛生原則を、
関数呼び出しの経路全体でも一貫させた形)。

**`/didcomm`のdid:dht登録フロー、実アカウント版に書き換え**: ログイン中の
`sessions[0]`のemailから`getDidRecord`→`_k1`が無ければ「ログアウト→再
ログインしてください」とエラー表示→あれば、**まず本人の既に公開済みの
文書を解決**(空文書で上書きして既存のrelay/alsoKnownAsを消さないため)
→そこに`_k1`を足して`registerDidCommViaDht`。ゲートウェイ一覧も
「本人のrelay群 + 公開フォールバック」という既存の解決の慣習
(DID.md「account's own relays as gateways」)に合わせた。

**発見した抜け穴、修正済み: リカバリーフレーズ(24語)経由のログインは
`initDid`を通らない別経路だった。** `src/did/restore.ts`の
`restoreFromMnemonic`が`initDid`とは独立に`DidRecord`を自前構築・
`storeDidRecord`していたため、`initDid`側だけに足したlazy migrationが
効かなかった(ユーザーが実際にリカバリーフレーズで再ログインしても
`_k1`が生成されないと報告、実地で発覚)。`restore.ts`にも
`deriveDidCommKey`を追加——`restoreFromMnemonic`は毎回レコードを完全に
再構築して`put`で上書きする実装なので、migration分岐は不要(常に
フルで作り直すため、この修正だけで次回のリカバリーログインから
`_k1`が入る)。

**発見したバグ、修正済み: 実アカウント(既存のJMAPRelayサービス持ち)で
Register with mediatorすると400エラー。** 実際のメインアカウントで
再現・報告を受けた:
```
Unable deserialize DIDDoc from JsValue: unknown variant `JMAPRelay`,
expected `DIDCommMessaging` or `Other`
```
`didcomm-rust`の`did_doc.rs`を直接確認して原因特定(記憶からの推測では
ない)——`ServiceKind`は`#[serde(tag = "type", content = "serviceEndpoint")]`
の内部タグ付きenumで、`type`フィールドの値が**文字通り**`"DIDCommMessaging"`
か`"Other"`のどちらかである必要がある(`Other`は「未知の型を何でも
受け入れるcatch-all」ではなく、リテラル文字列`"Other"`との完全一致が
要る)。biset本体のdid:dht文書が持つ`JMAPRelay`サービスをそのまま
didcomm-nodeへ渡すと、この2択のどちらにも一致せず即座に失敗する。

**修正**: `~/didmediator/src/resolver.ts`の`toDidDoc`、および
`~/biset/src/did/didcomm/resolve.ts`の`didDhtToPeerDidDocShape`——両方の
service変換に`type === 'DIDCommMessaging'`フィルタを追加(didcomm-node
には他のservice情報は不要なので単純に除外)。JMAPRelayサービスを持つ
did:dht識別子でのmediator登録を再現テストし修正確認済み
(`scratch-k1-mediator-with-relay-check.mjs`)。

**did:dht↔did:dht、実物のPkarrゲートウェイ・`~/didmediator`相手に
send/pickupのフルフローをend-to-end検証済み**(`scratch-k1-live-dht-
fullflow.mjs`)——did:peerが一切登場しない、純粋なdid:dht経路のみで
Alice→mediator→Bobが完走。ビルド後`dist/index.html`は983KB(ほぼ変化なし、
wasm不使用のまま)。

**検証中に見つけた注意点(製品コードのバグではない)**: `src/did/resolver.ts`
の巻き戻り防止(`freshness.ts`)は`localStorage`(ブラウザ専用API)を使う——
Bunスクリプトから直接検証しようとすると`ReferenceError`になる。実ブラウザ
では問題なし。検証スクリプト側にだけ最小限のin-memory polyfillを足して
対応(製品コードは無変更)。人間による実ブラウザでのUI操作確認はまだ
(前回同様、playwrightがこの環境にインストールできないため)。

## Architecture sketch (proposed, not yet built)

```
client   src/did/didcomm.ts — X25519鍵派生(keys.ts拡張)、
                              inner message(authcrypt) + forward wrapping、
                              resolver.ts経由で相手の_k1公開鍵・Mediator
                              エンドポイント・routingKeysを解決
relay    jmapdidcomm(新規repo、Node.js/TypeScript実装、既存Go relay群とは別言語)
                              — `didcomm`/`didcomm-node`(sicpa-dlab製)ライブラリ採用
                              + Mediator機能(他人の鍵IDも中継可)
                              + Mediator Coordination Protocol(2.0)
                              + Pickup Protocol(3.0)
                              + relay自身のforward-wrapping鍵ペア
                              専用永続化(鍵ID→キュー、既存Go relay群のStoreは使わない)
document _k1(X25519 verification method)+ _s2(DIDCommMessaging service,
         serviceEndpoint = MediatorのURL, ac=/rk= 拡張フィールド)
```

## Phases

**順序の指針(決定): 自前のMediator(relay)を作るより先にクライアント側を
実装する。** クライアント側(鍵派生・JWE・forward wrapping)はMediatorの実装に
依存しない — 送り先が"biset自前のjmapdidcomm relay"である必要はなく、既存の
(他のDIDComm実装が運営する)公開Mediatorや、DIDComm公式test vectors(存在すれば)
を相手に検証できる。「標準準拠・相互運用性を最優先」という方針上も、biset実装
同士だけで閉じてテストするより、他の公開実装を相手に検証する方が真の相互運用性
の確認になる。自前relay(Mediator Coordination + Pickup Protocolのサーバー側)は
一から書く大きな作業であり、後回しにしてリスクを下げる。

1. **鍵 + document拡張** — `keys.ts` にX25519派生追加、`document.ts` に
   `_k1`/`_s2`(`ac=`/`rk=`拡張含む)。relay不要、既存resolve/publishの
   テストで検証可能。
2. **did:dht Additional Properties Registryへの提案** — `TBD54566975/did-dht`
   へ`ac=`/`rk=`のPRを提案(相互運用性を狙う本筋)。
3. **クライアント実装(送受信 + forward wrapping)** — `src/did/didcomm.ts`。
   自前relay不要。既存の公開Mediator実装やDIDCommライブラリ/test vectorsを
   相手に暗号フォーマット・forward wrappingの正しさを検証する。
4. **jmapdidcomm 最小実装(Node.js/TypeScript)** — Mediator Coordination
   Protocol + Pickup Protocol、鍵ID→キューの専用永続化、relay自身の鍵ペア
   管理。ここで初めてbiset自前のMediatorが必要になる(biset同士の実運用、
   自前運用の選択肢確保)。
5. **UI統合** — mail/APと同一Inboxへの統合表示。
6. *(optional, unscheduled)* Nostr NIP-17代替ルートの検証。

## 実地検証ログ(2026-07-15、Phase 3の一部を前倒しで実施)

Phase 3(クライアント実装の検証)を先取りし、scratchコードで2つの目標を検証した:

**目標1「biset ユーザー自身が直接postできるか」— 完全達成。**
`didcomm-node`ライブラリで生成したX25519鍵ペア2組(Alice/Bob)を使い、
authcrypt(`ECDH-1PU+A256KW`/`A256CBC-HS512` — 決定していたデフォルトと一致)
でメッセージを暗号化し、実際のローカルHTTPサーバーへPOST → 受信側で正しく
unpack・復号できることを確認した。

**目標2「第三者Mediatorを挟んでpostできるか」— 5つ目の実装で部分的に達成。**

| 実装 | 結果 |
|---|---|
| Vericomm(`vericomm.veritrust.vc`) | マーケティングページ上のプレースホルダー(`routingKeys`が説明用の架空文字列)、実データではなかった |
| Indicio公開Mediator | 実在・稼働しているが**DIDComm v1**(Aries旧仕様)専用、v2非対応 |
| RootsID mediator(`roots-id/didcomm-mediator`、Python) | s1にDocker+Cloudflare Quick Tunnelで実際に稼働させたが、**authcryptメッセージの送信者DID解決で必ずクラッシュする構造的バグ**を特定(`didcomm==0.3.2`の`DIDDoc`が`pydid`ベースの新APIに刷新されているのにコードが旧APIのまま) |
| Blocktrust Mediator(`bsandmann/blocktrust.Mediator`、.NET) | Azureホスト版も500エラーで機能せず。ローカルビルドは認証必須のprivate NuGetフィードで正規手順では回避不能 |
| **adorsys/didcomm-mediator-rs(Rust)** | **s1にDocker Compose(MongoDB+LocalStack)でデプロイして稼働。Mediator Coordination Protocol(mediate-request→mediate-grant、keylist-update)がauthcryptで完全成功。** forward配送(実メッセージのMongoDB保存)のみ500エラーで未解決 |

**adorsys/didcomm-mediator-rsでの発見(2026-07-15):**
- CI(GitHub Actions)が通っている、全プロトコル実装済みマーク付きの現役プロジェクト。ローカルビルド(cargo、Docker Compose)は特別な依存なしで成功。
- `localstack/localstack:latest`がいつの間にかPro版ライセンスを要求するようになっていた(プロジェクトのバグではなくLocalStack側の仕様変化) — `:3.8`等の旧バージョンタグに固定して回避。
- **did:peer method 2の実装依存の癖を複数発見**(仕様がkid命名やservice構造を厳密に規定していないため):
  - kidは「DID文字列内のセグメント出現順で`#key-1`,`#key-2`,...」という位置ベースの連番(RootsIDの"multibase値から`z`を除去"とは別の慣習 — did:peerのkid命名は完全に実装依存と再確認)。
  - authentication(V)セグメントが空だと拒否される(最低1つ必須)。
  - serviceのSセグメントは`{id, t, s: {uri, a, r}}`という、`s`が**ネストされたオブジェクト**の形式(RootsIDの"sが文字列"とは異なる)。
  - `service.uri`が別のDID文字列であれば、それを再帰的に解決する"chain resolution"を持つ(`is_did(service_endpoint)`) — Bobの公開DIDの`uri`にはMediator自身の**routing_did**(実URLではない)を指定し、そのrouting_didの解決先で初めて実URLに辿り着く、という2段構成が正しい設計だった。
  - DIDComm標準の`return_route: "all"`拡張ヘッダーが無いと、同一チャネルでの応答(HTTPレスポンスとしての即時返信)を拒否される。
  - Mediator Coordination Protocolの`keylist-update`(受信者が自分のkeyAgreement kidをMediatorの許可リストに明示登録する手続き)を経ないと、forwardメッセージの`next`フィールドがMediatorの許可リストと一致せず拒否される(`forward/src/handler.rs`の`checks()`関数、`UncoordinatedSender`)。

**結論**: Mediator Coordination Protocol(仕様上もっとも重要な"相互運用性の握手"部分)が、biset実装(TS/`didcomm-node`)と第三者実装(Rust/`didcomm-rust`)の間でauthcryptにより実際に成立することを実証できた——これは目標2の核心を満たす。forward配送(メッセージの実配達)の残バグは、サーバー側内部の実装(`message_repository.store`周り、原因未特定)に起因し、これ以上の追跡はadorsysへのissue報告候補として保留する。DIDComm v2エコシステム全体は依然としてPoC〜早期プロダクション品質が混在する状態(5実装中1つのみ完全機能)であり、実装間の相互運用性は仕様が厳密に規定しない部分(kid命名、service構造)で個別の調整が必要になる、という実情も明らかになった。

## Open design questions (unresolved — next pass)

- **Mediator接続用の一時did:peer生成 — 範囲を再確認、方針決定(2026-07-15)。**
  「Multi-method resolution」節の決定(biset自作Mediatorのresolverはdid:dht+
  did:peer両対応)により、biset↔biset間の通信ではこの迂回が不要——通常運用の
  識別子は常に`did:dht` + `_k1`(既存決定のまま)。did:peerは、bisetユーザーが
  did:dhtを解決できない第三者Mediator(RootsID/adorsys等)を使う場合の**フォール
  バックのみ**に限定して確定。

  一時「相手ごとに毎回did:peerを生成する」設計をbiset自身の恒常的なDIDComm
  ペルソナとして採用しかけたが却下——bisetは既にDNS経由で`did:dht`を相手に
  公開する設計であり、相手は最初からあなたの本当の識別子を知っている以上、
  「相手ごとに別IDで名寄せ防止」という利点自体bisetの脅威モデル上ほぼ効かない
  (ユーザー合意の上で撤回)。**上記フォールバックが実際に必要になった場合に
  限り、その外部Mediator関係ごとにdid:peerを新規生成する**という細部だけ活かす
  ——恒常的識別子の話とは別レイヤー。

- **Mediator自身の鍵ペアの生成・管理方法。** relay起動時に生成して永続化
  するのか、biset全体の鍵体系(masterSeed由来)とは無関係な純粋なサーバー鍵
  として扱うのか。運用者(relay operator)がローテーションする余地を持たせる
  べきかも未定 — ユーザー個人の鍵とは異なり、これはrotation-lessである
  必然性がない(recipientの秘密性はinner messageの`_k1`側で担保されるため)。
- **Mediator利用登録のタイミング/UX。** アカウント作成時に自動で(自分の
  relayを自分のMediatorとして、または他relayを)登録するのか、明示的な
  ユーザー操作にするのか。
- **クライアントUI統合の詳細。** mail/APと同一Inboxへの統合表示自体は決定
  済みだが、具体的な`ui/thread.ts`/`ui/left-pane.ts`への組み込み方法は未着手。

## 実装進捗: `didmediator`(TS)骨格が完成、フルフロー動作確認済み(2026-07-15)

`~/didmediator/`(独立リポジトリ、未コミット)に、Coordination Protocol +
Routing(forward) + Pickup Protocolを実装し、**Alice→自作didmediator→Bobの
フルフローがend-to-endで動作することを確認した**——前回adorsys(Rust)実装で
未解決のまま残っていた「forward配送」まで含めて完走。

**構成:**
```
src/identity.ts         — did:peer:2 encode/decode、鍵生成(adorsysで検証済みの
                          kid規則 "#key-N"、serviceの{id,t,s:{uri,a,r}}構造を踏襲)
src/mediatorIdentity.ts — Mediator自身の鍵ペアをファイル永続化(data/mediator-identity.json)、
                          再起動してもDIDが変わらない
src/resolver.ts         — did:peer解決を実装。did:dht解決は未実装、呼ばれたら
                          明示的にthrowするTODOスタブ(黙って失敗させない設計)
src/secrets.ts          — SecretsResolverラッパー
src/queue.ts            — 鍵ID→キュー(インメモリ、v1決定通り)
src/connections.ts       — Mediator Coordination Protocolの許可リスト管理
src/didUrl.ts           — DID/kid正規化ヘルパー(下記の発見に対応するため追加)
src/server.ts           — HTTPハンドラ本体(mediate-request/grant, keylist-update,
                          forward, status-request, delivery-request)
src/index.ts            — エントリポイント
```

**実装中に発見した`didcomm-node`の型定義とランタイム挙動の乖離(2点、
今後この分野で作業する際の注意点として重要):**
1. `Message.try_parse_forward()`は`.d.ts`上`ParsedForward`クラス
   (`.as_value()`で値を取り出す設計)だが、**実際のランタイムは既に展開済みの
   プレーンオブジェクト`{next, forwarded_msg}`を返す**。`.as_value()`を呼ぶと
   `TypeError: as_value is not a function`になる。
2. `next`フィールドは**fragment(kidのsuffix)なしの裸のDID**になる——
   forward wrappingがrecipientの特定のkeyAgreement kidを解決して暗号化した
   にもかかわらず、`try_parse_forward()`が返す`next`はDID全体のみ。
   `keylist-update`で登録した完全なkid文字列とは一致しないため、**kidの
   fragment有無を問わずDID単位に正規化してから比較・キー管理する
   (`didUrl.ts`の`stripFragment`)必要がある** — これをせず素朴に文字列比較
   すると、正しくkeylist登録していても"uncoordinated recipient"扱いになる。

**未実装(次のステップ):**
- did:dht resolver対応(既存`src/did/resolver.ts`のDHT問い合わせロジックとの
  統合) — 「Multi-method resolution」節の決定はまだ実装されていない。
- Mediator利用登録のUI/UX、クライアント側統合(`src/did/didcomm.ts`相当)。
- git初回コミット(意図的に保留中)。

## 実装進捗: biset本体側のDIDComm送受信、実機(自作didmediator)でend-to-end動作確認済み(2026-07-15)

`~/biset/src/did/`にdid:peerフォールバック経路のクライアントコードを追加。
「相手ごとにdid:peer」という当初案は却下し(名寄せ防止の効能がbisetの脅威
モデル上薄いと判断、[[project_biset_didcomm]]参照)、既存決定通り
`did:dht`+`_k1`が本流のまま、did:peerは**第三者/自作mediatorとの接続時
だけのフォールバック**という位置付けを維持。

**構成:**
```
src/did/peer.ts              — did:peer:2 encode/decode/generate(~/didmediatorから移植)
src/did/didcomm/crypto.ts    — JWE構築(認証暗号=ECDH-1PU+A256KW、匿名暗号=
                                ECDH-ES+A256KW、共にA256CBC-HS512)、純TS・wasm不使用
src/did/didcomm/message.ts   — DIDCommプレーンテキストのenvelope共通ヘルパー
src/did/didcomm/coordinate.ts — Mediator Coordination Protocol(mediate-request/
                                grant, keylist-update)
src/did/didcomm/send.ts      — Forward wrapping + 送信
src/did/didcomm/pickup.ts    — Pickup Protocol(status-request/delivery-request)
src/ui/didcomm-debug.ts      — 最小デバッグUI(`/didcomm`ページ、inbox統合なし)
```

**wasm不使用の理由(技術スタック検証、実装前に確認):** `didcomm`/`didcomm-node`
(sicpa-dlab製npm)はどちらもRust実装のwasm-bindgenビルドで、ブラウザ向け
`didcomm`パッケージも`bun build`に通すとwasm本体(0.89MB)が別ファイルとして
切り出され、実行時に`fetch`される構造だった——bisetの「単一HTMLファイル、
`file://`で動く」という中核設計(ARC.md)と衝突するため不採用。代わりに
`@noble/curves`(既存依存)+`@noble/ciphers`(追加)でJWE構築を自前実装。
ConcatKDF/ECDH-1PU/ECDH-ESの実装はhyperledger/aries-askarのRustソース
(didcomm-rustが実際に使うcrate)を直接参照して構築し、記憶からの再構成は
していない——draft-madden-jose-ecdh-1pu-04のAppendix A/B含む複数のRFC/
参照実装テストベクトルをバイト単位で一致確認済み
(`scratch-didcomm-crypto-vectors.mjs`)。

**相互運用性検証(実物の`didcomm-node`ライブラリとのラウンドトリップ):**
authcrypt/anoncrypt双方向、`scratch-didcomm-crypto-interop.mjs`で確認——
pure-TS実装とdidcomm-node実装が完全にwire互換。

**End-to-end検証(実際に動いている`~/didmediator`相手、`scratch-didcomm-
e2e-check.mjs`):** Alice(biset新規did:peer)→自作didmediator→Bob(biset
新規did:peer、事前にmediate-request+keylist-update登録済み)のフルフローが、
biset側の純TSクライアントコードのみで完走。ビルド後の`dist/index.html`は
979KB(wasm不使用のため既存サイズからほぼ変化なし)。

**未検証:** ブラウザでの実UI動作——このセッションのplaywright(Chrome)は
環境上インストールできず(`npx playwright install chrome`がsudo要求で失敗)、
`/didcomm`ページの実ブラウザ操作は確認できていない。`grep`でビルド済み
`dist/index.html`に新コードが含まれていることは確認済み。人間が`file://`で
`dist/index.html`を開き、Mediator URLに`http://localhost:4100`(起動中の
`~/didmediator`)を入れて実地確認する必要がある。

**人間による実ブラウザでの最終確認、成功(2026-07-15)。** `file://`で開いた
`dist/index.html`の`/didcomm`ページから実際に「Register with mediator」を
実行し、`~/didmediator`への登録(mediate-request/grant + keylist-update)に
成功——返ってきたdid:peer文字列をデコードし、`service.uri`が
`http://localhost:4100`、`routing_keys`がmediator自身のkeyAgreement kidを
正しく指していることを確認。続けてスクリプト(Alice役)からそのDID宛に
送信し、人間がブラウザで「Check for messages」を押して**実際に復号済みの
平文メッセージが画面に表示される**ことを目視確認——biset本体側の
送受信・自作mediator経由の中継まで含め、当初の2目標(直接post/第三者
mediator経由post)がスクリプトだけでなく実ブラウザ・実人間操作で完走した。**続けてブラウザの送信方向も確認**——
mediator登録済みの受信専用「Charlie」identityをスクリプトで用意し、その
DIDを人間が`/didcomm`のRecipient欄に貼って送信、Charlie側(スクリプト)の
pickupで正しく復号・到達を確認(`from`が人間のブラウザのDIDと一致)。
これで送受信の両方向が実ブラウザ操作で完全に実証された。

**「mediatorなしでも送れる?」への回答: 送れる(検証済み)、ただし受信側が
実際にリスンしていることが条件。** `sendDidComm`は元々、相手の
`service.serviceEndpoint.routing_keys`が空ならforward wrappingせず
`service.uri`へ直接POSTする分岐を持っていた——スコープ外機能ではなく、
最初から実装済みの経路。使い捨てのHTTPリスナー(実ブラウザは自分から
listenできないので、その代わり)を1つ立てて検証(`scratch-direct-no-
mediator-check.mjs`)、mediator抜きの直接送受信を確認。

**この検証中に発見したバグ、修正済み: `identityFromKeys`が`service`引数を
in-memory `doc`に反映していなかった。** `encodePeerDid2`はDID**文字列**には
serviceを正しく埋め込むが、同時に構築される`doc.service`は常に`[]`固定
だった——これまでの全検証(coordinate/e2e/ブラウザ)は`decodePeerDid2(did)`
で文字列から再デコードした`doc`を使っていたため症状が隠れていたが、
`identity.doc`を直接使う経路(今回のdirect-send検証で初めて踏んだ)では
serviceが消え、"recipient DID doc has no DIDCommMessaging service"で
即座に落ちた。`peer.ts`の`identityFromKeys`を修正——`service`引数から
正しく`doc.service`を組み立てるようにした。既存の全チェック(coordinate/
e2e/direct)で再検証、回帰なし。フルビルド(`bun run build`)して
`dist/index.html`にも反映済み。

**発見したバグ(人間の実地確認で発覚): `~/didmediator`にCORS未対応、修正済み。**
これまでの検証(scratch-*.mjsスクリプト)はすべてNode/Bunランタイムから直接
`fetch`しており、ブラウザのCORS制約を一切受けていなかった——biset本体が
`file://`(`Origin: null`)から実際に`fetch`して初めて
`Access-Control-Allow-Origin`ヘッダー欠落が表面化した(`net::ERR_FAILED`、
サーバー自体は200を返していた)。**スクリプトでの検証がブラウザでの動作を
保証しないことを示す実例** — `server.ts`に`Access-Control-Allow-Origin: *`
(`null`/`file://`originにも一致)+ OPTIONSプリフライト応答を追加して解決、
既存の全scratchチェックで再検証済み。tailscale funnel等での公開は無関係
(到達性の問題ではなくCORSヘッダー欠落そのものが原因なので、公開URLに
しても同じ理由でブロックされていたはず)。

## 実アカウントのDID文書を破壊した設計ミス3件、修正済み(2026-07-16)

実ユーザー(`y@biset.md`、`did:dht:6oien8gc…`)の`/didcomm`登録で
`DNS packet 1257B exceeds BEP44 1000B limit`が発生。調査のため実際の
公開済み文書を解決したところ、**mail/APのJMAPRelayサービスと
`alsoKnownAs`が消え、代わりに同一のDIDCommMessagingサービスが2つ重複**
という壊れた状態になっていた。原因は`/didcomm`の登録実装(私が書いた
もの)にあった、独立した3つの設計ミス:

**(1) resolve失敗時に空文書へフォールバックし、それをpublishしていた。**
`resolveDidDht(...) ?? buildBisetDocument(did, key, [], [])`——一時的な
ネットワーク不調でresolveが`null`を返しただけで、「relayが1つも無い
identity」という文書を本物として署名・公開してしまう。実アカウントの
relay情報が失われたのはこれが原因。

**(2) DIDCommMessagingサービスを置き換えではなく追加していた。**
再試行・別デバイス・別mediatorのたびに重複が積み上がる。1件あたり
約330バイト(mediatorのdid:peer routing kidだけで236文字)なので、
2〜3回で1000バイト上限を突破し、以後**一切publishできなくなる**——
今回の1257Bエラーの直接原因。

**(3) [最も危険] `publishOwnDids()`が`_k1`とDIDCommサービスを含まない
文書で毎回上書きしていた。** `publish.ts`の自動republishは**アプリ起動
のたびに走る**(`main.ts`)。当時の`buildOwnDocument`はDIDComm層を知らな
かったため、**mediator登録に成功しても、次にbisetを開いた瞬間に登録が
消える**——UIで検証していたら「昨日は動いたのに今日は動かない」という
形で必ず遭遇したはずの、機能そのものを成立させない致命傷。

**修正(共通化、[[feedback_unify_common_logic]]):** `publish.ts`が既に
持っていた**「公開済み文書を読んで追記するのではなく、ライブの
セッション状態から毎回組み立て直す」**という正しいパターンを唯一の
builderとして`buildOwnDocument`に抽出・export。`/didcomm`の登録も
これを起点にするよう書き換え(resolve-and-append自体を廃止したので
(1)は構造的に起きえない)。`register.ts`はDIDCommMessagingを
filter+追加=置き換えに変更(2)。`DidRecord`に
`didCommMediatorUrl`/`didCommRoutingKey`を永続化し、
`buildOwnDocument`が`_k1`とDIDCommサービスを常に含めるようにした(3)
——鍵は導出可能だがmediator登録は導出不可能な状態なので、ローカルに
persistする以外に「起動時のrebuildが登録を消さない」保証が作れない。

**検証**: 実アカウントと同型の文書(mail+AP relay 2本)で、
_k1+DIDCommサービス込み**819バイト**(1000B上限内)を確認、
**2回連続登録しても819バイトのまま・サービス重複なし・relay保持**を
`scratch-k1-idempotent-check.mjs`で自動検証。did:peer/did:dht両経路の
既存end-to-endチェックも回帰なし。

**教訓**: この3件はいずれも**スクリプト検証では発見不可能**だった——
(1)はresolve失敗という例外時のみ、(3)は「登録→アプリ再起動→再確認」
という時間をまたぐ操作でのみ露見する。実ユーザーの実データで初めて
表面化した。CORSの件と同じく、**scratchスクリプトの成功はブラウザでの
実利用を保証しない**という実例がまた1つ増えた形。

**復旧確認済み(実ユーザーの実アカウント)**: 修正後に再度
「Register with mediator」を実行してもらった結果、`alsoKnownAs`・
mail/AP両方のJMAPRelayサービス・表示名`name`がすべて復活し、
DIDCommMessagingサービスはちょうど1件(重複なし)。そのうえで実際に
`did:dht:6oien8gc…` から送受信が成功。

**同時に見つかった小さな不備、修正済み**: `/account`の公開DID文書
プレビュー(`left-pane.ts`)が`identityKey`だけを明示的にhex整形して
おり(コメントで「Uint8Arrayは`{"0":244,…}`になってしまうので」と
理由まで書いてある)、後から追加した`keyAgreementKey`が対象から
漏れていた——同じ文書内で一方はhex文字列、他方は32個の数値キーを持つ
オブジェクト、という不整合な表示になっていた。**当初これを
「`JSON.stringify`の仕様なので仕方ない」と回答したのは誤り**で、
コードベースには既にこの問題への対処が存在していた(それを新フィールドへ
広げ忘れていただけ)。両方をhex整形するよう共通化して修正。

## Non-goals (v1)

- Nostr NIP-17実装(将来の代替候補として保留するのみ)。
- **Perfect forward secrecy / X3DH / session ratcheting鍵管理**(検討の上で明示的に
  却下 — 上記「Rotation policy」節参照。SPK/OPKによるFSは「seed一本で全復元」
  というbiset全体の鍵設計原則と両立しないため、原則側を優先した)。機密性の高い
  やり取りはAP/MLS(FS+PCSあり)に誘導する用途制限で代替する。
- **biset自身が複数のDID method(did:webvh等)を持つこと。** 「Multi-method
  resolution」節参照 — 分裂を避けるため、biset自身のidentifierは`did:dht`
  一本を堅持。相手のDIDを読む側のresolverが複数method対応になることとは
  独立(将来検討の余地あり)。
- グループメッセージング(MLSがAP向けに既に担当領域、役割の重複を避ける)。
- **`from_prior`(DIDComm v2.1のDID rotation機構)。** 仕様はDID変更時の関係遷移を
  `from_prior` JWTヘッダで扱うが、bisetのrootは意図的にrotation-less(`DID.md`)
  なのでDIDが変わる状況自体が発生しない。実装不要。
