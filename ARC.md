# Biset アーキテクチャ

> MLS の vendored fork（ciphersuite、UpdatePath fix、vendor diff の一覧）については `src/protocol/mls/VENDOR.md` と本書§13を参照する。かつて存在した `ARC-MLS.md` は Coordinator 完全撤去（2026-09-03、commit `57ffa67`）以前の調査で、中心的な二節が存在しないサブシステムを説明していたため 2026-09-05 に削除した。Self Group/Vault の現行の配送経路は本書§6・§9で説明する biset-mimi Self Vault である。

> 調査基準日: 2026-09-06（Asia/Tokyo）
> 調査対象: `~/biset` の commit `dc1cd84`。前回基準からの最重要変更は四つ——
> **Anchor の完全削除**、**native login（seed 由来 identity 層）の削除**、
> **到達不能コードの削除**（R2）、そして **`src/` の再構成**（R3/R4）。
> 現在のトップレベルは **client / server / protocol** の三つで、`shared/` も `vendor/` も存在しない。
> 構成と各ファイルの責務は **§21** にある。
> 状態: 現行コードを正とした実装アーキテクチャ。将来案は明示的に区別する。
>
> **⚠️ メールは実装されていない。** native login と一緒に削除され、再実装には did.md 側の
> mediator が必要（§11、`tasks/W3-wallet-mail-design-proposal.md`）。
> DIDComm による 1:1・グループチャット・複数端末同期・checkpoint は動作する。
>
> **実機での起動確認は取れていない。** typecheck / test / build はすべて通っているが、
> それは「起動して使える」ことの証明ではない（§20-2）。
>
> **⚠️ メールは実装されていない。** native login と一緒に削除され、再実装には did.md 側の
> mediator が必要（§11、`tasks/W3-wallet-mail-design-proposal.md`）。
> DIDComm による 1:1・グループチャット・複数端末同期・checkpoint は動作する。
>
> **実機での起動確認は取れていない。** typecheck / test / build はすべて通っているが、
> それは「起動して使える」ことの証明ではない（§20-2）。
>
> **⚠️ この時点のコードは機能的に不完全である。** 「先に削除、機能は後追い」という方針で native login を
> 削除したため、メール・グループチャット・送信 outbox・checkpoint が失われ、
> **どの端末も自分から関係を開始できない**（§3.1）。復旧作業は `tasks/W3-wallet-feature-gaps.md`。
> 本書は「今のコードがどうなっているか」を書いたものであり、「あるべき姿」ではない。

## 1. この文書の目的

Biset は、メールと DIDComm のデータを利用者の端末側で長期保管し、サーバーを恒久的なメールボックスやメッセージ履歴にしない通信クライアントである。本書は、現行コードの構成、信頼境界、暗号鍵、状態遷移、配送・復旧経路、運用方法、および未完成部分を一つの資料にまとめる。

リポジトリ直下の `PLAN.md` は現在 did.md Wallet login の設計だけを扱う（旧「Biset 再構築ロードマップ」は 2026-09-05 に置き換えられ、`PLANIMPLEMENTATION.md` も同日削除された——両者の役割は本書が引き継いだ）。簡素化作業の経緯と未解決issueは `PLAN-simplify.md` にある。本書はそれらを参考にしつつ、実際に `src/` と `test/` に存在し、呼び出し経路へ接続されているものを「実装済み」と判定する。クラスやテストだけが存在し、ブラウザの起動経路へ未接続のものは「部品実装済み」とする。

**この節の背景（2026-09-03〜04の変化）**: 前回調査（commit `11f0a62`）時点では `biset-core`（`src/core/`）がAnchor・Mediator・Vault・biset-mimiと並ぶ五番目の主要コンポーネントとして存在し、SMTP受信、outbound mail relay、did:webvh/routing.json公開文書ホスティング、device rosterに基づくmail ingress-pull認可とlegacy Vault delivery、legacy DIDComm ingress fallbackを一手に担っていた。commit `99e08c0`（2026-09-03「core: remove src/core/ entirely, retired 2026-09-03」）で`src/core/`はディレクトリごと削除され、以後のcommitでその責務は次のように再配分された。

- SMTP受信・outbound mail relay → `src/mediator/mail-plugin/`（standalone mediatorの deployment variant、§3・§11）
- did:webvh/routing.json公開文書ホスティング → core撤去後は Anchor が唯一の host だったが、**その Anchor も 2026-09-05 に削除された**。現在は外部の did.md がホストする（§3・§13.1）
- device rosterに基づくmail ingress-pull認可、legacy Vault delivery、legacy DIDComm ingress fallback → **後継なしに消滅**。roster機構自体（`rosterBackedVaultDeliveryAuthorizer`、`ensureMimiCoreRoster`、`src/mls/self-group.ts`（削除済み）のroster projection関連コード）も削除された。mail認可はdid:webvh update keyの署名検証へ置き換わり（§11.2）、legacy Vault delivery/DIDComm ingressはMIMI Self Vault/standalone mediatorへの移行が既に完了していたため、コード上は「production configが指さないfallback」として一部残っているだけである（§9.3、§12.1、§12.5）。

## 2. 設計原則と非目標

### 2.1 原則

- 長期正本は各 endpoint の暗号化 Vault であり、mediator や biset-mimi ではない。Coordinatorという別プロセスは存在しない——複数端末間の Vault 同期は biset-mimi の Self Vault（後述、§3・§9）が担う。
- Standalone mediator（および mail-plugin deployment variant）が保持するのは、DIDComm の blind queue と SMTP 境界の metadata に限る。Vault plaintext、SegmentKey、MLS exporter secret、OpenPGP private key は知る必要がない。**biset-core が担っていた device roster・TTL/quota 付き ingress バッファ・legacy Vault delivery は 2026-09-03 の core 撤去で後継なく消滅した**（§9.1・§9.3）。
- UI と保存層の間には JMAP 形のローカル API を置き、暗号方式を UI へ漏らさない。
- MLS は user-to-user のチャット本文暗号化には使わない（それは DIDComm の役割）。一方、同じ identity の信頼済み端末集合を表す Self/Vault MLS group は、Vault mutation を運ぶ暗号文チャンクそのものを MLS PrivateMessage/PublicMessage として運ぶ——「MLSはVEK導出境界だけに使う」という旧原則は、biset-mimi 移行後は成り立たない。VEK（Vault Epoch Key）は依然としてこの MLS exporter secret から導出し、SegmentKey の epoch-wrap 境界として使う。
- 外部 ingress を ACK するのは、端末で検証・暗号化・永続化が完了した後だけとする。mail-plugin bridge の inbound mail は「ACK」という独立概念を持たず、DIDComm Forward としてmediator queueへ積まれた時点で標準の DIDComm 受信パイプラインに合流する（§9.1・§12.5）。
- 復旧に必要な履歴本体を biset のサーバーに置かない。**復旧経路は biset-mimi Self Vault の checkpoint 一本である**。
  かつて設計原則が挙げていた「信頼済み peer」と「利用者管理の暗号化 archive」は、
  配線を持たないまま 2026-09-05 に削除された（R2）。
  checkpoint の KEK は MLS self-group の VEK であり、**現行 epoch でしか導出できない**——
  したがって新デバイスを迎えるには既存デバイスが1台オンラインである必要があり、
  全デバイスを失った場合の復旧手段は無い。これは意図的に受け入れた代償である（§9）。
- did:webvh の SCID を identity の安定した識別子として扱い、ドメイン移転で Self Vault や配送列を分断しない。
- **identity の発行とホスティングは biset の責務ではない**（2026-09-05〜）。外部の did IdP（did.md）が担い、
  biset は解決するクライアントに徹する。biset は公開文書を書かない。

### 2.2 現行スコープ外または未完成

- MLS ベースの複数人グループチャット（旧 Conversation Group / biset-mls-ds）。2026-09-03 にソース一式（`src/mls-ds/`、`src/mls/conversation-group*.ts`、`src/protocol/conversation-mls-ds*.ts`）が削除され、DIDComm group chat（§3.1、§12.6）に置き換わった。biset-mimi の `normal`/`anon` モード（複数 OIDC owner を跨ぐ一般グループチャット hub）は稼働しているが、client からの呼び出し経路がなく、この意味でのグループチャットは依然として実装されていない。
- ActivityPub の実動 adapter。protocol enum に値は残るが、adapter、UI、配送経路はない。
- サーバー側の mailbox、全文検索、履歴 API、添付 archive。
- 完全な JMAP server。ローカル gateway は UI が必要とする最小メソッドだけを実装する。
- OpenPGP を用いた実際のメール送信時暗号化と UI での受信復号。
- Web Push。Service Worker は install/activate のみで、通知・バックグラウンド同期を行わない。
- 端末/鍵管理の統合。self-group.ts（Coordinator撤去で大半削除、core撤去でroster projection専用コードも消滅）・MIMI room membership・Sign Key rotation は、同じ「端末を追加/削除する」操作に対する別々のコードパスのままであり、Coordinator撤去で Sign rotation の MIMI 版代替が消えたまま。§20 参照。

## 3. システム全体像

> **2026-09-05 の大きな変更**: biset 自前のログイン（BIP39 seed から identity を作り、Anchor が OIDC provider として
> 認証する方式）を廃止し、外部の did IdP（**did.md**）ログインへ一本化した。**Anchor はリポジトリから削除された**
> （commit `74864ff` `c26db16`）。seed 由来の identity 層も削除済み（`dd5a0cd` `71336b9` `7357830`）。
> この削除は「先に消して機能は後追い」という方針で行われたため、**現在いくつかの機能が失われた状態にある**（§19）。

```text
┌──────────────────────── Biset Client（ブラウザ） ────────────────────────┐
│ UI ─ Projection                                                          │
│                  │                                                       │
│        IndexedDB Vault（暗号文 object + 署名 event + key wrap）          │
│                  │                                                       │
│  did:webvh 解決 / did.md Wallet セッション /                             │
│  Self Vault MLS group / DIDComm 1:1                                     │
└──┬────────────────────┬─────────────────────────┬───────────────────────┘
   │OAuth (DPoP-bound)  │DIDComm v2 encrypted HTTP │MIMI Vault sync wire
   │＋ did:webvh 解決   │（受信はすべてこの経路）  │（DIDComm ではない、
   │（読むだけ。biset は│                          │ biset-mimi 独自 protocol。
   │ 公開文書を書かない）│                         │ self モードだけに向く）
   ▼                    ▼                          ▼
┌─ did.md（外部）──┐┌─ Mediator（"A"素のDIDComm／"B"mail-plugin同梱）┐┌─ biset-mimi (self = Vault) ─┐
│identity provider ││"A" = src/server/mediator/index.ts                 ││このidentityのSelf Vault用。 │
│did:webvh の発行・ ││  did:peer identity、SQLite queue、             ││main.ts から実配線済み——    │
│ホスティング      ││  Coordinate/Pickup/relay-hop                   ││Vault mutation を運ぶ MLS    │
│OAuth 認可        ││"B" = 上記 + SMTP:25 listener(inbound bridge) + ││application message チャネル │
│（biset は        ││  submission HTTP:8792(outbound、独立Bun.serve) ││                             │
│ クライアント）   ││  本番はBが稼働中（両者は同じsqliteを           ││                             │
│                  ││  奪い合う排他ターゲット）                      ││                             │
└──────────────────┘└────────────────────────────────────────────────┘└─────────────────────────────┘
                          ▲ SMTP/DNS MXは"B"のSMTP listenerが直接受ける
                          │
                    外部メールシステム

┌─ biset-mimi (normal/anon = hub) ─┐
│複数 owner を跨ぐ一般 group chat hub。client からの呼び出し経路なし（サーバーとして稼働のみ）│
└──────────────────────────────────┘
```

Biset が**自分で運用する**主要コンポーネントは三つである（Anchor の削除により、四つから一つ減った）。
identity provider は外部（did.md）に移ったため、もはや biset の構成要素ではない。

1. **Mediator** — DIDCommの一時配送（store-and-forward）。`src/server/mediator/index.ts`を入口とする"A"（素のmediator）と、
   それに加えてSMTP inbound listener + outbound submission HTTPを同梱する`src/server/mediator/mail-plugin/index.ts`入口の"B"の、
   二つのdeployment variantがある。本番は"B"（mail-plugin同梱）が稼働中（`mediator.biset.md`）——
   同じ`biset-didcomm-mediator.service`とSQLiteを二つのバイナリが奪い合う排他関係であり、
   deploy.shの`didcomm-mediator`/`mail-plugin`ターゲットはどちらか一方だけをデプロイする（§17.3）。永続化はSQLite（`sqlite-store.ts`）。
2. **Vault** — `src/client/app/main.ts`内で動くClient local storage。暗号化長期正本、projection、秘密、server間bindingを保持する。
3. **biset-mimi**（`src/server/mimi/index.ts`）— IETF `draft-ietf-mimi-protocol`に準拠したMLS Delivery Service。
   設計・実装状況の詳細な正本は[PLAN_biset-mimi-server.md](PLAN_biset-mimi-server.md)。
   `normal`/`anon`/`self`の3プロセスとして本番稼働中。**`self`モードは`main.ts`から実配線されており、
   単一identityの複数端末間Vault同期（Self Vault）の本番バックエンドである**。
   一方`normal`/`anon`モード（一般group chat hub）は`main.ts`からの呼び出し経路がなく、「部品実装済み」のままである。

**did.md** は biset が運用するものではなく、依存する外部サービスである。identity（did:webvh）の発行とホスティング、
および OAuth による認可を担う。biset 側は `src/wallet/`（`did-md-oauth.ts` / `did-md-store.ts`）でそのクライアントとして振る舞い、
**公開文書を書き込むことはない**——読んで解決するだけである（`src/identity/webvh/` の resolver 系）。

`src/protocol/protocol/`は各境界が共有するwire schema、canonical encoding、ID、署名対象byte列を定義する。
browser、mediator、mail-plugin、mimiは別々のTypeScript設定（`tsconfig.*.json`、4設定——
旧`tsconfig.core.json`と`tsconfig.anchor.json`はいずれもディレクトリごと削除済み）で型検査する。

### 3.1 メッセージング機構の現況

「AさんからBさんにメッセージを届ける／複数端末で同期する」という問題に対する機構は、native login 削除の前後で大きく変わった。

| 機構 | 用途 | 状態（2026-09-05） |
|---|---|---|
| DIDComm 1:1 chat | ペアワイズ・共有鍵なし | **部分的に稼働**。受信・応答はできるが、**自分から関係を開始できない**（下記） |
| MIMI Self Vault | 単一identityの複数端末同期（対人チャットではない） | 稼働中（§9） |
| Mail (SMTP/JMAP) | 従来のメール | **失われた**。送信・受信とも配線が削除された。`src/mail/` はモジュールとして残るがテストからしか到達されない |
| DIDComm group chat | フルメッシュ・ペアワイズfan-out、MLS無し | **失われた**。`src/client/didcomm/group-chat.ts` は残るが呼び出し元がない |

> **現在の最重要の欠落**: `initiateRelationship`（`didcomm/send-message.ts`）の本番呼び出し元が**ゼロ**である。
> `sendRelationshipAccept` は生きているため INIT に応答することはできるが、**どの端末も自分から関係を開始できない**。
> 全アカウントが did.md Wallet アカウントである現在、**誰も誰とも関係を確立できない**状態にある。
> 復旧作業は `tasks/W3-wallet-feature-gaps.md` の①。

- **DIDComm 1:1**（Mediator経由）は1:1のダイレクトメッセージ専用。§12.2〜12.5で詳述。
- **MIMI Self Vault**（biset-mimi `self`モード）はユーザー対ユーザーのチャットではなく、
  一つのidentityの複数端末間でVault mutationを暗号化配送する専用チャネルである。
  Self VaultのMLS groupは(a)そのidentityの端末集合を表すroster、(b)VEK導出境界、
  (c)Vault mutationチャンクそのものを運ぶapplication messageチャネル、の三役を兼ねる。§6・§9で詳述する。

### 3.2 認証（did.md OAuth）

かつて Anchor が担っていた二層認証（外側 OIDC Authorization Code + PKCE、内側 OpenID4VP Verifier、
Biset 発行の holder-bound Login Credential）は**すべて削除された**。現在の認証は外部 did IdP への OAuth である。

```text
              Biset Client（ブラウザ）
                     │ OAuth Authorization Code
                     │（/wallet/callback へ戻る）
                     ▼
                  did.md Wallet
                     │ device capability を承認
                     ▼
        DPoP-bound device session（biset 側に保存）
```

利用者は did.md Wallet で biset の端末を一度承認する。biset はその device session を
`src/client/identity/wallet/did-md-store.ts` に暗号化して保持し、以後 Wallet を再度開かずにセッションを復元できる。
biset は did.md の controller 鍵を一切保持しない。

**mediator との関係（設計方針、未実装）**: メールアドレスの採番と送信署名鍵は biset ではなく **mediator の責務**として
設計しなおす方針が決まっている（2026-09-05）。did.md が専用の mediator を運用し、利用者は Wallet ログイン時に
そこへ登録する。特定 mediator の使用許可を capability として付与する形を検討中。
これに伴い `mailFromForIdentity`（`src/protocol/webvh/identifier.ts`）の
「DID のドメインが biset の apex 配下であること」という制約は将来外れる。

## 4. 信頼境界

### 4.1 Client が信頼して保持するもの

- identity の master seed、Root Key、端末 MLS private state（Self Vault groupの自device leaf含む）
- Vault の暗号文、署名 event、SegmentKey と wrap、JMAP projection
- identity 共有の DIDComm / OpenPGP 秘密 credential
- relationship ごとの非公開 DIDComm credential（1:1・group chat 共通）
- 復号済み本文と鍵を扱う実行時メモリ

Client は plaintext の最終処理点であり、侵害された client から既取得の秘密を取り戻すことはできない。MLS revoke（Self Vault の Remove commit、§6.2）は将来 epoch へのアクセスを止めるが、過去にコピー済みの DIDComm/OpenPGP 共有秘密や平文を消去する機能ではない。

### 4.2 did.md を信頼する範囲

**2026-09-05 に Anchor が削除され、この節は完全に置き換わった。** かつて Anchor が担っていた
did:webvh/did:web mirror/routing.json の公開文書ホスティングと OIDC/OpenID4VP 認証は、
いずれも biset の構成要素ではなくなった。

did.md は identity の発行元かつホスト、および OAuth の認可者である。biset は**そのクライアント**にすぎない。
did.md が知り得るのは、公開文書そのもの（元々公開情報）と、OAuth の認可・device capability に伴う metadata である。
Vault plaintext、SegmentKey、MLS exporter secret、OpenPGP private key を知る必要はない——この性質は Anchor の頃と変わらない。

biset 側が did.md に対して持つ秘密は device session（`src/client/identity/wallet/did-md-store.ts` に暗号化保存）だけであり、
**did.md の controller 鍵を biset が保持することはない**。利用者は did.md Wallet 側から当該 capability をいつでも失効できる。

### 4.3 Standalone mediator（"A"/"B"共通）を信頼する範囲

Mediator は inner DIDComm JWE を復号しない blind queue である。一方、登録された recipient kid、接続、queue 数、時刻、送受信元 IP、外側 Forward の routing metadata は観測できる。継続会話では公開 did:webvh ではなく relationship 固有の `did:peer:2` を使い、公開 identity との直接相関を mediator の保存状態から外す。DIDComm group chat も同じ relationship 経由で送るため、この分離はグループチャットにも及ぶ。

**"B"（mail-plugin同梱）追加分**——SMTP inbound listenerとoutbound submission HTTPが同じプロセスに同居することで、mediatorはさらに以下を観測できるようになる（旧biset-coreが観測していたのとほぼ同じ範囲）。

- SMTP envelope（MAIL FROM/RCPT TO）、接続元、TLS使用有無、メッセージ byte 数（listener.ts、§11.1）
- outbound submission requestの`mailFrom`/`rcptTo`/署名者identity（mail-submission-http.ts、§11.2）——ただしこれは「mailFromがidentityの正当なアドレスであること」と「署名がcurrent update keyで検証できること」を確認するためだけに使われ、別途保持されるroster/credentialは存在しない（旧core roster方式は完全に消滅した）

inbound mailの`protectedPayload`はmediatorに対するE2EEを意味しない。通常メールならmediatorは受信したraw RFC 5322 byteを見ることができる。DIDComm Forwardへ変換された後は他の1:1/group chatメッセージと同じくblind queueに載る。

### 4.4 biset-mimi Self Vault を信頼する範囲

Self Vault hub は MLS application/handshake message の内容を復号しない——providerがVault plaintextやSegmentKeyを知ることはない。一方、Self Vault groupのroom URI、参加device数、epoch/sequence、payload size、時刻は観測できる。checkpointペイロード自体もAES-GCM暗号化されており、hubはmanifest（coveredSeq、transferId、chunkCount、payloadHash）だけを見る。

### 4.5 外部 peer と archive（削除済み）

Peer restore と利用者管理の Recovery archive は、**配線を持たないまま 2026-09-05 に削除された**（R2）。
かつては peer restore が現在の MLS member による署名と current-epoch grant を要求し、
archive は独立した 32-byte Recovery Key で AES-GCM 暗号化されていた。

現在、復旧経路は Self Vault checkpoint 一本である（§9.4）。
`recovery-archive.ts` という名前のモジュールは残るが、これは checkpoint の snapshot 生成に使われるもので、
利用者向けの archive export/import ではない。

## 5. Identity と did:webvh

### 5.1 Identity の生成と取得（2026-09-05 に全面的に変わった）

> **biset は identity を作らない。** 発行とホスティングは外部の did IdP（did.md）が行う。
> かつてここにあった自前の identity 生成（32バイト master seed → 24語 BIP39 mnemonic →
> SLIP-0010 で Root Key 導出 → Spare Key → did:webvh genesis を自分で書く）は、
> `createNewIdentity` / `restoreIdentity` ごと削除された（N1、commit `7357830`）。
> 以下は現行の姿である。

利用者は did.md Wallet で biset の端末を一度承認する。biset 側は:

1. `beginDidMdWalletLogin`（`src/client/identity/wallet/did-md-oauth.ts`）が、
   **Wallet を開く前に**公開された did:webvh log を検証する
2. OAuth Authorization Code フローで `/wallet/callback` に戻り、`state` と `iss` を照合する
3. DPoP-bound な device session を得て、`did-md-store.ts` が暗号化して保管する
4. 端末固有の MLS leaf signature key（random Ed25519）と、did.md が認可した MLS device credential
   （`MlsDeviceCredentialV2`）を得る

**biset は did.md の controller 鍵を一切保持しない。** 利用者は Wallet 側から当該 capability をいつでも失効できる。

Self/Vault group（MIMI room）への参加はこの時点では**行わない**。
Self Vault group の作成・external join は `main.ts` の boot flow が `ensureMimiVaultRoom` 経由で別途駆動する。

#### メールアドレスについて

`mailFromForIdentity`（`src/protocol/webvh/identifier.ts`）は、DID の domain が biset の apexDomain の
サブドメインであることを要求し、`{username}@{apexDomain}` を canonical form とする。

> **この関数は現在どこからも呼ばれていない。** メール転送は 2026-09-05 に削除された（§11）。
> かつ **did.md がホストする DID は biset の apex 配下ではない**ため、この導出規則は
> 新方式では成立しない。アドレス採番は **mediator の責務**として設計しなおす方針が決まっている
> （`tasks/W3-wallet-mail-design-proposal.md`）。
>
> 削除前の経緯は記録として残す: 2026-09-04以前は `{username}@mail.{apexDomain}` が正規形だった——
> 外部送信者からの実メールが `user@{apexDomain}` 宛に届いて 550 "no such user" で bounce した実障害を機に、
> bare apex を canonical にし（`5fd385f`）、その後 back-compat を明示的に削除した（`274d110`）。
> `test/identity/webvh-identifier-mail.test.ts` に残る。

### 5.2 複数端末

現行 UI は既存の他端末が生きているかどうかを区別しない。
`mimiSelfBaseUrl` と `deviceKid` が揃った boot は必ず `ensureMimiVaultRoom` を呼び、
routing.json に記録された room URI が見つかれば external join、見つからなければ新規 room を作成する。

新規作成の場合、その端末は Self Vault の唯一の member として始まる。
**過去の履歴を引き継ぐ唯一の経路は checkpoint である**（§9）——peer restore と archive import は
2026-09-05 に削除された（R2）。checkpoint の KEK は現行 MLS epoch の VEK から導出されるため、
**新しい端末を迎えるには既存の端末が1台オンラインである必要がある**。

### 5.3 公開文書

| 文書 | 内容 | 更新認可 | ホスト |
|---|---|---|---|
| `did.jsonl` | hash chain、updateKeys、verificationMethod、move | did:webvh proof / current update key | **did.md**（外部） |
| `did.json` | 任意の did:web mirror | current did:webvh state による検証 | **did.md**（外部） |
| `routing.json` | DIDComm service/keyAgreement、mediator、Self VaultのMIMI room URIポインタ、alsoKnownAs、name、OpenPGP 公開鍵 | Root/current update key の Data Integrity proof | **did.md**（外部） |

`routing.json` は operational data を署名付き PUT で管理するが、did:webvh hash chain 自体には含まれない。DIDComm を有効化すると、signed log には `#routing` pointer が追加される。Self Vault の room URI（`mimiVaultRoom`フィールド、`setRoutingMimiVaultRoom`/`mimiVaultRoomFromRouting`）もこの同じ署名付き文書経由で公開・発見される——別のlookup serviceは存在しない。

### 5.4 Domain move

> **この節は現行コードを説明していない。** ドメイン移転（`moveWebvhIdentity`、旧 `src/identity/webvh/move.ts`）は
> native login と一緒に 2026-09-05 に削除された。identity の発行と移転は did.md の責務である（§3）。
> 以下は削除前の挙動の記録として残す。

Identity は SCID を維持したまま新しい domain へ移転できた。`moveWebvhIdentity` は次を行っていた。

- 新 location に moved did:webvh log を作り、最後に old location に move を記録する。
- 移転を実行する端末の MLS device credential を新 DID prefix へ更新する。
- `routing.json` を新 location へ移し、埋め込まれた DID prefix を置換する。
- identity record、Vault object store、local MLS self-group state row（Self Vault room metadata・deliveryCursorを含む、同一row内に格納されているため自動的に引き継がれる。§6.3参照）を新 DID key へ re-key する。
- DID を埋め込んだ既存 KeyPackage pool を clear し、次回補充させる。

Self Vault room自体は raw DID ではなく SCID または移転後のDIDそのもので管理し、移転で列を分割しない。

移転に関係しなかった sibling device は、boot 時の `adoptPendingMove` で old DID を resolve し、document の現在の `id` が異なれば local record を追従させる。追従は一回の boot につき一 hop である。複数回の移転中に中間 domain が廃止されると、自動追従できない。

### 5.5 署名鍵解決の場所

「この kid の鍵は正当か」という検査は、MLS Authentication Service（`mls/webvh-authentication-service.ts`）、DIDComm sender 解決（`didcomm/webvh-resolve.ts`）、および mail-plugin outbound submission の署名検証（`identity/webvh/resolver.ts`の`resolveCurrentUpdateKeys`、§11.2）にそれぞれ存在する（旧`core/identity/webvh-signing-key-resolver.ts`はcore撤去で消滅し、mail submissionの認証がその代わりに`resolveCurrentUpdateKeys`を直接呼ぶ形へ置き換わった——device roster/credential registrationという別レイヤーそのものが消えた点が、旧ARC.mdの「三つの場所」との実質的な違いである）。

Domain move は document 内の DID prefix を一括変更するため、caller の古い完全 kid ではなく `#fragment` を current document の `doc.id` に結合して照合する。DIDComm routing は old domain ではなく、verified log が示す current `doc.id` から取得する。

## 6. Self Vault MLS group

### 6.1 用途

一つの identity に一つの Self Vault MLS group（MIMIの`self`モードroom）が対応する。用途は三つある。

- 現在信頼されている device leaf の roster
- MLS exporter secret から current VEK を導出する暗号境界
- `flushMimiVaultOutbox`/`synchronizeMimiVault`（`src/client/store/vault/mimi-vault-sync.ts`）が送受信する、Vault delivery pack をチャンク化したMLS application message（PrivateMessage）そのものの搬送

メール本文や DIDComm Basic Message は依然として MLS application message として送られない——それらはDIDCommのauthcrypt/anoncryptで運ばれる（§12）。Self Vaultが運ぶapplication messageの中身は、あくまで各端末が既に確定させたVaultイベント/オブジェクト/SegmentKeyWrapの暗号化パックであり、ユーザーが読む本文そのものではない。

### 6.2 Lifecycle

Self Vault roomのroom IDは、**random**な `mimi://{providerHost}/r/vault-{32 random bytes}` である（`createMimiVaultRoom`）。決定論的なSCID派生ID（`selfGroupIdHex`、旧 `src/mls/self-group.ts`）は前回調査時点ではcore roster projectionのラベルとして生き残っていたが、**core撤去に伴いその用途自体が消滅した**——`selfGroupIdHex`は現行treeでも存在するが、参照するroster projection機構（`installCurrentRosterProjection`、`ensureMimiCoreRoster`）ごと呼び出し元を失っている（knipのunused files/exports、§18参照）。復旧端末は`routing.json`の署名付き`mimiVaultRoom`ポインタからroom URIを発見する（§5.3）。

- 最初の端末は`createMimiVaultRoom`でroomを作成し、初期commitに`app_data_update`拡張（franking agent、participant list、room metadata）を含めて公開する。
- 後続端末は`joinMimiVaultRoom`でRFC 9420 §11 external commitにより参加する。hubがGroupInfo/ratchet treeをHPKEで新端末のkeyへ封印し、参加後の`deliveryCursor`はこの端末自身のexternal join commitがhub上で見つかったseqから開始する（それ以前のapplication messageはforward secrecyにより復号できないため）。
- boot時に`ensureMimiVaultRoom`が(a)routing.jsonからroomを発見してjoinするか、(b)既存stateをロードするか、(c)新規作成するかを決める。
- 他端末の revoke は`removeMimiVaultDevice`によるRemove + 必須UpdatePathのcommitで行う。削除された端末は新 epoch の exporter secret を導出できない。
- epoch 更新時、旧 active segment を seal して新 segment を作り、旧 segment の同じ SegmentKey を current VEK で re-wrap する self-grant sweep（`repairCurrentLocalSegmentKeyWraps`）を行う。

`ensureMimiVaultRoom`は`main.ts`のboot内で二度呼ばれる——一度目はUIのread/write setupより**前**（他のself-groupリーダーがこのroomの存在を前提にするため）、二度目はSelf Vaultのpolling/watchを起動する箇所（そこでは単に既存stateの高速読み出し + best-effortなrouting再publishになる）。

### 6.3 Vendored ts-mls

`src/mls/vendor/` は ts-mls v1.6.2 の fork で、利用する ciphersuite を `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` に限定し、noble ベース HPKE を使う。主な差分は以下である。

1. 1 member Remove にも UpdatePath を必須化する security fix。
2. self-remove 後の無限走査回避と application sender leaf attribution。
3. Domain move のため、committer 自身の UpdatePath で credential を置換できる additive hook。

差分には `// biset:` marker があり、`src/protocol/mls/VENDOR.md` に記録される。`test/mls-core.test.ts` と `test/mls-crypto.test.ts` は現行 tree に存在し、fork の主要操作を検査している。

## 7. 鍵と秘密の一覧

> **2026-09-05 に大きく変わった。** native login の削除で `IdentityRecord` ごと消えたため、
> master seed・Root Key・Sign Key・Spare Key は**もう存在しない**。
> identity の controller 鍵は did.md 側にあり、biset は保持しない。

| 鍵・秘密 | 単位 | 保存 | 公開・伝播 | 更新状況 |
|---|---|---|---|---|
| did.md device session（DPoP 鍵、device material、Vault secret） | device | `biset-did-md-wallet` IndexedDB。**private leaf key と Vault secret は非抽出の browser AES 鍵で封印**（`did-md-store.ts`） | しない | Wallet 側から失効可能 |
| MLS device credential / Self Vault leaf private state | device | MLS IndexedDB（`biset-mls-self-group`、同一 row に Self Vault room state を内包） | public verification method、Self Vault room | MLS UpdatePath / credential migration |
| MLS HPKE leaf material | device/epoch | MLS state | MLS tree / KeyPackage | commit により更新 |
| VEK（Vault Epoch Key） | identity + epoch | 永続保存しない | 同 epoch member が exporter から導出 | epoch ごとに変更 |
| SegmentKey | Vault segment | `vault_segments.segmentKey` に平文保存 | VEK で暗号化した signed wrap を同期 | key は固定、wrap を epoch ごとに更新 |
| Relationship X25519 + Ed25519 | counterparty/世代 | encrypted `contact-key.set` Vault object | service-bearing `did:peer:2`、Vault 同期 | `supersedesKid` chain、UI rotation なし |
| Identity front-door DIDComm X25519 | identity | encrypted Vault credential | routing.json、信頼済み端末へ Vault 同期 | rotation schema/UI なし |
| checkpoint の data key | checkpoint ごと | 保存しない。**現行 epoch の VEK で包んで checkpoint 本体に同梱**（§9） | Self Vault member のみ復号可 | checkpoint ごとに新規 |

### 7.1 保存時（at rest）の保護状況

**did.md Wallet の device material は封印されている。** 非抽出（`extractable: false`）の
AES-GCM 鍵を IndexedDB に置き、その鍵で private leaf key と Vault secret を包む。
鍵自体は JS から取り出せないため、IndexedDB のダンプだけでは平文に戻せない。

**一方、Vault 側の `VaultSegmentRecord.segmentKey` は local IndexedDB に平文で保持される。**
Vault object と delivery payload は暗号化されるが、端末 local storage 全体が別鍵で封印されているわけではない。

したがってこの構成は server compromise と配送経路上の漏洩を主に抑えるものであり、
**browser profile / local IndexedDB を読み取れる攻撃者に対する at-rest protection は Vault 側で未完成**である。
かつて存在した「`IdentityRecord` の master seed と Root private key が平文」という最大の穴は、
その record ごと消えたことで結果的に無くなった。

### 7.2 消えた鍵

| かつて | 現状 |
|---|---|
| Master seed / 24語 Root Key phrase | **無い**。identity は did.md が発行する |
| Root / Sign / Spare Ed25519 key と pre-rotation | **無い**。鍵ローテーションは did.md の責務 |
| OpenPGP private credential | 書き手（reader/sink）は R2 で削除。record 型（`assertOpenPgpCredentialRecord`）だけが<br>過去 event の復号のため `mutation-records.ts` に残る |
| Recovery Key（利用者管理 archive 用） | archive import は R2 で削除。`recovery-archive.ts` 自体は<br>checkpoint の snapshot 生成に使われるため残る |

## 8. Vault

### 8.1 データモデル

Vault の長期正本は immutable な二種類の record からなる。

- **VaultObjectV1** — 32-byte SegmentKey と AES-256-GCM で暗号化した content-addressed object。nonce、AAD、ciphertext hash、plaintext length を ID に含める。
- **VaultEventV1** — actor device、actor sequence、kind、target、object reference、parents、timestamp を MLS leaf Ed25519 key で署名した event。event ID は canonical body と署名から導出する。

代表的 event kind は `message.add/edit/tombstone`、`mailbox.set`、`keyword.set`、`transport.result`、`didcomm.control`、`contact-key.set`、OpenPGP/DIDComm credential である（`src/protocol/vault.ts`の`VAULT_EVENT_KINDS`が唯一の正本リストであり、`vault/delivery-pack.ts`のdecode allow-listもこの同じ定数を直接参照する）。Raw RFC 5322 と JMAP metadata は別々の encrypted object として一つの `message.add` から参照される。

### 8.2 Segment と epoch

同一 segment の object は同じ random SegmentKey を使う。SegmentKey は current epoch の VEK で AES-GCM wrap され、grantor device の署名を付ける。Self Vault epoch が変わると active segment を seal し、新 segment を作る。過去 segment は鍵自体を変えず、current VEK 向け wrap を追加する。

復号時は必ず current Self Vault state を読み、current epoch の有効な member が署名した wrap だけを受け入れる。古い epoch の wrap へ自動 fallback しない。

### 8.3 IndexedDB transaction

`biset-vault-core` database は、object、event、chunk、segment、key wrap、manifest、projection、JMAP state、各種 durable outbox/receipt/cursor、restore session、transport statusに加え、Clientだけが知る did.md セッション↔Vault binding、private MLS state、期限付きpending join KeyPackage秘密鍵を持つ。

Ingress commit、local mutation、Vault delivery ingest は、record、projection、JMAP state、次の network ACK/outbox を同一 transaction に書く。Network 送信に失敗しても、次回 retry すべき ACK または delivery intent が local に残る。重複 event/ingress は unique key と content hash で idempotent に扱う。

### 8.4 Projection

Local JMAP projection は cache/read model であり正本ではない。Reducer は event を決定論的順序で適用し、offline の競合を収束させる。壊れた projection は全 event/object を検証・復号して再構築できる。必要な current-epoch wrap が一つでもなければ部分結果を返さず失敗する。

Local garbage collection は実装されていない。Tombstone や completed outbox は一部削除されるが、長期 Vault record の compact/retention policy はない。

## 9. 配送モデル

### 9.1 メール受信（mail-plugin bridge）

**旧biset-coreのbounded ingress store/pull/ack機構は完全に消滅した。** 現行の受信経路は次のとおりで、pull ではなく push であり、TTL/quotaを持つ独立バッファも存在しない。

1. `src/server/mediator/mail-plugin/listener.ts`（"B" deployment）が port 25 で生SMTPを受ける。EHLO/HELO、MAIL、RCPT、DATA、RSET、NOOP、QUIT、STARTTLSを扱い、既定25 MiB制限を広告・強制する。SMTPUTF8とAUTHは提供しない。TLS certificate/keyが設定されればSTARTTLSを提供するが、未設定でもserverは起動しplaintext SMTPとなる（旧biset-coreのSMTP listenerと同じ挙動——`smtp-socket-server.ts`/`mail-smtp-protocol.ts`は`src/core/adapters/`から2026-09-03にこのディレクトリへ物理的に移設されただけで、ロジックは変わっていない）。
2. RCPT TO時点で`bridge.ts`の`resolveMailRecipientRoute`が宛先アドレスの**routing.jsonをdomainだけから直接resolveする**（`identityDomainForMailAddress`が`mailFromForIdentity`の決定論的逆関数——SCID lookupもsigned-log resolveも経由しない）。宛先がDIDComm keyAgreement/serviceを公開していなければ550で拒否する。
3. DATA受理時、同じ`bridge.ts`の`packInboundMailForward`が受信メッセージを`MAIL_BRIDGE_INBOUND`型のDIDCommプレーンテキストへ包み、mail-pluginが自分で保持する専用の`did:peer`送信元identity（`SqliteMediatorStore.loadMailPluginIdentity`、real end-user identityとは別）からauthcryptし、宛先のmediator（Forward hop chainを含む）へ`OutboundDelivery`としてPOSTする——**core時代のingress store/pull/ackという独立した概念がなく、通常のDIDComm 1:1/group chatメッセージと全く同じmediator queueに載る**（§12.5）。
4. Client側は他のDIDCommメッセージと同じ`DidCommIngressProjector`/mediator SSE watch経由でこれを受け取る（§12.5）。deviceごとのlease/quota/ACKという概念はもう存在しない。

roster（device集合の認可情報）はこの経路のどこにも登場しない——宛先解決がrouting.jsonの公開情報だけで完結するため、"このidentityの端末集合をmail認可のために知っておく"という前段そのものが不要になった。前回調査時点の`rosterBackedVaultDeliveryAuthorizer`/`ensureMimiCoreRoster`は呼び出し元を失っている（§6.2、§18のknip debt）。

### 9.2 MIMI Self Vault delivery（現行）

一端末で確定した Vault mutation は、`VaultDeliveryOutboxReader`から読み出され、`flushMimiVaultOutbox`（`src/client/store/vault/mimi-vault-sync.ts`）が`splitMimiVaultPayload`でチャンク化し、各チャンクを`PersistedMimiVaultSession.sendApplication`経由でMLS PrivateMessageとして暗号化し、Self Vault roomへ`POST /update/{roomId}`で送信する。1件のoutbox entryのすべてのchunkが受理されて初めてoutbox recordを削除する。

- HTTP応答が失われても、`pending`フィールド（同一identityId row内）に暗号化済みバイト列とdeliveryIdが永続化されているため、次回attemptは同じciphertextを同じdeliveryIdで再送する——プレーンテキストを新しいratchet stateで再暗号化することはない。
- 受信側の`synchronizeMimiVault`は`pullMimiVaultPages`でbounded pull（1ページ32件、最大1024ページ）し、`decodeMimiVaultBatch`でチャンクを再構成する。
- checkpoint（後述、§9.4）は chunk と manifest が別々の非atomicな送信であるため、pull windowがその境界をまたぐと今回のbatchだけでは再構成できないことがある。`recoverSplitCheckpoints`がより広いpull windowで一度だけ再試行する。
- 4種類の名前付きrecovery strategy（`recoverSplitCheckpoints`／`applyCheckpoints`／`ingestDeliveries`／`synchronizeMimiVault`内のepochTooOldリトライ）がそれぞれ独立した関数として切り出されており、いずれも一件の失敗をbatch全体の失敗に波及させない。失敗は`MimiVaultSyncGap`（`kind`+`detail`）として構造化されたレポートに蓄積され、`synchronizeMimiVault`自体は例外を投げない。呼び出し側（`main.ts`）は`gaps`に`outbox-flush-failed`があれば明示的に例外へ変換し、UIのVault cardをerror状態にする。
- **checkpoint自動再作成のpoisoning対策**: 自分のローカルVaultがこのラウンドで一件でも不完全（undecryptable、ingest失敗、checkpoint restore失敗等）であれば、`result.gaps.length === 0`のガードにより新しいcheckpointを作成しない。ローカルが不完全な端末が「最新」を騙って他端末の復元を汚染する問題への対策である。

### 9.3 現行 Client の接続状態

MIMI Self Vaultのprotocol、SQLite store（hub側）、HTTP transport、projector、outbox/checkpoint、boot/poll loop、live SSE watch（`watchMimiVaultDeliveries`、`mimi-vault-watch.ts`）はすべてブラウザ製品経路へ接続済みであり、複数端末への同一メッセージ配送を実機で確認済みである。`message.add`が直接transportとVault delivery projectorの二経路から届く場合は、base projectionに同一immutable metadataがあれば冪等化し、同一batch内の重複または異なるmetadataは競合として拒否する。

**legacy core Vault delivery（`flushVaultDeliveryOutbox`/`CoreVaultDeliveryTransport`、`/v1/vault-delivery/*`）はコードとして`main.ts`に残っているが、この宛先を実装するサーバー（biset-core）自体が2026-09-03に削除されているため、production configの有無に関わらずもはや動作しうる経路ではない。** 呼び出しは`mimiVaultConfigured`のfalse時にのみ発生し、production configは常に`mimiSelfBaseUrl`を設定しているためこの分岐自体が実行されないが、仮に実行されたとしても`coreBaseUrl`（デフォルト空文字列）宛のHTTP呼び出しが失敗するだけである。旧ARC.mdの「MIMI未設定時のfallback」という説明は、core撤去後は「fallbackの体をした死んだコード」に変わった。

### 9.4 Restore（2026-09-05〜06 に全面的に変わった）

**復元経路は biset-mimi Self Vault checkpoint 一本である。**
かつて §2.1 が挙げていた「信頼済み peer からの restore」と「利用者管理の暗号化 archive」は、
配線を持たないまま R2 で削除された。

1. Client は event/object と全 SegmentKey を canonical Recovery Archive snapshot にする
   （`createRecoveryArchiveSnapshot`）。MLS exporter secret と device signing key は含めない
2. fresh random data key で snapshot を AES-GCM 暗号化する
3. **その data key を、現行 MLS epoch の VEK で包む**（envelope v3、`createVaultCheckpoint`）。
   envelope は `selfGroupId` と `epoch` を平文で持ち、AAD にも含める——
   鍵を取り出す前に「自分に開けるか」を判断でき、epoch のすり替えは AAD 不一致で落ちる
4. manifest（`VaultCheckpointManifest`: `coveredSeq` / `transferId` / `chunkCount` / `payloadHash`）だけが
   hub に見え、payload 自体は MLS application message として運ばれる
5. 新端末は `joinMimiVaultRoom` の external commit で Self Vault に参加した後、checkpoint を復号し、
   current epoch へ key wrap を更新して projection/cursor を再構築する

#### KEK が masterSeed から VEK へ変わった理由と、その代償

旧設計は recovery KEK を **root phrase から HKDF で導出**していた。native login の削除で
master seed が存在しなくなり、**checkpoint は作成も復元もできない状態になった**。

代替として3案を検討し、**MLS self-group の VEK で包む案**が選ばれた（W5、commit `da6bfcf` `74358bb`）。

> **`deriveVaultEpochKey` は現行 epoch でしか鍵を返さない。** これは MLS の forward secrecy と
> 整合した意図的な設計である。したがって:
>
> - **epoch が進むと、古い checkpoint は誰にも開けなくなる**（作った本人を含む）
> - 新端末が参加すると epoch は必ず進む。つまり参加直後の新端末は既存 checkpoint を開けない
>
> 解決は「再ラップ」ではなく「**作り直し**」である。古い VEK を再導出する道は無いが、
> Vault 全体をローカルに持つ端末なら checkpoint をいつでも作り直せる。
> `main.ts` の自動再作成ゲートに epoch 不一致の条件が入っている。
>
> **そのゲートは、その端末が既にその履歴を持っている場合（`coveredSeq <= localCursor`）にだけ
> 再作成を許す。** さもないと、参加直後で Vault が空の端末が「最新」を名乗って checkpoint を
> 再公開してしまう（2026-09-02 に実際に起きた checkpoint poisoning と同じ形）。

**受け入れた代償**: 新端末を迎えるには既存端末が1台オンラインである必要があり、
**全端末を失った場合の復旧手段は無い**。現状これを利用者に警告する UI は無く、
Vault カードに skip の詳細が出るだけである。

開けない checkpoint は例外ではなく `gaps`（`checkpoint-epoch-unavailable`）として報告され、
同期ループは止まらない。

> 関数名の `Coordinator` 接頭辞（`createPortableCoordinatorCheckpoint` 等）は W5 の書き直しで
> 解消した。現在は `createVaultCheckpoint` / `openVaultCheckpoint` である。

#### 検討して却下した案: Wallet 側で決定論的に導出した secret（2026-09-06）

新端末の enrollment は必ず did.md Wallet 認証を経る。Wallet は root private key を保持しているため、
`vaultSecret`（現状 `crypto.getRandomValues` で**端末ごとにランダム**に生成、`did-md-oauth.ts`）を、
**Wallet 側で root key から決定論的に導出**すれば、全端末が同じ値を得られる——masterSeed が持っていた
「時間にも端末にも依存しない」性質を、biset 側に private key を渡さずに取り戻せる案として検討した。

**却下した。** この変更は checkpoint に対する前方秘匿性（forward secrecy）と
post-compromise security の**両方**を失わせる——一度その secret が漏れれば、
それ以前に公開された checkpoint も、その後に作られる checkpoint も、ローテーションの仕組みが無い限り
永久に読める固定鍵になる。加えて、`vaultSecret` は現在**端末ごとに別々**だが、決定論的にすると
**全端末が同じ値を持つ**ため、1台の端末の侵害だけで identity 全体の checkpoint が終わる——
被害範囲も広がる。VEK（現行案）は epoch ごとに変わるため、この種の固定鍵化を避けている。
**VEK 堅持が結論。**



## 10. Local JMAP と UI

### 10.1 Local gateway

`LocalJmapGateway` は IndexedDB projection を JMAP 形で公開する。実装済みメソッドは以下である。

- `Mailbox/get`
- `Email/get`
- `Email/query`（mailbox filter、position、limit）
- `Email/set`（mailboxIds / keywords の限定更新）
- `EmailSubmission/set`（一回に一 create の同期的最小実装）
- local blob download と byte range

Session は `biset://local/...` URL を使い、account を read-only と宣言しているが、mutation sink が構成された場合は限定 write を受け付ける。JMAP changes、search、copy、identity、vacation response、完全な submission lifecycle は未実装である。

### 10.2 Remote JMAP

`RemoteJmapTransport` と `AccountRouter` は標準 `/.well-known/jmap` discovery、method call、blob range download、および `local-vault` / `remote-jmap` account type を実装する。ただし `main.ts` の実 UI は local records の先頭一件だけを選び、account switcher や remote account provisioning を構成しない。現時点では library capability であり製品機能ではない。

### 10.3 Boot sequence

Identity がある場合の`bootClient`（`src/client/app/main.ts`）の主要順序は次のとおりである。

0. **（新規、2026-09-04）** `storedRecords.length === 0`（このデバイスにidentityが一つもない）場合は、account-createページを描画する前に`biset-identity`以外のすべてのsecondary IndexedDB（`biset-mls-self-group`、`biset-mls-keypackages`、`biset-vault-core`、`biset-wallet`、`biset-didcomm-group-chat`）を削除する（`ALL_LOCAL_DATABASE_NAMES`定数 + `deleteLocalDatabases`ヘルパー）。crash中のsignupや壊れたstoreでこの状態に迷い込んだ端末が、所有者不在のsecondary storeを無期限に溜め込むのを防ぐ防御的cleanupで、UIは一切介在しない（logoutの延長ではなく、logoutを経由しない到達も含む）。同じcommitで`logout()`自身の同等cleanupに`biset-didcomm-group-chat`が最初から欠けていた別のリークも修正した（この store が追加されて以来、logoutのたびにそのrowが孤立していた）。
1. 以前の poll interval / Self Vault watch handle / mediator poll handle をすべて停止する（logout の再入で古いidentityのポーリングが残らないようにする）。
2. identity record、MLS/Self Vault、Vault IndexedDB を開く。
3. domain move を passive adoption する（`adoptPendingMove`）。
4. 最初の identity で read model を構成し、**ここで一度目の`ensureMimiVaultRoom`を呼ぶ**——後続のSegmentKeyWrap修復・migration読み出しがSelf Vault stateの存在を前提にするため。
5. 全local identityについて`repairCurrentLocalSegmentKeyWraps`/`migrateLocalSegmentKeysToStorageRoot`を実行する。
6. account UI を構成する（device一覧、removeVaultDevice、editName、moveIdentity）。
7. **`apexDomain && identity.deviceKid`が揃っていれば** Vault mutation boundary を作り、DIDComm/OpenPGP credential を best-effort で provision し、compose/reply、DIDComm group chat、mail ingress、mediator watch（SSE）を構成する（§14の「coreBaseUrl gate regression」を参照——この条件は2026-09-04まで`coreBaseUrl && apexDomain && identity.deviceKid`だった）。
8. inbox を描画し、mail ingress を直ちに同期する。
9. mail ingress と DIDComm outboxを 10 秒間隔で poll する。
10. mimiVaultConfigured なら**二度目の**`ensureMimiVaultRoom`（軽量な再読み出し）を経て`synchronizeMimi`を即時実行し、続けて`watchMimiVaultDeliveries`（SSE）を起動する。DIDComm 1:1/group chatの受信もmediator SSE watch（`watchMediator`、ポーリングではない）経由である。

apexDomainまたはdeviceKidがなければ UI は local projection の read-only viewer として起動する。

## 11. Mail transport

> **⚠️ クライアント側のメールは 2026-09-05 に削除された（N1）。**
> 送信（`buildMailSubmitter`）も受信（`MailIngressProjector`、mail-bridge 分岐）も配線が消えている。
> **サーバー側（mail-plugin）は稼働したまま**であり、SMTP を受けて DIDComm Forward へ変換する能力を保っている——
> それを受け取るクライアント側が無いだけである。

### 11.1 現状

| 層 | 状態 |
|---|---|
| SMTP listener、inbound bridge、outbound SMTP client、submission HTTP | ✅ **稼働**（`src/server/mediator/mail-plugin/`） |
| クライアントの送信経路 | ❌ 削除済み |
| クライアントの受信経路 | ❌ 削除済み |
| OpenPGP | ❌ 削除済み（reader/sink は R2 で削除、record 型のみ残存） |

現在の送信 UI は DID 宛先しか受け付けず、メールアドレスを入れると
`'A did.md Wallet session composes to DID recipients only'` で明示的に失敗する。

### 11.2 再実装の方針（未着手）

**メールアドレスの採番と送信署名鍵は biset ではなく mediator の責務**として設計しなおす方針が
決まっている（2026-09-05 ユーザー判断）。

> did.md が専用の mediator を運用し、利用者は Wallet ログイン時にそこへ登録する。
> 特定 mediator の使用許可を capability として付与する。

これに伴い `mailFromForIdentity` の「DID のドメインが biset の apex 配下であること」という制約は外れる
（did.md がホストする DID は apex 配下ではないため、現行の導出規則では**そもそもアドレスを持てない**）。

設計案は `tasks/W3-wallet-mail-design-proposal.md`。**実装には did.md 側の mediator が必要で、
このリポジトリ内では完結しない。**

### 11.3 削除前の設計（記録）

サーバー側の認可は現在も次の二点だけで、**device roster という概念は存在しない**
（`mail-submission-http.ts` の `isAuthorised`）。

1. 申告された `mailFrom` が `mailFromForIdentity(identityId, apexDomain)` の導出結果と一致すること
2. `signature` が `resolveCurrentUpdateKeys(identityId)`——routing.json 更新そのものが要求するのと同じ
   did:webvh current update key——で検証できること

**found live（2026-09-04）: outbound relay はこの日まで一度も実際に動作したことがなかった。**
`smtp-client.ts` の outbound SMTP に STARTTLS のバグがあり、修正して初めて end-to-end で確認された。
その翌日にクライアント側が削除されたため、**実働が確認されたのは実質1日だけ**である。

## 12. DIDComm

### 12.1 Public front door

Boot 時、最初の端末が identity-shared X25519 credential を Vault に作り、routing.json の一つの `keyAgreementVerificationMethod` として公開する。Sibling は同じ encrypted credential を Vault 同期経由で読む設計である。Mediator URL が設定されていれば各 mediator へ Coordinate Mediation 2.0 で登録し、成功した endpoint だけを DIDCommMessaging service として公開する。

**core撤去による訂正**: `enableDidComm`（`src/client/identity/bootstrap.ts`）は、全mediator登録が失敗した場合の"legacy fallback"として、依然として`opts.coreBaseUrl`から`{coreBaseUrl}/v1/didcomm/ingress`という形のエンドポイント文字列を組み立ててroutingへ最初に一旦PUTするコードを持つ。しかし`coreBaseUrl`は`readBisetConfig()`で常に空文字列にデフォルトし（production configはこの変数を一切設定しない）、`/v1/didcomm/ingress`を受けるサーバー自体（biset-core）も存在しない。production configはmediatorUrlsを常に設定しており、通常はそのうち少なくとも一つの登録が成功して`mediators.length`が真になった時点でこの一時的なroutingがmediator情報で上書きされるため、実運用上この空origin fallbackが最終的に公開されて観測される事態にはなっていない。ただし、すべてのmediator登録が失敗する状況では、動作しないURLを指すDIDCommMessaging serviceが公開文書に残ることになる——これは「fallbackとして機能する」というより「動かないなら動かないなりに、無害だが無意味な文字列を残す」という状態であり、旧ARC.mdの「legacy core `/v1/didcomm/ingress`をfallbackとする」という説明はもはや正確ではない（§20の cleanup項目参照）。

Identity front-door key は新規関係の発見と `RELATIONSHIP_INIT` だけに使う。

### 12.2 Private relationship

初回送信者は relationship 専用 X25519/Ed25519 pair と service-bearing `did:peer:2` を生成し、その peer kid を mediator に **INIT より先に** 登録する。受信者も専用 peer identity を生成・登録し、双方の公開情報と自分の秘密鍵を encrypted `contact-key.set` として保存し、登録済み initiator peer へ `RELATIONSHIP_ACCEPT` を返す。

確立後の Basic Message 2.0（1:1）とDIDComm group chatのINVITE/MESSAGE（§12.6）はどちらも同じ relationship kid 間の authcrypt だけを使う。継続 JWE と mediator connection owner に公開 did:webvh front-door kid を含めない。Current relationship credential は boot 時に Vault から読み、peer kid ごとにmediator SSE watchを再開する。

Handshake pending state は `main.ts` の二つの `Map`（`pendingByOwnKid`/`pendingByCounterparty`）にのみ存在し、60 秒 timeout がある。INIT 後 ACCEPT 前に reload/crash すると private pending key と promise を失い、queue に届いた ACCEPT を復号できない。この状態の durable 化または再開始 protocol は依然として未実装であり、DIDComm group chatの招待メッシュ完成（§12.6）もこの同じ揮発性handshakeに乗るため、同じ制約を受け継ぐ。

### 12.3 暗号形式

- Authcrypt: `ECDH-1PU+A256KW` + `A256CBC-HS512`
- Anoncrypt Forward: `ECDH-ES+A256KW` + `A256CBC-HS512` を生成し、受信は `XC20P` も許容
- 任意の hybrid authcrypt: X25519 + ML-KEM-768 を独自 alg identifier で KDF に混ぜる

Hybrid は recipient routing に ML-KEM key がある public-DID path の primitive として存在する。Relationship credential schema は X25519/Ed25519 だけで、継続 private relationship は ML-KEM hybrid を使わない。

### 12.4 Mediator

Standalone mediator は自身の did:peer identity、connection keylist、queueを**SQLite**（`src/server/mediator/sqlite-store.ts`）に保存する。Coordinate/Pickup request は DIDComm authcrypt の sender X25519 keyで認証する。did:webvh sender は公開 routing を resolve し、did:peer sender は self-certifying DID から鍵を得る。

Queue は recipient kid あたり最大 256 件、保持 30 日で、満杯時は古い正当 message を捨てず sender を拒否する。Pickup は non-destructive delivery の後、`messages-received` ACK で削除する。Connection は最大 10,000、connection ごとに最大 32 kid。Replay guard は既定 10 分 / 50,000 ID、resolved key cache TTL は 10 分で stale-while-refresh 動作をする。共有HTTP surfaceは単一の `POST /` （DIDCommメッセージ種別で内部分岐）、`GET /.well-known/did.json`、`GET /stream`（SSE、client側の`watchMediator`が使う）の3経路であり、これは"A"（素のmediator）と"B"（mail-plugin同梱）で完全に共通（`deployment.ts`）である。"B"はこれに加えてSMTP:25とsubmission HTTP:8792を独立に持つ（§3・§11）。

`relay-poller.ts`は、あるmediatorが別のupstream mediatorへ自分自身をclientとして登録し（`MEDIATOR_RELAY_UPSTREAM_URL`）、自分宛のForwardをunwrapして自分のqueueへ再Forwardする、任意のmulti-hop中継機能である。routing.jsonの`routingKeys`（outermost-first）でこの中継段を名指しできる。dispatch()自体はこの機能の有無で変わらない——upstream側からは通常のend-user deviceに見え、downstream側からは通常のForward requestに見える。

DBファイルへの書き込み失敗時の挙動は、本調査でも未検証のまま次回調査で確認すべき既知の空白として残る。

### 12.5 メッセージ振り分け（1:1・group chat・mail bridge）

**旧「Legacy core DIDComm path」節は本調査で全面的に置き換えた——core自体が存在しないため、`/v1/didcomm/ingress`というサーバー route はどこにも実装されていない。** mediatorのSSE watchループが受け取るのは、型タグで振り分けられる単一のqueueに載った次の3種のペイロードだけである。

1. DIDComm 1:1（Basic Message 2.0、§12.2・§12.3）
2. DIDComm group chat control/content（GROUP_INVITE等、§12.6）
3. `MAIL_BRIDGE_INBOUND`（§9.1・§11.1のmail-plugin bridgeが変換したメール）

`DidCommIngressProjector`（`src/client/didcomm/ingress-projector.ts`）は元々core経由のlegacy ingressとmediator経由の両方で共用される汎用decodeクラスとして書かれていたが、core側の呼び出し元（`CoreIngressTransport`、main.tsの`if (coreBaseUrl)`ブロック内、§14参照）は現在事実上死んでいる。実際に動くのはmediator SSE watch経由の1経路だけであり、legacy core ingressとの二重化は名目上残るコード（`CoreIngressTransport`、`opts.coreBaseUrl`の空文字列defaultなど）はあっても、実質的には解消済みである。

### 12.6 DIDComm group chat

複数人チャットの現行かつ唯一の実装。`src/client/didcomm/group-chat.ts`と`group-chat-store.ts`（IndexedDB、device-localなroster cache）、`main.ts`側の`createAndSendDidCommGroup`/`sendDidCommGroupMessage`/`handleDidCommGroupInvite`/`handleDidCommGroupContent`から構成される。MLS共有group stateを一切使わない full-mesh pairwise fan-out であり、1:1チャットと同じ`ContactKeyV1`関係を再利用する。

- アドレススキームは`didcomm-group:<groupId>`（compose/replyの`toAddrs`が2件以上のDIDのとき自動的にグループ作成へ分岐する）。
- グループ作成（`createAndSendDidCommGroup`）は各招待者へ`GROUP_INVITE`（version, groupId, 送信者含む完全なmembers一覧, name）を送り、続けて`sendDidCommGroupMessage`で founding message を送る。招待の一部が失敗しても founding message は全メンバー分キューに積まれ、outboxのretryで後から届く。
- 受信側の`handleDidCommGroupInvite`は招待メッセージを`groupChatStore`へmergeし、まだ`ContactKeyV1`を持たない各メンバーとの handshake を非同期に(awaitせず)開始して mesh を完成させる。
- v1スコープは意図的に狭い——グループ作成後のメンバー変更、端末間でのroster同期（同一identityの複数端末は個別にrosterを持つ）、改名、退出、メッセージの編集/削除/リアクションはいずれも未実装。
- **2026-09-03に修正された既知の鋭利な角**: グループメッセージは1つの`emailId`をN人のrecipientで共有するが、outbox flushはかつて`mailbox.set{sent:true}`という per-email フラグだけを見て「送信済みだから削除してよいoutbox行」を判定していた。1人目のrecipientへの送信成功がそのフラグを立てると、同じflushパス内の他のrecipient行が「クラッシュ後の残骸」に見えて実際には一度も送信されずに削除される——2人以上の招待を伴うグループ作成メッセージが最初の1人にしか届かない、という形で現れた。修正後は各recipient行ごとに`noteDidCommOutboxAttempt`で試行を記録し、per-email フラグに頼る早期削除を行わない。同じコミットで、1recipientの送信失敗が同一flushパス内の他recipientへの配送を止めてしまう`break`も`continue`に直した。

## 13. HTTP surface と保存状態

**この節は二度書き換えられている。** biset-core はディレクトリごと削除され（2026-09-03）、
続いて **Anchor も削除された**（2026-09-05）。したがって biset が運用する HTTP surface は現在
Mediator/mail-plugin（§13.2）と biset-mimi（§13.3）の**2系統だけ**である。

### 13.1 HTTP surface（did.md — 外部依存）

did:webvh log（`/.well-known/did.jsonl`）、did:web mirror（`/.well-known/did.json`）、
routing 文書（`/.well-known/routing.json`）、および OAuth のエンドポイントは、いずれも **did.md が提供する**。
biset はこれらを**読むだけ**で、書き込まない（§3）。したがって biset 側にこれらを提供する HTTP surface も、
`ANCHOR_DATA_DIR` のような永続化ディレクトリも、もはや存在しない。

クライアント側で対応するのは `src/identity/webvh/` の resolver 系（`resolver.ts` `log.ts` `log-io.ts` `proof.ts` ほか）で、
これは**他人の DID を解決する**ために必須であり、native login の廃止とは無関係に残っている。

### 13.2 HTTP surface（Mediator / mail-plugin）

共有部分（"A"/"B"共通、`deployment.ts`）は単一の `POST /`（DIDComm種別で内部分岐: Coordinate Mediation、Pickup、Forward中継等）、`GET /.well-known/did.json`、`GET /stream`（SSE）である。

"B"（mail-plugin同梱）はこれに加えて以下を持つ。

| 経路 | プロトコル | 役割 |
|---|---|---|
| SMTP `:25`（既定） | 生SMTP、STARTTLS任意 | inbound mail → `MAIL_BRIDGE_INBOUND` DIDComm Forward変換（§9.1・§11.1） |
| `POST /v1/mail/submit`（HTTP `:8792`、独立`Bun.serve`） | 署名済みJSON | outbound mail submission（§11.2）。CORS/originチェックあり（`MEDIATOR_ALLOWED_ORIGINS`、2026-09-04追加、下記参照） |

旧biset-coreにあった`/v1/roster/*`、`/v1/ingress/pull`・`/ack`、`/v1/vault-delivery/*`、`/v1/restore/*`、`/v1/didcomm/ingress`はいずれもこのHTTP surfaceに存在しない——これらの機能自体が§9.1・§9.3・§12.1・§12.5で述べた通り後継なく消滅したか、公開情報から直接解決する設計に置き換わったかのどちらかである。

**found live（2026-09-04）**: `/v1/mail/submit`はshared mediatorの`deployment.ts`が持つCORS/originチェック（`MEDIATOR_ALLOWED_ORIGINS`allowlist）を最初から一切継承していなかった——独立した`Bun.serve`である以上当然だが、当初はこの経路専用のCORS処理そのものが存在しなかった。ブラウザからのoutbound mail送信は、compose UIのoriginとmediator.biset.mdのoriginが常に異なるため、OPTIONSプリフライトが`Access-Control-Allow-Origin`を得られずPOST自体に到達しないまま全て失敗していた。`deployment.ts`と同じ`MEDIATOR_ALLOWED_ORIGINS`環境変数を再利用する形でOPTIONS/CORSヘッダ処理を追加して解消した（commit `b270324`）。

### 13.3 HTTP surface（biset-mimi）

IETF draft-ietf-mimi-protocol §5.2/§5.3のprovider-facing routesを実装する（`src/server/mimi/http.ts`）。主なpathは、well-known protocol directory、`GET /stream`（deliveries、SSE watch tokenで認可）、franking agentデータ、asset proxy download、`POST /notify/*`（federation fanout受信）、`POST /groupInfo/{roomId}`（external join、`allowExternalJoin`が有効なdeploymentのみ既定拒否を解除——`self`モードだけがこれを有効化する）、abuse report、consent request/update、identifier query、`POST /keyMaterial/{targetUser}`、`POST /keyPackage`、`POST /update/{roomId}`（room作成・external join commit・通常commit・checkpoint application messageのいずれも、この単一endpointを通る）である。すべてのbodyはbiset独自のprovider-internal credential signature（`authorizer.ts`）で認証する——membershipとMLS leaf署名だけが認可根拠であり、外部の認証トークンは要求しない。この節は core 撤去にも Anchor 削除にも影響を受けていない。

### 13.4 Fail-closed composition

Mediator（"A"/"B"共通）は`MEDIATOR_PUBLIC_URL`と`MEDIATOR_DATABASE_PATH`/`MEDIATOR_DATA_DIR`のいずれかが必須。"B"（mail-plugin）はさらに`MAIL_PLUGIN_APEX_DOMAIN`が必須。biset-mimiは`MIMI_DATABASE_PATH`必須で、未設定時は起動時に例外で落ちる（healthのみ公開という緩やかなfallbackはない）。

一つの SQLite database（mediator側）に did:peer identity、connection、queueを置く。Self Vault/group chatのMLS状態はbiset-mimi自身の別プロセス・別SQLiteファイルに置く（`MimiDeploymentOptions.mode`ごとに専用DBファイルが必須）。**did:webvh/routing files は biset のどのサーバーにも置かれない**——did.md がホストする（§13.1）。Plaintext mailbox projection、private identity key、SegmentKey、MLS exporter secret はどのサーバー側storageにも置かない。

### 13.5 Hosting limits

- did.jsonl / did.json / routing.json のサイズ上限は、ホストである **did.md 側の関心事**である。
  かつて Anchor が課していた上限（did.jsonl: request 1 MiB、identity ごと 10,000 entry / 16 MiB、他は 1 MiB）は、
  Anchor ごと削除された
- mail submit body: 25 MiB（mail-plugin `/v1/mail/submit`）
- inbound SMTP message: 既定25 MiB（mail-plugin SMTP listener、`MAIL_PLUGIN_MAX_MESSAGE_BYTES`）

biset-coreが持っていた「多くの場合request時に実行する」expiry sweep（roster/ingress/vault-deliveryのTTL管理）は、それらの機構自体が消滅したことで不要になった。常時timer/jobによるvacuumがない点、tombstoneとSQLite fileの物理縮小が運用者責任である点は変わらない。

## 14. 可用性、失敗、冪等性

- Client の local transaction を network ACK より先に行うため、response loss は再送で回復できる。
- biset-mimi Self Vault送信は`pending`フィールドへ暗号化済みciphertextとdeliveryIdを先に永続化してから送信するため、HTTP応答喪失は同一ciphertextの再送で回復し、平文の二重暗号化を起こさない（§9.2）。
- mail-plugin bridgeのinbound mailは、DIDComm Forwardとしてmediator queueに積まれた時点でmediatorの標準queue TTL（30日、§12.4）の対象になる——core時代の独立したingress TTL/quotaという概念はなく、mail宛先ごとの専用lease/pull/ackもない（§9.1）。
- DIDComm mediator SSE watch と mail ingress poll は network error を log して次周期/再接続に retry する。
- Outbound mail temporary failure は durable outbox に残るが scheduler がないため、利用者操作なしには retry されない。
- OpenPGP / DIDComm provision、domain move adoption、Self Vault maintenanceの一部は boot を止めない best-effort であり、警告が console にしか出ない。
- `routing.json` 更新は fetch-merge-put だが version/ETag compare-and-swap がなく、複数端末の同時更新で last-write-wins となり得る。
- MIMI Vault syncの各recovery strategyは失敗を`gaps`として記録し、一件の失敗が他の全項目の適用を止めない（§9.2）。
- **found live（2026-09-04）: coreBaseUrl gate regression**。`main.ts`の`bootClient()`で、DIDComm有効化・mediator登録/SSE poll開始（`startMediatorPolling`/`mediatorPollHandles`）・mail submit/ingress・DIDComm group chat・contact-key relationship処理・outbox flushを含む「identityがある場合」のブロック全体（§10.3の手順7）が、`if (coreBaseUrl && apexDomain && identity.deviceKid)`という条件でgateされていた。biset-core撤去（`99e08c0`）の際、この条件式自体は更新されず、以後どのproduction configも`coreBaseUrl`を設定しないため条件は常にfalseになり、**このブロック全体がエラーも出さずに一度も実行されなくなっていた**。何もここで観測できなかったのは、`startMediatorPolling`/`mediatorPollHandles`のセットアップ自体がこの同じブロックの内側にあり、外側から「スキップされた」ことを検知する手段がなかったためである。2026-09-04、実際のinbound mailテスト（mediator自身のSQLite `queued_messages`テーブルには届いていることを確認済み）で、受信者のclientがそれを一度もpollしていないことから発覚した。修正は`coreBaseUrl`をgateから外す（`apexDomain && identity.deviceKid`のみにする、commit `57c3bf6`）。**アーキテクチャ上重要な点として、この regression により core撤去後しばらくの間、DIDComm/mail/group chat/relationshipのすべてが本番で静かに機能停止していた**——typecheck/build/testはすべて通り続けていたにもかかわらずである。これはまさに、§18が指摘する「`main.ts`のboot wiringはbrowser E2Eでカバーされておらず、部品テストの成功と製品経路への接続を区別できない」というリスクそのものが実際に発現した例である。

## 15. Security properties と限界

### 15.1 実装されている主な性質

- Vault object は authenticated encryption、content-derived ID、ciphertext hash で改ざんを検出する。
- Vault event と SegmentKeyWrap は current MLS member device の Ed25519 signature を要求する。
- Device revoke 後の新 epoch は UpdatePath により rekey され、removed member は将来 VEK を導出できない。
- 新規端末は過去 delivery recipient へ遡及追加されない。
- Mail submissionはidentityのcurrent did:webvh update keyによる署名検証を要求し、mailFromが署名者自身のアドレスと一致しない申告を拒否する——別のidentityになりすました送信はできない（§11.2）。
- Mail受信の宛先解決は公開routing.jsonのみに基づき、device roster等の非公開状態を必要としない（§9.1）。
- DIDComm mediator は未登録 recipient への open forwarding を拒否する。
- Relationship ごとの pairwise DID により、継続会話（1:1・group chat 双方）を公開 identity front door から分離する。
- biset-mimi hub は MLS application/handshake message の内容を復号しない（§4.4）。
- Canonical encoding と domain-separated signing/hash labels を protocol 全体で使う。

### 15.2 未解消リスク

1. **Local secret at rest（高）** — master seed、Root private key、DIDComm private cache、SegmentKey が IndexedDB 平文。Passkey/WebAuthn PRF sealing が必要。
2. **Restore UI/boot 未接続（高）** — TTL gap や端末全損時に、実装済みcheckpoint/peer/archive primitive を利用者が起動できない（§9.4）。mail-plugin bridgeの受信経路自体には旧core ingressのようなTTL/quotaという概念はもうないが、mediator queue自体のTTL（30日、§12.4）が尽きた場合の救済経路はやはり接続されていない。
3. **Credential revoke gap（高）** — device revoke だけでは既取得の identity-shared DIDComm/OpenPGP private key を無効化できない。Rotation/republication/re-encryption policy がない。
4. **端末/鍵管理の概念分裂（高）** — Coordinator撤去でSign Key rotationの一括世代交代機構（旧`rotateKeyRotation`）が代替なしに消えた。MIMI room membership（個別device除去）とSpare Key rotationは今なお別々のコードパスであり、統一設計がない（§20）。
5. **OpenPGP mail E2EE 未接続（中）** — 鍵を公開するため相手は暗号化可能だが、通常 UI が復号しない。公開 capability と製品挙動が一致しない。
6. **Relationship handshake 非永続（中）** — reload で ACCEPT を復号不能にする。DIDComm group chatのmesh-completion handshakeも同じ揮発性state（`pendingByOwnKid`/`pendingByCounterparty`）に乗るため、同じ制約を受け継ぐ（§12.2、§12.6）。
7. **DIDComm dedupe lookup 未接続（中）** — projector の `alreadyProcessed()` は常に false。同一 message ID は reducer conflict で拒否されるが、静かな idempotent skip ではない。
8. **Routing update race（中）** — ETag/CAS なし。複数端末同時更新で field loss の可能性。
9. **Domain multi-hop adoption（中）** — 一 boot 一 hop、中間 domain 廃止で停止。
10. **DIDComm group chatのクロスデバイスroster未同期（中）** — `group-chat-store.ts`はdevice-localなIndexedDBキャッシュであり、同一identityの複数端末間でグループroster自体は同期されない（v1の既知の受容済み制約）。
11. **DIDComm group chatとMIMI Self Vaultの機構重複（低〜中、未調査）** — 両者とも「暗号化した内容をhub経由で複数宛先に配る」を別々のchunk機構・別々のretry設計で解いている。共有可能な部分の有無は未調査のまま残る（§3.1、§20）。
12. **No background/push（運用）** — page が閉じている間は pull せず、mediator queueのTTL（30日）を越えると restore が必要。
13. **Mediator relay-poller/DB write failureの挙動未検証（運用）** — SQLite化後のDB書き込み失敗時の扱いは本調査では未確認（§12.4）。
14. **core撤去後の死んだfallbackコード（低、新規）** — `bootstrap.ts`の`opts.coreBaseUrl`起点のroutingフォールバック文字列生成（§12.1）、`main.ts`の`CoreIngressTransport`/`CoreVaultDeliveryTransport`（§9.3、§12.5）、`buildMailSubmitter`が使う`CoreMailSubmissionTransport`という名前（§11.2）は、いずれも実害はないが「coreはまだ動いているのか」を次にこのコードを読む人が調べ直す原因になる。§20参照。
15. **gitignore対象のtracked外test file（運用、既知）** — `test/`配下に実在する149個の`*.test.ts`のうち、gitで実際にtrackedなのは113個のみで、残り36個（約33%）は`.gitignore`が隠すuntracked fileである。`bun run test`（`find test -name '*.test.ts'`）は両方を区別せず実行するため製品側の検証自体には支障がないが、`git worktree`ベースの隔離環境（このARC.md自体の調査を含む）はuntracked fileをコピーしないため、worktree内でのtest実行・ファイル数カウントは常にこの36個を欠いた過小な結果になる。§18参照。

## 16. Protocol versioning

Wire record は原則 `version: 1` を持ち、decoder は shape、canonical serialization、hash、署名、identity/epoch binding を検証して fail closed する。Opaque ID は domain-separated hash または UUID として扱う。

互換性を保つ際は、TypeScript union に event kind を追加するだけでは不十分である。Wire decoder の allow-list、Vault reducer の explicit no-op/application rule、archive decoder、delivery projector、テスト fixture を同時更新する必要がある。`src/protocol/vault.ts`の`VAULT_EVENT_KINDS`を`vault/delivery-pack.ts`のdecoderが直接参照する現行の実装は、この cross-layer checklist を単一の正本へ収束させた一例である（§8.1）。

legacy core Vault delivery（§9.3）とMIMI Self Vaultの並存は、biset-core撤去によりサーバー側の実体を失った点で、旧ARC.mdが記述していた「並存」から「片方が死んでいるコードの並存」へ性質が変わった。廃止（コード削除）する際は、§15.2のリスク14に挙げた各所を一括で取り除く必要がある——中途半端に一部だけ削除すると、残った箇所が動かない前提でconfigを参照する形になりかねない。

## 17. Build、設定、運用

### 17.1 Client

- `bun run build` — `src/client/app/main.ts` と `src/client/app/sw.ts` を browser IIFE に bundle し、`scripts/inline.mjs` で `dist/index.html` に inline 化する。
- Runtime config — `window.__BISET_CONFIG__` の `apexDomain`、`mediatorUrls`、`mimiSelfBaseUrl`。旧native login用の`anchorBaseUrl`と`anchorOidcClientId`は削除済み。
- `enableDidComm` は **2026-09-05 の native login 削除で消えた**。identity 全体の X25519 provisioning、
  `#routing` ポインタの publish、mediator 登録はいずれも biset 側から行われなくなり、
  DIDComm の device enrollment は did.md Wallet の認可フローが担う（§3.2）。
  したがって「`mediatorUrls` 未設定時に動作しない URL を routing.json へ publish する」という
  旧来の失敗モードも同時に消滅した——biset は routing.json を書かない。
- `mimiSelfBaseUrl` が未設定であれば MIMI Self Vault 機能全体が起動しない。
  かつてそこから分岐していた legacy core Vault delivery 相当の経路はサーバー側実体を欠いたまま削除された。
  production config は `mediatorUrls`・`mimiSelfBaseUrl` のいずれも設定済みである。

### 17.2 （削除済み）Anchor environment

Anchor は 2026-09-05 に削除された（`74864ff` `c26db16`）。`ANCHOR_DATA_DIR` / `ANCHOR_DOMAIN_HEADER` /
`bun run build:anchor` / `biset-anchor.service` / `deploy.sh` の `anchor` ターゲットは、いずれも存在しない。
identity のホスティングは did.md が行う（§3・§13.1）。

> 節番号は後続節の参照を壊さないために残してある。

### 17.3 Mediator / mail-plugin environment

"A"（`src/server/mimi/index.ts`）と"B"（`src/server/mimi/index.ts`）は共通の変数セットに加え、"B"だけが追加変数を要求する。**両者は同じ`biset-didcomm-mediator.service`/DBを奪い合う排他ターゲットであり、どちらか一方だけが本番で動く**（deploy.shコメント。§3・§13.4）。core retirement後の現行方針（2026-09-03時点）では"B"（mail-plugin）が本番稼働中。

共通:

| 変数 | 必須性 / 既定 |
|---|---|
| `MEDIATOR_PUBLIC_URL` | 必須 |
| `MEDIATOR_DATABASE_PATH` / `MEDIATOR_DATA_DIR` | いずれか必須（SQLiteファイルパス） |
| `PORT` | 既定 8791 |
| `MEDIATOR_HOST` | 既定 `127.0.0.1` |
| `MEDIATOR_ALLOWED_ORIGINS`、`MEDIATOR_MAX_REQUEST_BYTES`、`MEDIATOR_RATE_LIMIT_PER_MINUTE`、`MEDIATOR_MAX_CONNECTIONS`、`MEDIATOR_MAX_KEYS_PER_CONNECTION`、`MEDIATOR_MAX_QUEUE_ITEMS`、`MEDIATOR_MAX_QUEUE_BYTES`、`MEDIATOR_MAX_MESSAGE_BYTES`、`MEDIATOR_QUEUE_TTL_MS`、`MEDIATOR_REPLAY_TTL_MS`、`MEDIATOR_MAX_REPLAY_IDS` | いずれも既定値ありの運用チューニング。**`MEDIATOR_ALLOWED_ORIGINS`は"B"の`/v1/mail/submit`のCORSチェックにも同じ値が再利用される**（§13.2） |
| `MEDIATOR_RELAY_UPSTREAM_URL` | 任意。設定すればmulti-hop relay pollerを起動する（§12.4） |

"B"追加分（`src/server/mimi/index.ts`）:

| 変数 | 必須性 / 既定 |
|---|---|
| `MAIL_PLUGIN_APEX_DOMAIN` | 必須 |
| `MAIL_PLUGIN_SMTP_HELLO_NAME` | 既定 `mail.{apexDomain}` |
| `MAIL_PLUGIN_SMTP_HOST` | 既定 `0.0.0.0` |
| `MAIL_PLUGIN_SMTP_PORT` | 既定 25 |
| `MAIL_PLUGIN_MAX_MESSAGE_BYTES` | 既定 25 MiB |
| `MAIL_PLUGIN_TLS_CERT_PATH`, `MAIL_PLUGIN_TLS_KEY_PATH` | 両方あれば inbound STARTTLS |
| `MAIL_PLUGIN_SUBMIT_HOST` | 既定 `127.0.0.1` |
| `MAIL_PLUGIN_SUBMIT_PORT` | 既定 8792 |

`bun run build:didcomm-mediator`（`build:mediator`のalias）で"A"、`bun run build:mail-plugin`で"B"のLinux x64 binaryを生成する。

### 17.4 MIMI environment

| 変数 | 必須性 / 既定 |
|---|---|
| `MIMI_DATABASE_PATH` | 必須 |
| `MIMI_MODE` | 必須。`normal` または `anon`（`self`はdeployment.tsの`mode`オプション経由——index.tsのCLI env経路自体は`normal`/`anon`しか受け付けない点に注意） |
| `MIMI_PUBLIC_BASE_URL` | 任意。protocol directoryが広告する公開origin |
| `MIMI_ALLOW_EXTERNAL_JOIN` | 既定false。`true`でSelf Group向けexternal join（`POST /groupInfo`）を有効化 |
| `PORT` | 既定 8793 |

`bun run build:mimi` で Linux x64 binary を生成する。

### 17.5 デプロイターゲット（deploy.sh）

`./deploy.sh [app|landing|anchor|didcomm-mediator|mail-plugin|smtp|ap|relay|all]`（引数なし = `all`）。`app`はdist/index.htmlをt.biset.mdへ、`landing`はhome/をbiset.mdへ、`anchor`はbiset-anchor binaryを、`smtp`/`ap`は`~/biset/jmapsmtp`（Rust）と`~/go-jmapap`（Go）という biset repo 外のrelay実装をそれぞれ配る。`didcomm-mediator`と`mail-plugin`は前述の通り排他ターゲットであり、**両方とも`all`から除外されている**（旧biset-coreも同じ理由で`all`から除外されていた——`all` = `app`, `landing`, `anchor`, `smtp`, `ap`のみ）。

## 18. 検証状況とコード品質

対象 commit（`5b9f1fa`）で以下を実行した（2026-09-04、worktree上で再実行、数値はすべて実測）。

- `bun run typecheck` — `tsc --noEmit`（root/browser）+ `tsconfig.mediator.json` + `tsconfig.mail-plugin.json` + `tsconfig.mimi.json` の**4設定**すべて成功。かつての6設定から、core 撤去（`tsconfig.core.json`）と Anchor 削除（`tsconfig.anchor.json`）で2つ減った。
- `bun run reachability` — 本番エントリからの到達可能性を検査する。knip はテストが import したファイルを "used" と見なすため、「テストからしか到達されない＝本番では動いていない」層を捕まえられない。この差を埋めるための独自チェック（`scripts/reachability.mjs`）。
- `bun run build` — 成功。`app.js` 1.1 MB、`sw.js` 183 bytes、inline HTML 1188 KB（ビルドツール自身の出力値。前回調査の約1195KBからほぼ変わらず、わずかに減少——core関連コードのbundleからの除去とmail-plugin側コードの追加が相殺した程度と見られる）。
- `bun run test` — `find test -name '*.test.ts'` で数えて **111個** の `*.test.ts` fileを serial 実行し、すべて成功（exit code 0、非ゼロの `fail` 行なし）。ただし `git ls-tree -r HEAD` でtracked扱いなのは113個のみで、残り36個はgitignore対象のuntracked file（このセッション以前から既知の状態——git worktreeはgitignore対象untracked fileをコピーしないため、worktree内での実測はこの36個を欠いた113個になる。本節の数字は実際のmain working tree（`/Users/n/biset`）で直接実行した結果を採用した）。coreディレクトリごと削除されたことに伴うtest減少は実際には起きておらず、旧`test/core/*`相当のファイルが個別に削除された一方、mail-plugin関連の新規testが追加されたことで純増になっている。gitignore対象のtracked外test fileが33%を占める状態自体は、依然として未解消の運用上の負債である（§15.2・§20参照）。

テストは canonical protocol、Vault crypto/store、DIDComm crypto/mediator/private relationship/group chat mesh、mail-plugin bridge/listener、SQLite、Self Vault MLS、domain move、SMTP、OpenPGP primitive、MIMI Vault sync/chunks/client transport/room/session/room-migrationを広く覆う。`test/vault-mimi-sync.test.ts`は意図的に一部エラーログ（undecryptable application entry、checkpoint chunk不足）を出力しながらpassする——それらは§9.2の各recovery strategyが正しくgapとして記録して回復することを検証するテストである。一方、`main.ts` の boot wiring を browser E2E として網羅しておらず、「部品のテスト成功」と「製品経路への接続」を検出できていない——§14の coreBaseUrl gate regression はまさにこの隙間から本番へ出た実例である。

`bun run knip` は失敗する（exit code 1）。現状の debt は次のとおりである。

- unused files: **2**（いずれも `src/protocol/mls/` 配下の vendored fork。upstream diff を保つため意図的に残している）
- unused dependencies: 5（`@scure/bip32`、`bittorrent-dht`、`cborg`、`hash-wasm`、`jmap-jam`）——変化なし。
- unused devDependencies: 2（`@hpke/core`、`@types/wicg-file-system-access`）——変化なし。
- unlisted binaries: 2（`tsc`、`knip`）——変化なし。
- unresolved imports: 4（`scripts/pkarr-smoke.mjs`が参照する`src/did/keys.ts`等4ファイル——旧did:dht/Pkarr実装の残骸。did:webvh一本化後もこのスクリプトだけ削除されずに残っている）——変化なし。
- unused exports: **325**、unused exported types: **192**。大半は `src/protocol/mls/`（RFC 9420 fork、触らない方針）である
- configuration hints: 4（`deploy.sh`のignoreBinaries、`src/anchor/index.ts`/`src/server/mimi/index.ts`/`src/server/mimi/index.ts`のentry pattern重複——前回調査の`src/core/index.ts`が`src/server/mimi/index.ts`に置き換わった）。

したがって `bun run check`（typecheck && knip && test）は typecheck/test が正常でも knip で非 zero になる。unused filesが微増しているのは、core撤去・Conversation Groups撤去に伴う未使用コードの掃除が引き続き追いついていないことを示す。

## 19. 実装状態の総括

| 領域 | 状態 | 判定 |
|---|---|---|
| did:webvh **解決** | UI/boot に接続。`src/protocol/webvh/` の resolver 系 | 実装済み |
| did:webvh create/update/pre-rotation/domain move | **削除済み**（2026-09-05）。発行は did.md の責務 | 廃止 |
| Self Vault MLS group、roster、individual device removal、VEK | UI/boot と biset-mimi(self) に接続 | 実装済み |
| Local encrypted Vault + JMAP projection | UI read/write に接続 | 実装済み |
| Mail 受信（mail-plugin SMTP bridge、push型） | **クライアント側の配線が削除された**（2026-09-05）。mediator 側は稼働 | 部品実装済み（W3⑤で再配線予定） |
| Mail 送信（mail-plugin 署名submission） | **クライアント側の配線が削除された**（2026-09-05）。mediator 側は稼働 | 部品実装済み（W3⑤で再配線予定） |
| MIMI Self Vault delivery | poll/SSE watch/outbox/gaps report まで UI に接続 | 実装済み |
| Self Vault checkpoint | 作成・復元とも接続。KEK は MLS self-group の VEK（§9.4） | 実装済み（W5、`da6bfcf` `74358bb`） |
| ~~Mnemonic login~~ | ~~identity/device join~~ | **廃止**（2026-09-05、`7357830`） |
| ~~Anchor OpenID4VP login~~ | ~~Verifier、credential、session、Wallet enrollment~~ | **廃止**（2026-09-05、`74864ff`） |
| **did.md Wallet login** | OAuth + DPoP-bound device session、boot の唯一の入口 | 実装済み |
| ~~Peer/archive restore~~ | ~~primitive と test あり、UI/boot なし~~ | **削除**（2026-09-05、R2） |
| ~~OpenPGP~~ | ~~key provision/publication/crypto primitive~~ | **削除**（2026-09-05、R2。record 型のみ残存） |
| DIDComm public front door | UI/boot に接続。legacy fallback文字列生成は残るが動作しない | 実装済み |
| Standalone mediator（"A"/"B"、SQLite永続化） | binary、protocol、SSE watch、relay-poller あり | 実装済み、"B"が本番稼働中 |
| Private relationship DIDComm 1:1 | 送受信・関係確立（INIT/ACCEPT）とも動作。送信 outbox と10秒再送あり | 実装済み（W3、`0aced81` `cbd73af`） |
| DIDComm group chat | 作成・招待・fan-out・受信・roster 表示まで接続 | 実装済み（W3、`9a9e6cf`） |
| ~~MLS Conversation Groups~~ | ~~ソース削除済み~~ | 廃止（2026-09-03） |
| ~~biset-core~~ | ~~ソース削除済み（`src/core/`ごと）~~ | 廃止（2026-09-03、commit `99e08c0`） |
| biset-mimi normal/anon（一般group chat hub） | サーバーとして稼働、client呼び出し経路なし | 部品実装済み |
| Multi-device product experience | Self Vaultにより大きく前進したが、account switching・端末/鍵管理の統合は未完成 | 部分実装 |
| Remote JMAP account | transport/router のみ | 部品実装済み |
| ActivityPub | adapter なし | 未実装 |
| Web Push / background sync | Service Worker shell のみ | 未実装 |

## 20. 推奨する次の作業順

2026-09-06 時点。R2/R3/R4 の再構成と N1 の機能削除を経た後の優先順位である。

1. **メールの再実装**（最大の欠落）。現在クライアントにメールは無い。
   アドレス採番と送信署名鍵を mediator の責務として設計する方針は決まっており（§11.2）、
   設計案は `tasks/W3-wallet-mail-design-proposal.md` にある。
   **実装には did.md 側の mediator が必要で、このリポジトリ内では完結しない**
2. **実機での動作確認**。N1 以降、この構成で `dist/index.html` を `file://` で開いた確認が取れていない。
   typecheck / test / build はすべて通っているが、それは「起動して使える」ことの証明ではない
3. **全端末喪失時の復旧手段が無いことを利用者に伝える**（§9.4）。
   現状 Vault カードに skip の詳細が出るだけで、警告は無い
4. **端末/鍵管理を1つの概念に統合する**。「Self Vault room の member = この identity の端末」を
   唯一の真実として、追加・削除・ローテーションを1つの API にまとめる。
   MLS self-group の世代ローテーションは Coordinator 撤去の巻き添えで消えたまま（§19）
5. **Relationship handshake を crash-safe にする**（`pendingByOwnKid` / `pendingByCounterparty` が
   メモリ上にしかない。§15.2 のリスク）
6. **Device revoke 後の credential rotation を crash-safe にする**（§15.2 のリスク3）
7. **`main.ts` の boot wiring に対する統合テスト**。配線ミス由来のバグは現状 実機でしか見つからない
8. **`bun run check` を release gate として通す**。`bun run reachability` は既に組み込み済み

> かつてここに挙げていた「OpenID4VP の consent UI」「core 撤去後の死んだ fallback 削除」
> 「Peer restore / archive を UI へ接続」は、いずれも**対象そのものが削除された**ため消滅した。

## 21. `src/` の構成

2026-09-06 の再構成（R2/R3/R4）後の姿である。トップレベルは **client / server / protocol** の三つだけで、
`shared/` も `vendor/` も存在しない。

```
src/
  client/     クライアント本体（ブラウザ）
    app/        起動・配線・UI
    store/      Vault と projection
    identity/   did.md Wallet セッションと did:webvh の client 側
    didcomm/    client 専用の DIDComm
    mls/        MLS group 層（Self Vault の実体）
    mimi/       MIMI クライアント
  server/     mediator（mail-plugin を内包）と MIMI サーバー（Bun）
  protocol/   wire 定義。使用者ではなく内容で命名する
```

### 21.0 なぜこの形なのか

かつての11ディレクトリは**デプロイ先・レイヤ・プロトコルという3つの軸が1階層に潰れており**、
新しいファイルをどこに置くべきかが構造から決まらなかった。

R3 でいったん `shared/` を作ったが、これは**使用者で命名されたバケツ**であり、実測すると
38ファイル中10が client からしか、4が server からしか到達しない——共有物ですらなかった。
本当に両側が使う23ファイルは**プロトコル線できれいに割れており**、
内容で命名し直すことで**重複ゼロで `shared` を廃止できた**（R4）。

**依存の向きは一方向である。**

```
client/ ──→ protocol/ ←── server/
```

`protocol/` と `server/` は `client/` を**参照しない**。これは機械的に検証できる:

```bash
grep -rnE "^\s*import .*from '[^']*\.\./(\.\./)*client/" src/protocol src/server --include='*.ts'
grep -rnE "^\s*import .*from '[^']*\.\./(\.\./)*server/" src/protocol --include='*.ts'
```

**この2つが空であることが構造の不変条件である。** 破れたら構成が壊れている。

### 21.1 `protocol/` — wire 定義

client と server の**両方**が使うものだけがここにある。どちらか一方しか使わないものは、
使う側へ置く（それが R4 の判定基準だった）。

| ファイル | 責務 |
|---|---|
| `canonical.ts` | 正準 JSON とバイト列化。**client・mediator・MIMI サーバーの3者すべてが使う唯一のファイル**。全署名対象の土台 |
| `ids.ts` | identity / device / ingress / segment などの ID 型 |
| `vault.ts` | Vault の event 種別と wire 型 |
| `signing.ts` | 各操作の署名対象バイト列 |
| `ingress.ts` | 短命な外部 payload。mailbox レコードではない |
| `mail-submission.ts` | mail 送信要求の型 |
| `net-fetch.ts` | `fetch` を裸の変数へ持ち出すときの束縛を保つラッパ。protocol クライアントと server の双方が使う |
| `test-vectors.ts` | 正準 JSON のテストベクタ |

**`protocol/didcomm/` — DIDComm プロトコル（client と mediator が使う）**

`crypto.ts`（JWE 構築、525行）、`message.ts`（平文エンベロープ）、`peer.ts`（did:peer:2）、
`devicekid.ts`（鍵から導出する識別子）、`multikey.ts`、`problems.ts`（Report Problem 2.0）、
`forward-wrap.ts`（Anoncrypt-Forward 包み）、`mediator-protocol.ts`（型 URI）、
`mediator-coordinate.ts`／`mediator-pickup.ts`／`mediator-transport.ts`（Coordination 2.0 / Pickup 3.0 / 転送）、
`webvh-routing.ts`／`webvh-resolve.ts`（routing.json とその合成）。

**`protocol/mimi/` — MIMI プロトコル（client と MIMI サーバーが使う）**

`protocol-types.ts`（room/user/client URI 型）、`wire.ts`（JSON + base64url 境界）、
`authorizer.ts`（provider 内部 credential 署名）、`app-data.ts`（MLS TLS 符号化の application component）。

**`protocol/webvh/` — did:webvh（client と mail-plugin が使う）**

`resolver.ts`（解決）、`log.ts`（DID Log 検証）、`proof.ts`（Data Integrity Proof、eddsa-jcs-2022）、
`document.ts`（W3C DID Core の形）、`identifier.ts`（識別子解析と DID→HTTPS 変換）、
`scid.ts`／`hash.ts`／`multihash.ts`／`multikey.ts`／`jcs.ts`（SCID 検証、ハッシュ、multiformats、RFC 8785）。

> mail-plugin が署名検証とアドレス判定に did:webvh を使うため、**これは client 固有ではない**。
> R4 の実測で13ファイル中10が mediator からも到達することが判明し、ここへ移した。

**`protocol/mls/` — RFC 9420 の vendored fork（98ファイル）**

client（Self Vault）と server（MIMI）の**両方**が使う。差分には `// biset:` marker があり `VENDOR.md` に記録される。
**中身は一切変更しない。** knip がこのディレクトリの unused export を報告し続けるのは**正常**であり、
中身を触らないことだけが upstream との差分を追える状態を保つ。

### 21.2 `client/app/` — 起動、配線、UI

| ファイル | 責務 |
|---|---|
| `main.ts` | 唯一のエントリポイント。boot からポーリング登録、UI へのハンドラ供給までの全配線 |
| `sw.ts` | Service Worker の外殻。install/activate のみ |
| `ui/shell.ts` | 画面の切り替えとページ表示の骨格 |
| `ui/left-pane.ts` | 会話一覧 |
| `ui/thread.ts` | スレッド表示と返信欄 |
| `ui/compose-page.ts` | 新規作成画面 |
| `ui/account-page.ts` | アカウント画面本体 |
| `ui/account-create.ts` | `#new` の新規オンボーディング。現在は did.md Wallet ログインのみ |
| `ui/account/state.ts` | アカウント画面のモジュール状態の唯一の所有者 |
| `ui/account/menu.ts` | identity のドロップダウンメニュー |
| `ui/account/config-page.ts` | 設定画面 |
| `ui/config.ts` | `window.__BISET_CONFIG__` を読む唯一の場所 |
| `ui/format.ts` | 表示ヘルパ（エスケープ、リンク化、時刻、引用除去、プレビュー） |
| `ui/did-display.ts` | DID を人間に見せるときの共通規則 |
| `ui/message/message-view.ts` | メール形 read model からスレッドを組み立てる |
| `ui/message/body-text.ts` | 本文の平文抽出 |
| `ui/message/rfc5322-headers.ts` | RFC 5322 ヘッダの読み取り |

> `ui/message/` の3ファイルは**メール転送ではなく表示**である。DIDComm メッセージはメール形の
> read model へ projection されるため、その描画に使う（§10）。メール転送は 2026-09-05 に削除された（§19）。
> かつて `client/app/mail/` にあったが、利用者が `ui/thread.ts` と `ui/left-pane.ts` だけであることを
> 確認して `ui/` 配下へ移した（2026-09-06）。

### 21.3 `client/store/` — Vault と projection

かつて `vault/` と `local-jmap/` に分かれていたが、**双方向の循環依存**（12/8）が
「1つの関心事を分けた結果」であることを示していたため統合した（R3）。

**`store/vault/` — 暗号化された長期正本**

| ファイル | 責務 |
|---|---|
| `store.ts` | IndexedDB 永続化層。object / event / key wrap / outbox を1つのトランザクション境界で扱う |
| `objects.ts` | 暗号化 object の封入と復号、SegmentKey 生成 |
| `events.ts` | immutable event の署名・検証 |
| `manifest.ts` | Merkle manifest と差分検出 |
| `crypto.ts` | VEK による SegmentKey の wrap と検証 |
| `active-segment.ts` | 書き込み可能な現行 segment の決定と検証（`assertActiveVaultSegment`） |
| `segment-key-resolver.ts` | MLS アダプタ境界。VEK は一時的で永続化しない |
| `storage-root.ts` | endpoint 専用の安定 KEK |
| **`commit.ts`** | **共有 Vault 状態を書く全経路が通る唯一の組み立て地点**。ここを迂回して delivery pack を直接作る本番コードがあってはならない |
| `mutations.ts` / `mutation-records.ts` | mutation の build と、検証してから復号する共通ステップ |
| `mail-message.ts` | メール形メッセージの event/object 生成 |
| `credential-store.ts` | private credential の汎用 reader / sink。4系統がこの1実装に記述子を渡す |
| `contact-key{,-reader,-sink}.ts` | ペアワイズ関係鍵（`ContactKeyV1`） |
| `didcomm-credential.ts` / `didcomm-device-key{,-reader,-sink}.ts` | DIDComm 鍵とデバイス対応 |
| `openpgp-credential.ts` | OpenPGP 鍵の指紋正規化 |
| `delivery-pack.ts` / `delivery-ingest.ts` / `delivery-projector.ts` | 共有 delivery の正準ボディ、検証、projection |
| `ingress-ingest.ts` | 外部 ingress の確定 |
| `mimi-vault-sync.ts` | Vault と MIMI のデータプレーン境界。`gaps` による構造化された欠落報告 |
| `mimi-vault-chunks.ts` | MLS application message に載せる不透明チャンク |
| `vault-checkpoint.ts` | checkpoint の封入と復元。KEK は MLS self-group の VEK（§9） |
| `recovery-archive{,-export,-rewrap}.ts` | 利用者が持つ独立の秘密による archive。snapshot 生成は checkpoint 作成にも使われる |
| `projection-rebuild.ts` | 全 projection の再構築（災害復旧経路） |
| `blob-reader.ts` | SegmentKey をメモリ上で解決する |

**`store/projection/` — UI が読む JMAP 形の read model**

`gateway.ts`（型）、`reducer.ts`（検証済み event から決定的に組み立てる）、`indexeddb.ts`（永続化）、
`mutations.ts`（`Email/set` を Vault mutation intent へ）、`vault-mutation-sink.ts`（書き込み橋）、`transport.ts`。

### 21.4 `client/didcomm/` — client 専用の DIDComm

R4 の実測で、**どのサーバーからも到達しない**ことが確認された10ファイル。
`protocol/didcomm/` とは別で、こちらは Vault と結合している。

| ファイル | 責務 |
|---|---|
| `send-message.ts` | 送信の入口。routing.json 解決から発送まで |
| `front-door-send.ts` | Vault 非依存の送信半分 |
| `relationship.ts` | ペアワイズ関係の確立（INIT / ACCEPT） |
| `basicmessage.ts` | Basic Message 2.0 |
| `trust-ping.ts` | Trust Ping 2.0 |
| `ingress-projector.ts` | 受信の鍵選択と Vault への projection |
| `group-chat.ts` | フルメッシュのグループチャット |
| `group-chat-store.ts` | グループ roster の端末ローカル保管（IndexedDB） |
| `mediator-sync.ts` | mediator 登録の self-heal と poll ループ |
| `mediator-watch.ts` | 1つの mediator からの SSE ライブ配送 |

### 21.5 `client/identity/` と `client/mimi/`

**`client/identity/`** — `bootstrap.ts`（Vault 側の identity 境界。MLS epoch 鍵、SegmentKey wrap、各種 reader/sink の組み立て）、
`idkey.ts`。

`identity/wallet/` — `did-md-oauth.ts`（**did.md OAuth。アプリへの唯一の入口**）、
`did-md-store.ts`（device session の暗号化保管）、`relationship.ts`（Wallet 起点の関係確立）、
`didcomm-outbox.ts`（送信 outbox と再送）。

`identity/webvh/` と `identity/web/` — `log-io.ts`（client からのみ使う log 入出力）と、
`create-genesis.ts` / `migrate.ts` / `web/*`（**本番から到達しないが、
残す側のコードのテスト3件が実物の did:webvh log を組み立てる唯一の手段**として使っている）。

**`client/mls/`** — MLS group 層。Self Vault の実体である。

| ファイル | 責務 |
|---|---|
| `group.ts` | biset の MLS group 操作。RFC 9420 の表面全体 |
| `store.ts` | MLS self-group 状態の永続化。**Self Vault の MIMI room metadata も同じ行に持つ**（re-key で両方が一緒に運ばれるための意図的な設計）。その永続化レコード型もここが所有する |
| `identity.ts` | MLS leaf が何を主張し、それが biset identity にどう対応するか |
| `device-credential.ts` | identity と MLS leaf 署名鍵の Root 認可された結び付き |
| `webvh-authentication-service.ts` | MLS Authentication Service。current WebVH 鍵でのみ leaf を承認する |
| `vault-epoch.ts` | MLS exporter から VEK を導出する境界。**現行 epoch でしか鍵を返さない**（forward secrecy） |
| `segment-key-membership.ts` | MLS デバイス鍵を Vault の2種類の検証質問へ適合させる |
| `keypackage-store.ts` | この端末自身の KeyPackage 秘密鍵。現行 Self Vault は external join を使うため未配線 |

**`client/mimi/`** — MIMI クライアント。

| ファイル | 責務 |
|---|---|
| `vault-room.ts` | 単一利用者の Self/Vault MIMI room の作成 |
| `vault-session.ts` | Vault データプレーンが使う永続的な MLS/MIMI セッション |
| `vault-watch.ts` | Self/Vault room の SSE ライブ配送 |
| `client-transport.ts` | MIMI provider のクライアント境界へのブラウザ側トランスポート |
| `client-routing.ts` / `room-migration.ts` | deployment 選択と anon room への移行。未配線 |

> **依存は `mimi/` → `mls/` の一方向**である。逆向きはゼロ:
> ```bash
> grep -rn "from '\.\./mimi/" src/client/mls --include='*.ts'   # 空であるべき
> ```
> 2026-09-06 の分割前は `mls/store.ts` が session の型を import しており逆流していた。
> それらの型は**この store が書く形の定義**なので store 側へ移し、方向を揃えた。

### 21.6 `server/`

**`server/mediator/`** — `index.ts`（本番エントリ "A"）、`deployment.ts`（合成）、
`server.ts`（Coordinate Mediation 2.0 / Routing 2.0 / Pickup 3.0）、`sqlite-store.ts`、`queue.ts`、
`connections.ts`、`keycache.ts`、`relay-poller.ts`（多段中継）、`signature.ts`、`replay.ts`、
`rate-limit.ts`、`watch-token.ts`、`route-deliver.ts`、`validate.ts`。

**`server/mediator/mail-plugin/`** — `index.ts`（本番エントリ "B"）、`listener.ts`、
`smtp-socket-server.ts`（`Bun.listen`/STARTTLS）、`mail-smtp-protocol.ts`（ソケット非依存の状態機械）、
`bridge.ts`（SMTP → DIDComm）、`smtp-client.ts`（outbound）、`mail-submission-http.ts`（`POST /v1/mail/submit`）、
`mail-bridge.ts`／`mail-submission-wire.ts`（wire 形）。

**`server/mimi/`** — `index.ts`／`deployment.ts`、`http.ts`、`store.ts`、`mls-appsync.ts`、
`mls-group-info-bootstrap.ts`、`group-info.ts`、`franking.ts`、`fanout.ts`／`federation.ts`、
`directory.ts`／`provider-directory-client.ts`／`provider-transport.ts`／`mimi-uri.ts`、
`room-policy.ts`、`asset-proxy.ts`、`watch-token.ts`、`anon/{identity-link,pseudonym}.ts`。

### 21.7 構成上の課題（すべて解消済み）

R3/R4 時点で挙げていた3件は、いずれも 2026-09-06 に解消した。

| 課題 | 解消 |
|---|---|
| `shared/didcomm/group-chat-store.ts` がブラウザ専用なのに shared にある | R4 で `client/didcomm/` へ |
| `client/mimi/` の大半が MIMI ではなく MLS | `client/mls/` へ分割。`mimi-` の冗長な接頭辞も除去 |
| `client/app/mail/` がメール転送を想起させる | `client/app/ui/message/` へ |

