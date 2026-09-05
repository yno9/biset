# Biset アーキテクチャ

> MLS の vendored fork（ciphersuite、UpdatePath fix、vendor diff の一覧）については `src/mls/vendor/VENDOR.md` と本書§13を参照する。かつて存在した `ARC-MLS.md` は Coordinator 完全撤去（2026-09-03、commit `57ffa67`）以前の調査で、中心的な二節が存在しないサブシステムを説明していたため 2026-09-05 に削除した。Self Group/Vault の現行の配送経路は本書§6・§9で説明する biset-mimi Self Vault である。

> 調査基準日: 2026-09-05（Asia/Tokyo）
> 調査対象: `~/biset` の commit `5ab136a`。前回基準 `5b9f1fa` からの最重要変更は二つ——
> **Anchor の完全削除**（`74864ff` `c26db16`）と **native login（seed 由来 identity 層）の削除**（`dd5a0cd` `71336b9` `7357830`）。
> `src/anchor/` も `src/oid4vp/` も `src/oidc/` も存在せず、identity provider は外部の did.md に移った。
> 状態: 現行コードを正とした実装アーキテクチャ。将来案は明示的に区別する。
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
- device rosterに基づくmail ingress-pull認可、legacy Vault delivery、legacy DIDComm ingress fallback → **後継なしに消滅**。roster機構自体（`rosterBackedVaultDeliveryAuthorizer`、`ensureMimiCoreRoster`、`src/mls/self-group.ts`のroster projection関連コード）も削除された。mail認可はdid:webvh update keyの署名検証へ置き換わり（§11.2）、legacy Vault delivery/DIDComm ingressはMIMI Self Vault/standalone mediatorへの移行が既に完了していたため、コード上は「production configが指さないfallback」として一部残っているだけである（§9.3、§12.1、§12.5）。

## 2. 設計原則と非目標

### 2.1 原則

- 長期正本は各 endpoint の暗号化 Vault であり、mediator や biset-mimi ではない。Coordinatorという別プロセスは存在しない——複数端末間の Vault 同期は biset-mimi の Self Vault（後述、§3・§9）が担う。
- Standalone mediator（および mail-plugin deployment variant）が保持するのは、DIDComm の blind queue と SMTP 境界の metadata に限る。Vault plaintext、SegmentKey、MLS exporter secret、OpenPGP private key は知る必要がない。**biset-core が担っていた device roster・TTL/quota 付き ingress バッファ・legacy Vault delivery は 2026-09-03 の core 撤去で後継なく消滅した**（§9.1・§9.3）。
- UI と保存層の間には JMAP 形のローカル API を置き、暗号方式を UI へ漏らさない。
- MLS は user-to-user のチャット本文暗号化には使わない（それは DIDComm の役割）。一方、同じ identity の信頼済み端末集合を表す Self/Vault MLS group は、Vault mutation を運ぶ暗号文チャンクそのものを MLS PrivateMessage/PublicMessage として運ぶ——「MLSはVEK導出境界だけに使う」という旧原則は、biset-mimi 移行後は成り立たない。VEK（Vault Epoch Key）は依然としてこの MLS exporter secret から導出し、SegmentKey の epoch-wrap 境界として使う。
- 外部 ingress を ACK するのは、端末で検証・暗号化・永続化が完了した後だけとする。mail-plugin bridge の inbound mail は「ACK」という独立概念を持たず、DIDComm Forward としてmediator queueへ積まれた時点で標準の DIDComm 受信パイプラインに合流する（§9.1・§12.5）。
- 復旧に必要な履歴本体を biset のサーバーに置かず、biset-mimi Self Vault の checkpoint、信頼済み peer、
  または利用者管理の暗号化 archive から取得する。**ただし3経路のうち実際に動いているのは checkpoint だけであり、
  その checkpoint も 2026-09-05 の native login 削除で KEK（`masterSeed` 由来）を失って停止している**（§19）。
  peer restore と archive import は部品はあるが配線がない。
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
│identity provider ││"A" = src/mediator/index.ts単体                 ││このidentityのSelf Vault用。 │
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

1. **Mediator** — DIDCommの一時配送（store-and-forward）。`src/mediator/index.ts`を入口とする"A"（素のmediator）と、
   それに加えてSMTP inbound listener + outbound submission HTTPを同梱する`src/mediator/mail-plugin/index.ts`入口の"B"の、
   二つのdeployment variantがある。本番は"B"（mail-plugin同梱）が稼働中（`mediator.biset.md`）——
   同じ`biset-didcomm-mediator.service`とSQLiteを二つのバイナリが奪い合う排他関係であり、
   deploy.shの`didcomm-mediator`/`mail-plugin`ターゲットはどちらか一方だけをデプロイする（§17.3）。永続化はSQLite（`sqlite-store.ts`）。
2. **Vault** — `src/main.ts`内で動くClient local storage。暗号化長期正本、projection、秘密、server間bindingを保持する。
3. **biset-mimi**（`src/mimi/index.ts`）— IETF `draft-ietf-mimi-protocol`に準拠したMLS Delivery Service。
   設計・実装状況の詳細な正本は[PLAN_biset-mimi-server.md](PLAN_biset-mimi-server.md)。
   `normal`/`anon`/`self`の3プロセスとして本番稼働中。**`self`モードは`main.ts`から実配線されており、
   単一identityの複数端末間Vault同期（Self Vault）の本番バックエンドである**。
   一方`normal`/`anon`モード（一般group chat hub）は`main.ts`からの呼び出し経路がなく、「部品実装済み」のままである。

**did.md** は biset が運用するものではなく、依存する外部サービスである。identity（did:webvh）の発行とホスティング、
および OAuth による認可を担う。biset 側は `src/wallet/`（`did-md-oauth.ts` / `did-md-store.ts`）でそのクライアントとして振る舞い、
**公開文書を書き込むことはない**——読んで解決するだけである（`src/identity/webvh/` の resolver 系）。

`src/shared/protocol/`は各境界が共有するwire schema、canonical encoding、ID、署名対象byte列を定義する。
browser、mediator、mail-plugin、mimiは別々のTypeScript設定（`tsconfig.*.json`、4設定——
旧`tsconfig.core.json`と`tsconfig.anchor.json`はいずれもディレクトリごと削除済み）で型検査する。

### 3.1 メッセージング機構の現況

「AさんからBさんにメッセージを届ける／複数端末で同期する」という問題に対する機構は、native login 削除の前後で大きく変わった。

| 機構 | 用途 | 状態（2026-09-05） |
|---|---|---|
| DIDComm 1:1 chat | ペアワイズ・共有鍵なし | **部分的に稼働**。受信・応答はできるが、**自分から関係を開始できない**（下記） |
| MIMI Self Vault | 単一identityの複数端末同期（対人チャットではない） | 稼働中（§9） |
| Mail (SMTP/JMAP) | 従来のメール | **失われた**。送信・受信とも配線が削除された。`src/mail/` はモジュールとして残るがテストからしか到達されない |
| DIDComm group chat | フルメッシュ・ペアワイズfan-out、MLS無し | **失われた**。`src/didcomm/group-chat.ts` は残るが呼び出し元がない |

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
`src/wallet/did-md-store.ts` に暗号化して保持し、以後 Wallet を再度開かずにセッションを復元できる。
biset は did.md の controller 鍵を一切保持しない。

**mediator との関係（設計方針、未実装）**: メールアドレスの採番と送信署名鍵は biset ではなく **mediator の責務**として
設計しなおす方針が決まっている（2026-09-05）。did.md が専用の mediator を運用し、利用者は Wallet ログイン時に
そこへ登録する。特定 mediator の使用許可を capability として付与する形を検討中。
これに伴い `mailFromForIdentity`（`src/identity/webvh/identifier.ts`）の
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

biset 側が did.md に対して持つ秘密は device session（`src/wallet/did-md-store.ts` に暗号化保存）だけであり、
**did.md の controller 鍵を biset が保持することはない**。利用者は did.md Wallet 側から当該 capability をいつでも失効できる。

### 4.3 Standalone mediator（"A"/"B"共通）を信頼する範囲

Mediator は inner DIDComm JWE を復号しない blind queue である。一方、登録された recipient kid、接続、queue 数、時刻、送受信元 IP、外側 Forward の routing metadata は観測できる。継続会話では公開 did:webvh ではなく relationship 固有の `did:peer:2` を使い、公開 identity との直接相関を mediator の保存状態から外す。DIDComm group chat も同じ relationship 経由で送るため、この分離はグループチャットにも及ぶ。

**"B"（mail-plugin同梱）追加分**——SMTP inbound listenerとoutbound submission HTTPが同じプロセスに同居することで、mediatorはさらに以下を観測できるようになる（旧biset-coreが観測していたのとほぼ同じ範囲）。

- SMTP envelope（MAIL FROM/RCPT TO）、接続元、TLS使用有無、メッセージ byte 数（listener.ts、§11.1）
- outbound submission requestの`mailFrom`/`rcptTo`/署名者identity（mail-submission-http.ts、§11.2）——ただしこれは「mailFromがidentityの正当なアドレスであること」と「署名がcurrent update keyで検証できること」を確認するためだけに使われ、別途保持されるroster/credentialは存在しない（旧core roster方式は完全に消滅した）

inbound mailの`protectedPayload`はmediatorに対するE2EEを意味しない。通常メールならmediatorは受信したraw RFC 5322 byteを見ることができる。DIDComm Forwardへ変換された後は他の1:1/group chatメッセージと同じくblind queueに載る。

### 4.4 biset-mimi Self Vault を信頼する範囲

Self Vault hub は MLS application/handshake message の内容を復号しない——providerがVault plaintextやSegmentKeyを知ることはない。一方、Self Vault groupのroom URI、参加device数、epoch/sequence、payload size、時刻は観測できる。checkpointペイロード自体もAES-GCM暗号化されており、hubはmanifest（coveredSeq、transferId、chunkCount、payloadHash）だけを見る。

### 4.5 外部 peer と archive

Peer restore は現在の MLS member による署名と current-epoch grant を要求する。Recovery archive は独立した 32-byte Recovery Key で AES-GCM 暗号化され、利用者自身が archive と鍵を別途管理する。archive 本体も Recovery Key もどのサーバーも保持しない。

## 5. Identity と did:webvh

### 5.1 Identity の生成

`createNewIdentity`（`src/identity/bootstrap.ts`）は以下を一続きで実行する。

1. 32-byte master seed を生成する。
2. seed を 24-word BIP39 mnemonic として利用者に提示する。
3. SLIP-0010 の `m/0'` から Ed25519 Root Key を導出する。
4. 独立のSpare Keyを生成し、phraseをRoot phraseと別に提示する。
5. `updateKeys=[Root]`、`nextKeyHashes=[hash(Spare)]`とrouting pointerを含むdid:webvh genesisを作る。pre-rotationはこの時点から永久にactiveである。
6. `registerDevice`が端末固有のMLS leaf signature key（random Ed25519）とRoot/Sign二重署名のMLS device credential（`MlsDeviceCredentialV2`）を導出する。

Self/Vault group（MIMI room）への参加は、この時点では**行わない**。identity生成は`deviceKid`/`deviceSignaturePrivateKey`という純ローカルな値をIdentityRecordへ書き込むだけで終わり、Self Vault groupの作成・external joinは`main.ts`のboot flowが`ensureMimiVaultRoom`経由で別途駆動する。

メール address は独立して発行せず、`did:webvh:{scid}:{username}.{apexDomain}` の domain から導出する。**canonical formはbare apexの`{username}@{apexDomain}`である**（`mailFromForIdentity`、`src/identity/webvh/identifier.ts`）。2026-09-04以前は`{username}@mail.{apexDomain}`が正規形だった——外部送信者からの実メールが`user@{apexDomain}`宛に届いて550 "no such user"で bounce した実障害を機に、まずbare apexをcanonicalにしつつ`mail.`形へのback-compatを追加し（`5fd385f`）、その後リポジトリオーナーの指示で明示的にそのback-compatを削除した（`274d110`）。現在`mail.{apexDomain}`宛は他の誤ったhostと同様に単純に拒否される（`identityDomainForMailAddress`）。この経緯は`test/identity/webvh-identifier-mail.test.ts`のtest名/コメントに残る。`routing.json.alsoKnownAs` にも best-effort で掲載する。

### 5.2 mnemonic によるログイン

Onboarding UI は入力 domain が既に resolve できる場合、signup から login へ切り替える。`restoreIdentity`はRoot phraseに加えてcurrent Sign phraseを要求し、did:webvh current `updateKeys`と照合する。初回rotation前はRootがSignを兼ねるため、同じRoot phraseを両方に入力する。`restoreIdentity`も`createNewIdentity`と同様、この時点ではSelf Vault groupに触れない——`registerDevice`でこの端末のdeviceKid/署名鍵を作るところまでで終わる。

現行 UI は既存の他端末が生きているかどうかを区別しない。mimiVaultConfigured（`mimiSelfBaseUrl`と`deviceKid`が揃っている）な boot は必ず`ensureMimiVaultRoom`を呼び、routing.jsonに記録されたroom URIが見つかればexternal join、見つからなければ新規roomを作成する。新規作成の場合、その端末はSelf Vaultの唯一のmemberとして始まり、Vault delivery の pull と archive/peer restore（§9.4）は依然として boot path に接続されていないため、mnemonic login だけで過去の Vault 本体が復元されるわけではない。

### 5.3 公開文書

| 文書 | 内容 | 更新認可 | ホスト |
|---|---|---|---|
| `did.jsonl` | hash chain、updateKeys、verificationMethod、move | did:webvh proof / current update key | **did.md**（外部） |
| `did.json` | 任意の did:web mirror | current did:webvh state による検証 | **did.md**（外部） |
| `routing.json` | DIDComm service/keyAgreement、mediator、Self VaultのMIMI room URIポインタ、alsoKnownAs、name、OpenPGP 公開鍵 | Root/current update key の Data Integrity proof | **did.md**（外部） |

`routing.json` は operational data を署名付き PUT で管理するが、did:webvh hash chain 自体には含まれない。DIDComm を有効化すると、signed log には `#routing` pointer が追加される。Self Vault の room URI（`mimiVaultRoom`フィールド、`setRoutingMimiVaultRoom`/`mimiVaultRoomFromRouting`）もこの同じ署名付き文書経由で公開・発見される——別のlookup serviceは存在しない。

### 5.4 Domain move

Identity は SCID を維持したまま新しい domain へ移転できる。`moveWebvhIdentity`（`src/identity/webvh/move.ts`）は次を行う。

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
- `flushMimiVaultOutbox`/`synchronizeMimiVault`（`src/vault/mimi-vault-sync.ts`）が送受信する、Vault delivery pack をチャンク化したMLS application message（PrivateMessage）そのものの搬送

メール本文や DIDComm Basic Message は依然として MLS application message として送られない——それらはDIDCommのauthcrypt/anoncryptで運ばれる（§12）。Self Vaultが運ぶapplication messageの中身は、あくまで各端末が既に確定させたVaultイベント/オブジェクト/SegmentKeyWrapの暗号化パックであり、ユーザーが読む本文そのものではない。

### 6.2 Lifecycle

Self Vault roomのroom IDは、**random**な `mimi://{providerHost}/r/vault-{32 random bytes}` である（`createMimiVaultRoom`）。決定論的なSCID派生ID（`selfGroupIdHex`、`src/mls/self-group.ts`）は前回調査時点ではcore roster projectionのラベルとして生き残っていたが、**core撤去に伴いその用途自体が消滅した**——`selfGroupIdHex`は現行treeでも存在するが、参照するroster projection機構（`installCurrentRosterProjection`、`ensureMimiCoreRoster`）ごと呼び出し元を失っている（knipのunused files/exports、§18参照）。復旧端末は`routing.json`の署名付き`mimiVaultRoom`ポインタからroom URIを発見する（§5.3）。

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

差分には `// biset:` marker があり、`src/mls/vendor/VENDOR.md` に記録される。`test/mls-core.test.ts` と `test/mls-crypto.test.ts` は現行 tree に存在し、fork の主要操作を検査している。

## 7. 鍵と秘密の一覧

| 鍵・秘密 | 単位 | 保存 | 公開・伝播 | 更新状況 |
|---|---|---|---|---|
| Master seed / 24-word Root Key phrase | identity | Client local `IdentityRecord` に hex 平文 | mnemonic を利用者が外部保管 | 自動 rotation なし |
| Root Ed25519 key | identity | Client local `IdentityRecord` に private key 平文 | did:webvh updateKeys、routing.json 署名、**mail-plugin outbound submission署名の検証根拠**（§11.2） | pre-rotation で権限移行可能 |
| Sign Ed25519 key | identity generation | アプリは永続保存せずphraseを利用者が保管 | current `updateKeys` | 初期はRootと同一、rotationで旧Spareへ移行 |
| Spare Ed25519 key | next generation | アプリは永続保存せずphraseを一度表示 | hashのみ`nextKeyHashes`へ常に一つ公開 | rotation時にSignへ昇格し新Spareを同時commit |
| MLS device credential / Self Vault leaf private state | device | MLS IndexedDB（`biset-mls-self-group`、同一rowにSelf Vault room state内包） | public verification method、Self Vault room | MLS UpdatePath / credential migration |
| MLS HPKE leaf material | device/epoch | MLS state | MLS tree / KeyPackage | commit により更新 |
| VEK | identity + epoch | 永続保存しない | 同 epoch member が exporter から導出 | epoch ごとに変更 |
| SegmentKey | Vault segment | `vault_segments.segmentKey` に平文保存 | VEK で暗号化した signed wrap を同期 | key は固定、wrap を epoch ごとに更新 |
| Identity front-door DIDComm X25519 | identity | encrypted Vault credential **と** identity record の hex 平文 cache | routing.json、信頼済み端末へ Vault 同期 | rotation schema/UI なし |
| Relationship X25519 + Ed25519 | counterparty/世代 | encrypted `contact-key.set` Vault object | service-bearing `did:peer:2`、Vault 同期 | `supersedesKid` chain、UI rotation なし |
| OpenPGP private credential | identity | encrypted Vault object | 公開 certificate を routing.json、private を Vault 同期 | supersedes chain のみ、trigger なし |
| Recovery Key | archive | アプリ内に保存しない | 利用者が archive と別管理 | archive ごとに新規 |

重要な現状上の注意は二点ある。

第一に、`IdentityRecord` の master seed、Root private key、DIDComm private key は IndexedDB に平文で保存される。過去設計にあった WebAuthn PRF 由来鍵による at-rest sealing は未移植である。

第二に、`VaultSegmentRecord.segmentKey` も local IndexedDB に平文で保持される。Vault object と delivery payload は暗号化されるが、端末 local storage 全体が別鍵で封印されているわけではない。したがって、この構成は server compromise と配送経路上の漏洩を主に抑えるもので、browser profile / local IndexedDB を読み取れる攻撃者に対する at-rest protection は未完成である。

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

1. `src/mediator/mail-plugin/listener.ts`（"B" deployment）が port 25 で生SMTPを受ける。EHLO/HELO、MAIL、RCPT、DATA、RSET、NOOP、QUIT、STARTTLSを扱い、既定25 MiB制限を広告・強制する。SMTPUTF8とAUTHは提供しない。TLS certificate/keyが設定されればSTARTTLSを提供するが、未設定でもserverは起動しplaintext SMTPとなる（旧biset-coreのSMTP listenerと同じ挙動——`smtp-socket-server.ts`/`mail-smtp-protocol.ts`は`src/core/adapters/`から2026-09-03にこのディレクトリへ物理的に移設されただけで、ロジックは変わっていない）。
2. RCPT TO時点で`bridge.ts`の`resolveMailRecipientRoute`が宛先アドレスの**routing.jsonをdomainだけから直接resolveする**（`identityDomainForMailAddress`が`mailFromForIdentity`の決定論的逆関数——SCID lookupもsigned-log resolveも経由しない）。宛先がDIDComm keyAgreement/serviceを公開していなければ550で拒否する。
3. DATA受理時、同じ`bridge.ts`の`packInboundMailForward`が受信メッセージを`MAIL_BRIDGE_INBOUND`型のDIDCommプレーンテキストへ包み、mail-pluginが自分で保持する専用の`did:peer`送信元identity（`SqliteMediatorStore.loadMailPluginIdentity`、real end-user identityとは別）からauthcryptし、宛先のmediator（Forward hop chainを含む）へ`OutboundDelivery`としてPOSTする——**core時代のingress store/pull/ackという独立した概念がなく、通常のDIDComm 1:1/group chatメッセージと全く同じmediator queueに載る**（§12.5）。
4. Client側は他のDIDCommメッセージと同じ`DidCommIngressProjector`/mediator SSE watch経由でこれを受け取る（§12.5）。deviceごとのlease/quota/ACKという概念はもう存在しない。

roster（device集合の認可情報）はこの経路のどこにも登場しない——宛先解決がrouting.jsonの公開情報だけで完結するため、"このidentityの端末集合をmail認可のために知っておく"という前段そのものが不要になった。前回調査時点の`rosterBackedVaultDeliveryAuthorizer`/`ensureMimiCoreRoster`は呼び出し元を失っている（§6.2、§18のknip debt）。

### 9.2 MIMI Self Vault delivery（現行）

一端末で確定した Vault mutation は、`VaultDeliveryOutboxReader`から読み出され、`flushMimiVaultOutbox`（`src/vault/mimi-vault-sync.ts`）が`splitMimiVaultPayload`でチャンク化し、各チャンクを`PersistedMimiVaultSession.sendApplication`経由でMLS PrivateMessageとして暗号化し、Self Vault roomへ`POST /update/{roomId}`で送信する。1件のoutbox entryのすべてのchunkが受理されて初めてoutbox recordを削除する。

- HTTP応答が失われても、`pending`フィールド（同一identityId row内）に暗号化済みバイト列とdeliveryIdが永続化されているため、次回attemptは同じciphertextを同じdeliveryIdで再送する——プレーンテキストを新しいratchet stateで再暗号化することはない。
- 受信側の`synchronizeMimiVault`は`pullMimiVaultPages`でbounded pull（1ページ32件、最大1024ページ）し、`decodeMimiVaultBatch`でチャンクを再構成する。
- checkpoint（後述、§9.4）は chunk と manifest が別々の非atomicな送信であるため、pull windowがその境界をまたぐと今回のbatchだけでは再構成できないことがある。`recoverSplitCheckpoints`がより広いpull windowで一度だけ再試行する。
- 4種類の名前付きrecovery strategy（`recoverSplitCheckpoints`／`applyCheckpoints`／`ingestDeliveries`／`synchronizeMimiVault`内のepochTooOldリトライ）がそれぞれ独立した関数として切り出されており、いずれも一件の失敗をbatch全体の失敗に波及させない。失敗は`MimiVaultSyncGap`（`kind`+`detail`）として構造化されたレポートに蓄積され、`synchronizeMimiVault`自体は例外を投げない。呼び出し側（`main.ts`）は`gaps`に`outbox-flush-failed`があれば明示的に例外へ変換し、UIのVault cardをerror状態にする。
- **checkpoint自動再作成のpoisoning対策**: 自分のローカルVaultがこのラウンドで一件でも不完全（undecryptable、ingest失敗、checkpoint restore失敗等）であれば、`result.gaps.length === 0`のガードにより新しいcheckpointを作成しない。ローカルが不完全な端末が「最新」を騙って他端末の復元を汚染する問題への対策である。

### 9.3 現行 Client の接続状態

MIMI Self Vaultのprotocol、SQLite store（hub側）、HTTP transport、projector、outbox/checkpoint、boot/poll loop、live SSE watch（`watchMimiVaultDeliveries`、`mimi-vault-watch.ts`）はすべてブラウザ製品経路へ接続済みであり、複数端末への同一メッセージ配送を実機で確認済みである。`message.add`が直接transportとVault delivery projectorの二経路から届く場合は、base projectionに同一immutable metadataがあれば冪等化し、同一batch内の重複または異なるmetadataは競合として拒否する。

**legacy core Vault delivery（`flushVaultDeliveryOutbox`/`CoreVaultDeliveryTransport`、`/v1/vault-delivery/*`）はコードとして`main.ts`に残っているが、この宛先を実装するサーバー（biset-core）自体が2026-09-03に削除されているため、production configの有無に関わらずもはや動作しうる経路ではない。** 呼び出しは`mimiVaultConfigured`のfalse時にのみ発生し、production configは常に`mimiSelfBaseUrl`を設定しているためこの分岐自体が実行されないが、仮に実行されたとしても`coreBaseUrl`（デフォルト空文字列）宛のHTTP呼び出しが失敗するだけである。旧ARC.mdの「MIMI未設定時のfallback」という説明は、core撤去後は「fallbackの体をした死んだコード」に変わった。

### 9.4 Restore

完全復元の正規経路は biset-mimi Self Vault checkpoint である。

1. Client は event/object と全 SegmentKey を canonical Recovery Archive snapshot にする。MLS exporter secret と device signing key は含めない。
2. root phrase と Self Vault の room ID（旧来のCoordinator `vaultId`に相当する位置に room ID を使う）、provider origin から HKDF-SHA256 で recovery KEK を導出する。
3. fresh random data key で snapshot を AES-GCM 暗号化し、その data key を recovery KEK で wrapする。外側 envelope に DID/SCID/domain/mail address を含めない。
4. `createPortableCoordinatorCheckpoint`/`openPortableCoordinatorCheckpoint`（`src/vault/vault-checkpoint.ts`）——**関数名に "Coordinator" が残っているが、Coordinatorプロセス自体は存在しない**。v2フォーマットは「Vault operatorの間で移植可能」という設計であり、v1（廃止済みCoordinatorが書いたcheckpointの読み込み専用互換）とv2（現在書き込む唯一の形式、biset-mimi向け）を区別する。関数名のリネームは未実施のまま残る技術的負債である。
5. checkpointのmanifest（`VaultCheckpointManifest`：`coveredSeq`/`transferId`/`chunkCount`/`payloadHash`）だけがhubに見え、payload自体はMLS application messageとして暗号化されてchunk化配送される（§9.2）。
6. 新端末は`joinMimiVaultRoom`のexternal commitでSelf Vaultに参加した後、root phraseで復号、current epochへkey wrapを更新し、projection/cursorを再構築する。

既存memberがonlineであれば、新端末のexternal joinはSelf Vault自体のMLS external commit機構で即座に成立する（Coordinator時代のような「pending KeyPackageのpoll承認」という別のステップは無くなった——external joinそのものがhub側で一発で受理されるかrejectされるかのいずれかである）。

これらの store、検証、import、projection rebuild は実装・テスト済みだが、`main.ts` と UI には export/import、peer approval、transfer、`restoreRequired` 処理が接続されていない（`main.ts`/`src/ui/*.ts`に`restoreRequired`という識別子は現行 tree に存在しない）。現行 UI で実行できる「restore」は mnemonic による identity/device 再参加（その結果 boot 時に自動的にSelf Vaultへexternal joinし、それ以降のVault mutationを追い掛け始める）までであり、それ以前の Vault history の一括 restore ではない。

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

Identity がある場合の`bootClient`（`src/main.ts`）の主要順序は次のとおりである。

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

**biset-core撤去（2026-09-03）と、standalone mediatorへのmail-plugin同梱（2026-09-03〜04、commit `9b98e4d`〜`5b9f1fa`）により、この節は前回調査から全面的に書き換わっている。** メールの受信・送信は、biset-coreではなく`src/mediator/mail-plugin/`（deployment variant "B"）が一手に担う。この変更は`ARC.md`の前回調査（commit `11f0a62`）の**後**に行われたため、旧文書は一切この設計を反映していなかった。

### 11.1 受信

§9.1で詳述した通り。要点は、(a) SMTP listenerとDIDComm変換ロジックが同一プロセス内にあり、(b) 宛先解決がroster/deviceローカルな認可情報を一切参照せず公開routing.jsonのみで完結し、(c) 変換後は通常のDIDComm Forwardとしてmediator queueに合流する、の三点である。core時代にあった独立のingress store・TTL・quota・per-device lease/pull/ackという概念はどれも存在しない。`src/mediator/mail-plugin/smtp-socket-server.ts`と`mail-smtp-protocol.ts`はcore撤去時に`src/core/adapters/`からこのディレクトリへ物理的に移設されたのみで、ロジックに変更はない。

### 11.2 送信

Client はまず local Vault に outbox message を commit する。`EmailSubmission/set` → `buildMailSubmitter`（`src/identity/bootstrap.ts`）が device leaf key ではなく、**identityのcurrent did:webvh update key（Root、またはpost-rotation後の後継鍵）**で`MailSubmissionRequestV1`（raw RFC 5322、MAIL FROM、recipient、時刻を含む）に署名し、`mediatorUrls[0]`（＝mail-plugin配下の`/v1/mail/submit`、port 8792、Caddyが同一public origin `mediator.biset.md`の下でこのpathだけをport 8792へ振り分ける）へPOSTする。

サーバー側（`mail-submission-http.ts`の`isAuthorised`）の認可は次の二点のみで、**device rosterという概念自体が存在しない**（旧biset-coreのMLS-device-credential + trusted-device-roster方式は2026-09-04に完全に置き換わった）。

1. 申告された`mailFrom`が`mailFromForIdentity(identityId, apexDomain)`の導出結果と一致すること（なりすまし防止）。
2. `signature`が`resolveCurrentUpdateKeys(identityId)`——routing.json更新そのものが要求するのと同じ、did:webvh current update keyの公開・自己証明可能な権威——で検証できること。

成功時は `transport.result` と `mailbox.set(sent)` を Vault に記録する。失敗時は temporary-failure として outbox に残すが、自動 retry scheduler と DSN はない。複数 domain の一部失敗も全体を temporary-failure に畳むため、recipient 単位の再送制御は未実装である。

`buildMailSubmitter`が使う transport class は依然として`CoreMailSubmissionTransport`という名前のままである（実体はmail-plugin宛のHTTP submitで、biset-coreとは無関係）——§9.4の`createPortableCoordinatorCheckpoint`と同種の、撤去後も残る名称上の負債である。

**found live（2026-09-04）: outbound relayはこの日まで一度も実際に動作したことがなかった。** `smtp-client.ts`のoutbound SMTPクライアント（`deliverMail`、core撤去時にadapterからverbatimで移設）が、追加TLSオプションなしのSTARTTLSアップグレード時に`socket.upgradeTLS({tls: {}, ...})`を呼んでいた。本プロジェクトが動かすBun 1.4.0では、空の`tls: {}`オブジェクトを渡すと実行時に`Expected "tls" option`で例外になる——`Bun.TLSOptions`の型定義（全フィールドoptional）は`{}`が有効であるかのように見せるが、実際にBunのnative bindingが要求する「デフォルトTLSでアップグレードする」の正しい書き方は`tls: true`である。この不具合はSTARTTLSを要求する実サーバーに対してこのcodepathが行使された最初の機会（core由来のこのコードがverbatimで復元されて以来）で発覚し、それまでのoutbound relay試行は全て`{"status":"temporary-failure","detail":"Expected \"tls\" option"}`で失敗していた。修正（commit `5b9f1fa`）後、実際の送信（`a91b@biset.md` → 外部の`y@4r.ma`宛）が配送されたことを確認した——**これが本番でoutbound mail relayが実際にend-to-endで動作した最初の事例である。**

### 11.3 OpenPGP

実装済みの endpoint primitive は、OpenPGP credential 生成、Vault への private key 保存、routing.json への public certificate 公開、RFC 3156 encrypted packet 抽出、packet 復号と署名検証である。

一方、`main.ts` の compose/send は常に plaintext RFC 5322 を構築し、recipient public key 解決や encrypt/sign を呼ばない。受信 UI も OpenPGP decrypt primitive を呼ばない。よって現在の OpenPGP は **鍵 provision と検証済み部品まで** であり、実際の mail E2EE は製品経路に未接続である。Autocrypt header の生成・peer state もない。

## 12. DIDComm

### 12.1 Public front door

Boot 時、最初の端末が identity-shared X25519 credential を Vault に作り、routing.json の一つの `keyAgreementVerificationMethod` として公開する。Sibling は同じ encrypted credential を Vault 同期経由で読む設計である。Mediator URL が設定されていれば各 mediator へ Coordinate Mediation 2.0 で登録し、成功した endpoint だけを DIDCommMessaging service として公開する。

**core撤去による訂正**: `enableDidComm`（`src/identity/bootstrap.ts`）は、全mediator登録が失敗した場合の"legacy fallback"として、依然として`opts.coreBaseUrl`から`{coreBaseUrl}/v1/didcomm/ingress`という形のエンドポイント文字列を組み立ててroutingへ最初に一旦PUTするコードを持つ。しかし`coreBaseUrl`は`readBisetConfig()`で常に空文字列にデフォルトし（production configはこの変数を一切設定しない）、`/v1/didcomm/ingress`を受けるサーバー自体（biset-core）も存在しない。production configはmediatorUrlsを常に設定しており、通常はそのうち少なくとも一つの登録が成功して`mediators.length`が真になった時点でこの一時的なroutingがmediator情報で上書きされるため、実運用上この空origin fallbackが最終的に公開されて観測される事態にはなっていない。ただし、すべてのmediator登録が失敗する状況では、動作しないURLを指すDIDCommMessaging serviceが公開文書に残ることになる——これは「fallbackとして機能する」というより「動かないなら動かないなりに、無害だが無意味な文字列を残す」という状態であり、旧ARC.mdの「legacy core `/v1/didcomm/ingress`をfallbackとする」という説明はもはや正確ではない（§20の cleanup項目参照）。

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

Standalone mediator は自身の did:peer identity、connection keylist、queueを**SQLite**（`src/mediator/sqlite-store.ts`）に保存する。Coordinate/Pickup request は DIDComm authcrypt の sender X25519 keyで認証する。did:webvh sender は公開 routing を resolve し、did:peer sender は self-certifying DID から鍵を得る。

Queue は recipient kid あたり最大 256 件、保持 30 日で、満杯時は古い正当 message を捨てず sender を拒否する。Pickup は non-destructive delivery の後、`messages-received` ACK で削除する。Connection は最大 10,000、connection ごとに最大 32 kid。Replay guard は既定 10 分 / 50,000 ID、resolved key cache TTL は 10 分で stale-while-refresh 動作をする。共有HTTP surfaceは単一の `POST /` （DIDCommメッセージ種別で内部分岐）、`GET /.well-known/did.json`、`GET /stream`（SSE、client側の`watchMediator`が使う）の3経路であり、これは"A"（素のmediator）と"B"（mail-plugin同梱）で完全に共通（`deployment.ts`）である。"B"はこれに加えてSMTP:25とsubmission HTTP:8792を独立に持つ（§3・§11）。

`relay-poller.ts`は、あるmediatorが別のupstream mediatorへ自分自身をclientとして登録し（`MEDIATOR_RELAY_UPSTREAM_URL`）、自分宛のForwardをunwrapして自分のqueueへ再Forwardする、任意のmulti-hop中継機能である。routing.jsonの`routingKeys`（outermost-first）でこの中継段を名指しできる。dispatch()自体はこの機能の有無で変わらない——upstream側からは通常のend-user deviceに見え、downstream側からは通常のForward requestに見える。

DBファイルへの書き込み失敗時の挙動は、本調査でも未検証のまま次回調査で確認すべき既知の空白として残る。

### 12.5 メッセージ振り分け（1:1・group chat・mail bridge）

**旧「Legacy core DIDComm path」節は本調査で全面的に置き換えた——core自体が存在しないため、`/v1/didcomm/ingress`というサーバー route はどこにも実装されていない。** mediatorのSSE watchループが受け取るのは、型タグで振り分けられる単一のqueueに載った次の3種のペイロードだけである。

1. DIDComm 1:1（Basic Message 2.0、§12.2・§12.3）
2. DIDComm group chat control/content（GROUP_INVITE等、§12.6）
3. `MAIL_BRIDGE_INBOUND`（§9.1・§11.1のmail-plugin bridgeが変換したメール）

`DidCommIngressProjector`（`src/didcomm/ingress-projector.ts`）は元々core経由のlegacy ingressとmediator経由の両方で共用される汎用decodeクラスとして書かれていたが、core側の呼び出し元（`CoreIngressTransport`、main.tsの`if (coreBaseUrl)`ブロック内、§14参照）は現在事実上死んでいる。実際に動くのはmediator SSE watch経由の1経路だけであり、legacy core ingressとの二重化は名目上残るコード（`CoreIngressTransport`、`opts.coreBaseUrl`の空文字列defaultなど）はあっても、実質的には解消済みである。

### 12.6 DIDComm group chat

複数人チャットの現行かつ唯一の実装。`src/didcomm/group-chat.ts`と`group-chat-store.ts`（IndexedDB、device-localなroster cache）、`main.ts`側の`createAndSendDidCommGroup`/`sendDidCommGroupMessage`/`handleDidCommGroupInvite`/`handleDidCommGroupContent`から構成される。MLS共有group stateを一切使わない full-mesh pairwise fan-out であり、1:1チャットと同じ`ContactKeyV1`関係を再利用する。

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

IETF draft-ietf-mimi-protocol §5.2/§5.3のprovider-facing routesを実装する（`src/mimi/http.ts`）。主なpathは、well-known protocol directory、`GET /stream`（deliveries、SSE watch tokenで認可）、franking agentデータ、asset proxy download、`POST /notify/*`（federation fanout受信）、`POST /groupInfo/{roomId}`（external join、`allowExternalJoin`が有効なdeploymentのみ既定拒否を解除——`self`モードだけがこれを有効化する）、abuse report、consent request/update、identifier query、`POST /keyMaterial/{targetUser}`、`POST /keyPackage`、`POST /update/{roomId}`（room作成・external join commit・通常commit・checkpoint application messageのいずれも、この単一endpointを通る）である。すべてのbodyはbiset独自のprovider-internal credential signature（`authorizer.ts`）で認証する——membershipとMLS leaf署名だけが認可根拠であり、外部の認証トークンは要求しない。この節は core 撤去にも Anchor 削除にも影響を受けていない。

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

- `bun run build` — `src/main.ts` と `src/sw.ts` を browser IIFE に bundle し、`scripts/inline.mjs` で `dist/index.html` に inline 化する。
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

"A"（`src/mediator/index.ts`）と"B"（`src/mediator/mail-plugin/index.ts`）は共通の変数セットに加え、"B"だけが追加変数を要求する。**両者は同じ`biset-didcomm-mediator.service`/DBを奪い合う排他ターゲットであり、どちらか一方だけが本番で動く**（deploy.shコメント。§3・§13.4）。core retirement後の現行方針（2026-09-03時点）では"B"（mail-plugin）が本番稼働中。

共通:

| 変数 | 必須性 / 既定 |
|---|---|
| `MEDIATOR_PUBLIC_URL` | 必須 |
| `MEDIATOR_DATABASE_PATH` / `MEDIATOR_DATA_DIR` | いずれか必須（SQLiteファイルパス） |
| `PORT` | 既定 8791 |
| `MEDIATOR_HOST` | 既定 `127.0.0.1` |
| `MEDIATOR_ALLOWED_ORIGINS`、`MEDIATOR_MAX_REQUEST_BYTES`、`MEDIATOR_RATE_LIMIT_PER_MINUTE`、`MEDIATOR_MAX_CONNECTIONS`、`MEDIATOR_MAX_KEYS_PER_CONNECTION`、`MEDIATOR_MAX_QUEUE_ITEMS`、`MEDIATOR_MAX_QUEUE_BYTES`、`MEDIATOR_MAX_MESSAGE_BYTES`、`MEDIATOR_QUEUE_TTL_MS`、`MEDIATOR_REPLAY_TTL_MS`、`MEDIATOR_MAX_REPLAY_IDS` | いずれも既定値ありの運用チューニング。**`MEDIATOR_ALLOWED_ORIGINS`は"B"の`/v1/mail/submit`のCORSチェックにも同じ値が再利用される**（§13.2） |
| `MEDIATOR_RELAY_UPSTREAM_URL` | 任意。設定すればmulti-hop relay pollerを起動する（§12.4） |

"B"追加分（`src/mediator/mail-plugin/index.ts`）:

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
- `bun run test` — `find test -name '*.test.ts'` で数えて **149個** の `*.test.ts` file（前回調査の「140個」から9増加）を serial 実行し、すべて成功（exit code 0、非ゼロの `fail` 行なし）。ただし `git ls-tree -r HEAD` でtracked扱いなのは113個のみで、残り36個はgitignore対象のuntracked file（このセッション以前から既知の状態——git worktreeはgitignore対象untracked fileをコピーしないため、worktree内での実測はこの36個を欠いた113個になる。本節の数字は実際のmain working tree（`/Users/n/biset`）で直接実行した結果を採用した）。coreディレクトリごと削除されたことに伴うtest減少は実際には起きておらず、旧`test/core/*`相当のファイルが個別に削除された一方、mail-plugin関連の新規testが追加されたことで純増になっている。gitignore対象のtracked外test fileが33%を占める状態自体は、依然として未解消の運用上の負債である（§15.2・§20参照）。

テストは canonical protocol、Vault crypto/store、DIDComm crypto/mediator/private relationship/group chat mesh、mail-plugin bridge/listener、SQLite、Self Vault MLS、domain move、SMTP、OpenPGP primitive、MIMI Vault sync/chunks/client transport/room/session/room-migrationを広く覆う。`test/vault-mimi-sync.test.ts`は意図的に一部エラーログ（undecryptable application entry、checkpoint chunk不足）を出力しながらpassする——それらは§9.2の各recovery strategyが正しくgapとして記録して回復することを検証するテストである。一方、`main.ts` の boot wiring を browser E2E として網羅しておらず、「部品のテスト成功」と「製品経路への接続」を検出できていない——§14の coreBaseUrl gate regression はまさにこの隙間から本番へ出た実例である。

`bun run knip` は失敗する（exit code 1）。現状の debt は次のとおりである。

- unused files: **12**（`src/context.ts`、`src/mediator/identity.ts`、`src/mls/keypackage-store.ts`、`src/mls/vendor/codec/json.ts`、`src/mls/vendor/customCredential.ts`、`src/oid4vp/file-bridge.ts`、`src/oidc/client.ts`、`src/protocol/mls-ds-wire.ts`、`src/protocol/transport.ts`、`src/route.ts`、`src/state.ts`、`src/types.ts`）——前回調査の11から1増加。新規は`src/protocol/transport.ts`。
- unused dependencies: 5（`@scure/bip32`、`bittorrent-dht`、`cborg`、`hash-wasm`、`jmap-jam`）——変化なし。
- unused devDependencies: 2（`@hpke/core`、`@types/wicg-file-system-access`）——変化なし。
- unlisted binaries: 2（`tsc`、`knip`）——変化なし。
- unresolved imports: 4（`scripts/pkarr-smoke.mjs`が参照する`src/did/keys.ts`等4ファイル——旧did:dht/Pkarr実装の残骸。did:webvh一本化後もこのスクリプトだけ削除されずに残っている）——変化なし。
- unused exports: **438**、うち unused exported types: **216**（前回調査は単一の「418」という数字だったが、現行knipバージョンは通常exportと型exportを別カテゴリとして分けて報告する——単純比較はできない。合算では654）。
- configuration hints: 4（`deploy.sh`のignoreBinaries、`src/anchor/index.ts`/`src/mediator/index.ts`/`src/mediator/mail-plugin/index.ts`のentry pattern重複——前回調査の`src/core/index.ts`が`src/mediator/mail-plugin/index.ts`に置き換わった）。

したがって `bun run check`（typecheck && knip && test）は typecheck/test が正常でも knip で非 zero になる。unused filesが微増しているのは、core撤去・Conversation Groups撤去に伴う未使用コードの掃除が引き続き追いついていないことを示す。

## 19. 実装状態の総括

| 領域 | 状態 | 判定 |
|---|---|---|
| did:webvh **解決** | UI/boot に接続。`src/identity/webvh/` の resolver 系 | 実装済み |
| did:webvh create/update/pre-rotation/domain move | **削除済み**（2026-09-05）。発行は did.md の責務 | 廃止 |
| Self Vault MLS group、roster、individual device removal、VEK | UI/boot と biset-mimi(self) に接続 | 実装済み |
| Local encrypted Vault + JMAP projection | UI read/write に接続 | 実装済み |
| Mail 受信（mail-plugin SMTP bridge、push型） | **クライアント側の配線が削除された**（2026-09-05）。mediator 側は稼働 | 部品実装済み（W3⑤で再配線予定） |
| Mail 送信（mail-plugin 署名submission） | **クライアント側の配線が削除された**（2026-09-05）。mediator 側は稼働 | 部品実装済み（W3⑤で再配線予定） |
| MIMI Self Vault delivery（checkpoint含む） | poll/SSE watch/outbox/gaps report まで UI に接続 | 実装済み |
| legacy core Vault delivery | コードのみ残存、サーバー実体（biset-core）は削除済みで動作しない | 死んだコード（§9.3・§15.2リスク14） |
| ~~Mnemonic login~~ | ~~identity/device join~~ | **廃止**（2026-09-05、`7357830`） |
| ~~Anchor OpenID4VP login~~ | ~~Verifier、credential、session、Wallet enrollment~~ | **廃止**（2026-09-05、`74864ff`） |
| **did.md Wallet login** | OAuth + DPoP-bound device session、boot の唯一の入口 | 実装済み |
| Peer/archive restore | primitive と test あり、UI/boot なし | 部品実装済み |
| OpenPGP | key provision/publication/crypto primitive あり、mail path 未接続 | 部分実装 |
| DIDComm public front door | UI/boot に接続。legacy fallback文字列生成は残るが動作しない | 実装済み |
| Standalone mediator（"A"/"B"、SQLite永続化） | binary、protocol、SSE watch、relay-poller あり | 実装済み、"B"が本番稼働中 |
| Private relationship DIDComm 1:1 | 受信・応答は可能。**自分から関係を開始できない**（`initiateRelationship` の本番呼び出し元がゼロ） | **機能不全**（W3①が最優先） |
| DIDComm group chat | **配線が削除された**（2026-09-05）。`didcomm/group-chat.ts` は残るが呼び出し元なし | 部品実装済み（W3④で再配線予定） |
| ~~MLS Conversation Groups~~ | ~~ソース削除済み~~ | 廃止（2026-09-03） |
| ~~biset-core~~ | ~~ソース削除済み（`src/core/`ごと）~~ | 廃止（2026-09-03、commit `99e08c0`） |
| biset-mimi normal/anon（一般group chat hub） | サーバーとして稼働、client呼び出し経路なし | 部品実装済み |
| Multi-device product experience | Self Vaultにより大きく前進したが、account switching・端末/鍵管理の統合は未完成 | 部分実装 |
| Remote JMAP account | transport/router のみ | 部品実装済み |
| ActivityPub | adapter なし | 未実装 |
| Web Push / background sync | Service Worker shell のみ | 未実装 |

## 20. 推奨する次の作業順

1. **端末/鍵管理を1つの概念に統合する**（最優先）。「MIMI Self Vault roomのmember = このidentityの端末」という前提のもとで、追加・削除・ローテーションを1つのAPIへまとめる。Coordinator撤去で失われたSign Key rotationの一括世代交代（旧`rotateKeyRotation`相当）をこのタイミングで作り直す必要がある（§15.2のリスク4）。
2. **core撤去後の死んだfallbackコードを一括で削除する**（新規、優先度高——§14のcoreBaseUrl gate regressionが実際に本番機能停止を引き起こした前例がある以上、「動かないが残っているgate/fallback」はこの種の事故の温床であることが実証された）。`opts.coreBaseUrl`起点のrouting fallback文字列生成（§12.1、`identity/bootstrap.ts`）、`CoreIngressTransport`/`CoreVaultDeliveryTransport`とその`if (coreBaseUrl)`分岐（§9.3・§12.5、`main.ts`）、`CoreMailSubmissionTransport`という名前（§11.2）、`createPortableCoordinatorCheckpoint`/`openPortableCoordinatorCheckpoint`という名前（§9.4）が対象。
3. `restoreRequired`を専用UIへ接続し、biset-mimi checkpoint・Peer/Archive restoreを開始できるようにする。現在はsystem messageまでで止まる（§9.4、§15.2のリスク2）。
4. OpenID4VPのconsent/account chooser UIとcredential管理/revoke UIを追加する。Verifier、session、永続provider compositionは実装済み。
5. Relationship handshake（1:1・group chat招待の双方が使う`pendingByOwnKid`/`pendingByCounterparty`）をcrash-safeにする（§15.2のリスク6）。
6. Device revoke後のidentity/DIDComm/OpenPGP credential rotationをcrash-safeにする（§15.2のリスク3）。
7. DIDComm group chatとMIMI Self Vaultの機構重複を調査する。共有できるchunk/retry設計があるかを検討する——現時点では推測でしかない。
8. Peer restoreとRecovery archive export/importをUIへ接続し、identity復旧と履歴復旧を分けて表示する。
9. knip debtとlegacy dependency/scriptを整理し、`bun run check`をrelease gateとして通す。特に`scripts/pkarr-smoke.mjs`（did:dht/Pkarr、既に廃止済みの機構）と、unused filesに残る`src/route.ts`/`src/state.ts`/`src/types.ts`/`src/protocol/transport.ts`等の要否を精査する。
10. `main.ts`のboot wiring（§10.3・§14）に対する最小限のbrowser E2Eまたは統合テストを追加する。coreBaseUrl gate regressionのような「typecheck/build/testはすべて通るのに製品経路が丸ごと死ぬ」regressionは、これがない限り再発しうる。

## 21. 主要ソース案内

| 関心 | 主なファイル |
|---|---|
| Client composition | `src/main.ts`, `src/ui/*`, `src/ui/config.ts` |
| Identity lifecycle | `src/identity/bootstrap.ts`, `src/identity/record-store.ts` |
| did:webvh 解決 | `src/identity/webvh/*`（resolver 系のみ。発行・移転・鍵ローテは削除済み） |
| did.md Wallet ログイン | `src/wallet/did-md-oauth.ts`, `src/wallet/did-md-store.ts` |
| Self Vault MLS | `src/mls/self-group.ts`（roster projection呼び出し元を失った状態で生存）, `src/mls/group.ts`, `src/mls/mimi-vault-room.ts`, `src/mls/mimi-vault-session.ts`, `src/mls/mimi-vault-watch.ts`, `src/mls/mimi-client-transport.ts`, `src/mls/vendor/VENDOR.md` |
| Vault | `src/vault/store.ts`, `objects.ts`, `events.ts`, `crypto.ts`, `delivery-pack.ts`, `restore-*`, `vault-checkpoint.ts` |
| MIMI Vault sync（client側data plane） | `src/vault/mimi-vault-sync.ts`, `src/vault/mimi-vault-chunks.ts` |
| biset-mimi（hub本体） | `src/mimi/index.ts`, `deployment.ts`, `http.ts`, `store.ts`, `wire.ts`, `protocol-types.ts`, `authorizer.ts`, `fanout.ts`, `room-policy.ts` |
| Local JMAP | `src/local-jmap/gateway.ts`, `reducer.ts`, `vault-mutation-sink.ts`, `indexeddb.ts` |
| Mail transport（mail-plugin） | `src/mediator/mail-plugin/index.ts`（"B"エントリポイント）, `bridge.ts`（RCPT解決・DIDComm変換）, `listener.ts`（SMTP listener組み立て）, `smtp-socket-server.ts`/`mail-smtp-protocol.ts`（core撤去時に移設、byte-orientedプロトコル）, `smtp-client.ts`（outbound SMTP、STARTTLS）, `mail-submission-http.ts`（`/v1/mail/submit`、認可・CORS） |
| DIDComm 1:1 | `src/didcomm/relationship.ts`, `basicmessage.ts`, `send-message.ts`, `ingress-projector.ts`, `src/vault/contact-key*`, `src/vault/didcomm-*` |
| DIDComm group chat | `src/didcomm/group-chat.ts`, `src/didcomm/group-chat-store.ts` |
| Standalone mediator | `src/mediator/index.ts`（"A"エントリポイント）, `deployment.ts`（"A"/"B"共通）, `server.ts`, `sqlite-store.ts`, `queue.ts`, `connections.ts`, `relay-poller.ts` |
| Wire schemas | `src/protocol/*` |
| Tests | `test/`, 特に `test/protocol/*`, `test/mediator-relationship-handshake.test.ts`, `test/vault-mimi-sync.test.ts`, `test/didcomm-group-mesh.test.ts`, `test/mls/mimi-*.test.ts`, `test/mediator/mail-plugin/*.test.ts` |

---

この文書は「意図」ではなく上記 commit の現状を記録する。将来の変更でコードと本書が食い違った場合は、まず実行経路と wire compatibility をコード・テストで確認し、その後この調査基準 commit と実装状態表を更新する。
