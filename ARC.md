# Biset アーキテクチャ

> MLSについては[ARC-MLS.md](ARC-MLS.md)を参照する。ただし同文書はCoordinatorの完全撤去（2026-09-03、commit `57ffa67`）以前の調査であり、「Coordinator MLS DS」「Coordinator owner-scoped Vault stream v2」を現行実装として説明する記述はすべて本書時点で誤りである——`src/coordinator/`はディレクトリごと存在しない。ARC-MLS.mdが依然として正確なのはRFC 9420 vendored forkそのものの節（ciphersuite、UpdatePath fix、vendor diffの一覧）に限られる。旧`ARC-coordinator.md`への相互参照は同ファイルが存在しないため削除した。Self Group/Vaultの現行の配送経路は本書§6・§9で説明するbiset-mimi Self Vaultである。

> 調査基準日: 2026-09-03（Asia/Tokyo）
> 調査対象: `~/biset` の commit `11f0a62c731c868d35c1b2a666c7a9de2563dfcd`
> 状態: 現行コードを正とした実装アーキテクチャ。将来案は明示的に区別する。

## 1. この文書の目的

Biset は、メールと DIDComm のデータを利用者の端末側で長期保管し、サーバーを恒久的なメールボックスやメッセージ履歴にしない通信クライアントである。本書は、現行コードの構成、信頼境界、暗号鍵、状態遷移、配送・復旧経路、運用方法、および未完成部分を一つの資料にまとめる。

リポジトリ直下の `PLAN.md` と `PLANIMPLEMENTATION.md` には実装経緯や将来計画も含まれる。`PLAN-SIMPIFY.md`（gitignore対象、2026-09-03作成）は今日一日で起きたCoordinator全廃・DIDComm group chat追加・MIMI Vault sync障害対応の連続を踏まえた簡素化診断であり、本書§3.1・§15.2・§20の記述はその内容と整合させてある。本書ではそれらを参考にしつつ、実際に `src/` と `test/` に存在し、呼び出し経路へ接続されているものを「実装済み」と判定する。クラスやテストだけが存在し、ブラウザの起動経路へ未接続のものは「部品実装済み」とする。

## 2. 設計原則と非目標

### 2.1 原則

- 長期正本は各 endpoint の暗号化 Vault であり、core や DIDComm mediator ではない。Coordinatorという別プロセスは存在しない——複数端末間の Vault 同期は biset-mimi の Self Vault（後述、§3・§9）が担う。
- core が保持するのは、公開 identity 情報、端末 roster、TTL・quota 付き暗号文バッファ、および（未設定時 fallback としての）legacy Vault delivery/DIDComm ingress に限る。
- UI と保存層の間には JMAP 形のローカル API を置き、暗号方式を UI へ漏らさない。
- MLS は user-to-user のチャット本文暗号化には使わない（それは DIDComm の役割）。一方、同じ identity の信頼済み端末集合を表す Self/Vault MLS group は、Vault mutation を運ぶ暗号文チャンクそのものを MLS PrivateMessage/PublicMessage として運ぶ——「MLSはVEK導出境界だけに使う」という旧原則は、biset-mimi 移行後は成り立たない。VEK（Vault Epoch Key）は依然としてこの MLS exporter secret から導出し、SegmentKey の epoch-wrap 境界として使う。
- 外部 ingress を ACK するのは、端末で検証・暗号化・永続化が完了した後だけとする。
- 復旧に必要な履歴本体を core に置かず、biset-mimi Self Vault の checkpoint、信頼済み peer、または利用者管理の暗号化 archive から取得する。
- did:webvh の SCID を identity の安定した識別子として扱い、ドメイン移転で Self Vault や配送列を分断しない。

### 2.2 現行スコープ外または未完成

- MLS ベースの複数人グループチャット（旧 Conversation Group / biset-mls-ds）。2026-09-03 にソース一式（`src/mls-ds/`、`src/mls/conversation-group*.ts`、`src/protocol/conversation-mls-ds*.ts`）が削除され、DIDComm group chat（§3.1、§12.6）に置き換わった。biset-mimi の `normal`/`anon` モード（複数 OIDC owner を跨ぐ一般グループチャット hub）は稼働しているが、client からの呼び出し経路がなく、この意味でのグループチャットは依然として実装されていない。
- ActivityPub の実動 adapter。protocol enum に値は残るが、adapter、UI、配送経路はない。
- サーバー側の mailbox、全文検索、履歴 API、添付 archive。
- 完全な JMAP server。ローカル gateway は UI が必要とする最小メソッドだけを実装する。
- OpenPGP を用いた実際のメール送信時暗号化と UI での受信復号。
- Web Push。Service Worker は install/activate のみで、通知・バックグラウンド同期を行わない。
- 端末/鍵管理の統合。self-group.ts（Coordinator撤去で大半削除）・MIMI room membership・Sign Key rotation は、同じ「端末を追加/削除する」操作に対する別々のコードパスのままであり、Coordinator撤去で Sign rotation の MIMI 版代替が消えたまま（`PLAN-SIMPIFY.md` §1.2）。§20 参照。

## 3. システム全体像

```text
┌──────────────────────── Biset Client（ブラウザ） ────────────────────────┐
│ UI ─ Local JMAP Gateway ─ Projection                                    │
│                  │                                                       │
│        IndexedDB Vault（暗号文 object + 署名 event + key wrap）          │
│                  │                                                       │
│  did:webvh / Self Vault MLS group / Mail / DIDComm 1:1 /                │
│  DIDComm group chat / Restore endpoint logic                            │
└──┬──────────┬─────────────────────────────┬─────────────────────────────┘
   │signed    │DIDComm v2 encrypted HTTP     │MIMI Vault sync wire
   │narrow    │（1:1・group chat の両方が    │（DIDComm ではない、
   │HTTP      │ 同じ経路。group chat は      │ biset-mimi 独自 protocol。
   │          │ full-mesh pairwise fan-out、 │ self モードだけに向く）
   │          │ 共有 MLS state を持たない）  │
   ▼          ▼                              ▼
┌─ Core ───┐┌─ Mediator ───────────────────┐┌─ biset-mimi (self = Vault) ─┐  ┌─ biset-mimi (group = hub) ──┐
│did.jsonl ││did:peer identity              ││このidentityのSelf Vault用。   │  │normal/anon モード。           │
│roster    ││SQLite queue                   ││main.ts から実配線済み——      │  │複数 OIDC owner を跨ぐ一般     │
│ingress   ││Coordinate/Pickup/relay-hop    ││Vault mutation を運ぶ MLS      │  │group chat hub。                │
│SMTP      ││1:1・group chat 両方をここで   ││application message チャネル  │  │client からの呼び出し経路なし  │
│legacy    ││authcrypt/pickup する          ││                              │  │（サーバーとして稼働のみ）     │
│Vault     ││                                ││                              │  │                                │
│delivery  ││                                ││                              │  │                                │
└────┬─────┘└───────────────────────────────┘└──────────────────────────────┘  └────────────────────────────────┘
     │ SMTP / DNS MX
     ▼
外部メールシステム
```

Bisetの主要コンポーネントは五つである。現行の製品UIから実際に呼び出されているか（接続状況）はコンポーネントごとに大きく異なる。

1. **Anchor** — `src/anchor/index.ts` を入口とするidentity provider。公開DID/domain/addressとOIDCを担当する。UI/bootに接続済み。
2. **Mediator** — DIDCommの一時配送（store-and-forward）。`src/mediator/index.ts`を入口とし、UI/bootに接続済み、本番稼働中（`mediator.biset.md`）。永続化はSQLite（`sqlite-store.ts`）であり、以前の単一JSONファイル永続化は現行コードにはない。
3. **Vault** — `src/main.ts`内で動くClient local storage。暗号化長期正本、projection、秘密、server間bindingを保持する。
4. **biset-core** — `src/core/index.ts`を入口とする、公開文書ホスティング・SMTP受信・境界付きingress・legacy Vault delivery/DIDComm ingressを提供する薄いHTTP+SMTP process。**Coordinatorという別プロセスは存在しない**（2026-09-03、commit `57ffa67`で`src/coordinator/`ごと削除）。UI/bootに接続済み、本番稼働中。
5. **biset-mimi**（`src/mimi/index.ts`）— IETF `draft-ietf-mimi-protocol`に準拠したMLS Delivery Service。設計・実装状況の詳細な正本は[PLAN_biset-mimi-server.md](PLAN_biset-mimi-server.md)。`normal`/`anon`/`self`の3プロセスとして本番稼働中（`mimi.biset.md`/`mimi-anon.biset.md`/`mimi-self.biset.md`と推定される命名——`mimiSelfBaseUrl`はruntime configで注入される）。**`self`モードは`main.ts`の`ensureMimiVaultRoom`/`synchronizeMimi`/`watchMimiVaultDeliveries`から実配線されており、単一identityの複数端末間Vault同期（Self Vault）の本番バックエンドである**。§1の判定基準に照らして「実装済み」——旧ARC.mdが同じ基準でCoordinatorを判定していた地位に、現在はbiset-mimi selfモードが立つ。一方`normal`/`anon`モード（複数OIDC ownerを跨ぐ一般group chat hub）は`main.ts`からの呼び出し経路がなく、「部品実装済み」のままである。

`src/core/index.ts`は複数の互換コンポジションを兼ねる薄い composition root であり、最終構成の主要データプレーンではない。`src/protocol/`は各境界が共有するwire schema、canonical encoding、ID、署名対象byte列を定義する。browser、anchor、core、mediator、mail-plugin、mimiは別々のTypeScript設定（`tsconfig.*.json`、6設定）で型検査する。

### 3.1 メッセージング機構の並存（Mail・DIDComm 1:1・DIDComm group chat・MIMI Self Vault）

`PLAN-SIMPIFY.md`が診断する通り、「AさんからBさんにメッセージを届ける／複数端末で同期する」という同じ種類の問題に対して、現状5つの独立した機構が存在する。

| 機構 | 用途 | 状態 |
|---|---|---|
| Mail (SMTP/JMAP) | 従来のメール | 稼働中（§11） |
| DIDComm 1:1 chat | ペアワイズ・共有鍵なし | 稼働中（§12.2〜12.5） |
| DIDComm group chat | フルメッシュ・ペアワイズfan-out、MLS無し | 稼働中、2026-09-03追加（§12.6） |
| MIMI Self Vault | 単一identityの複数端末同期（対人チャットではない） | 稼働中（§9） |

このうち後の4つは互いに独立した実装であり、コード上で一つのパイプに統合されているわけではない。

- **DIDComm 1:1**（Mediator経由）は1:1のダイレクトメッセージ専用。§12.2〜12.5で詳述。
- **DIDComm group chat**（`src/didcomm/group-chat.ts`）は複数人チャットの現行かつ唯一の実装。1:1チャットと同じ`ContactKeyV1`関係を使った full-mesh pairwise fan-out で、共有MLS group state を一切持たない。v1スコープは意図的に狭く、作成時のメンバーとメッセージのみ（作成後のメンバー変更・端末間roster同期・改名・退出・編集/削除/リアクションはない）。§12.6参照。
- **MIMI Self Vault**（biset-mimi `self`モード）はユーザー対ユーザーのチャットではなく、一つのidentityの複数端末間でVault mutationを暗号化配送する専用チャネルである。Self VaultのMLS groupは(a)そのidentityの端末集合を表すroster、(b)VEK導出境界、(c)Vault mutationチャンクそのものを運ぶapplication messageチャネル、の三役を兼ねる。§6・§9で詳述する。

`PLAN-SIMPIFY.md`はこの並存自体を問題として記録している。特に、「グループでチャットする」という一つの問題に対し2026-09-02までConversation GroupsとDIDComm group chatの2実装が同時に存在し、前者は本番デプロイから撤退済みなのにソースが残っていた——これはCoordinatorが「撤退したのに残り続けて後から混乱の元になった」のと同じパターンであり、2026-09-03にConversation Groups側のソースを削除して解消した（§2.2）。DIDComm group chatとMIMI Self Vaultの重複（両方とも「暗号化した内容をhub経由で複数の宛先に配る」という似た問題を別々のchunk機構・別々のretry設計で解いている）は未調査のまま残る課題である（`PLAN-SIMPIFY.md` §2.D、§20参照）。

Anchorの認証は二層である。third partyやbiset-coreから見える外側は通常のOpenID Connect Authorization Code + PKCEである。そのOIDC authorization endpointが必要とするinteractive authenticationだけをOpenID4VP 1.0 Verifierが担当する。WalletはAnchor発行のholder-bound Login Credentialを提示し、Anchorは検証結果を内部principalへ変換してOIDC処理を再開する。

```text
Nextcloud / Forgejo / biset-core / Biset Client
                     │ OIDC Code + PKCE
                     ▼
               Biset Anchor
          OIDC Authorization Endpoint
                     │ login required
                     ▼
          OpenID4VP Verifier (direct_post)
                     ▲
                     │ holder-signed vp_token
              Biset Login Wallet
```

Login CredentialのsubjectはrandomなAnchor account referenceで、DID、SCID、domain、mail address、MLS memberを含まない。初回発行だけはcurrent did:webvh documentの`authentication` keyによるData Integrity proofでbootstrapする。このenrollment APIはBiset profileであり、OpenID4VPのpresentation flowと、将来必要になり得る完全なOpenID4VCI issuer実装を区別する。

## 4. 信頼境界

### 4.1 Client が信頼して保持するもの

- identity の master seed、Root Key、端末 MLS private state（Self Vault groupの自device leaf含む）
- Vault の暗号文、署名 event、SegmentKey と wrap、JMAP projection
- identity 共有の DIDComm / OpenPGP 秘密 credential
- relationship ごとの非公開 DIDComm credential（1:1・group chat 共通）
- 復号済み本文と鍵を扱う実行時メモリ

Client は plaintext の最終処理点であり、侵害された client から既取得の秘密を取り戻すことはできない。MLS revoke（Self Vault の Remove commit、§6.2）は将来 epoch へのアクセスを止めるが、過去にコピー済みの DIDComm/OpenPGP 共有秘密や平文を消去する機能ではない。

### 4.2 biset-core を信頼する範囲

biset-core は可用性、順序付け、quota、SMTP 転送、公開文書の hosting、および（MIMI未設定時 fallback としての）legacy Vault delivery/DIDComm ingress を担う。Vault plaintext、SegmentKey、MLS exporter secret、OpenPGP private key を知る必要はない。

ただし、次の metadata は観測できる。

- identity、device kid、roster（`ensureMimiCoreRoster`がMIMI駆動identityをこのrosterへ反映する。§9.1参照）と操作時刻
- SMTP envelope、接続元、宛先、メッセージ byte 数
- ingress と（legacy fallback時の）Vault delivery の頻度、サイズ、TTL、ACK 状態
- did:webvh、did:web mirror、routing.json の公開内容

SMTP ingress の `protectedPayload` は「core に対する E2EE」を意味しない。通常メールなら core は受信した raw RFC 5322 byte を見ることができる。core が保存する期間を短く限定する設計である。

### 4.3 Standalone mediator を信頼する範囲

Mediator は inner DIDComm JWE を復号しない blind queue である。一方、登録された recipient kid、接続、queue 数、時刻、送受信元 IP、外側 Forward の routing metadata は観測できる。継続会話では公開 did:webvh ではなく relationship 固有の `did:peer:2` を使い、公開 identity との直接相関を mediator の保存状態から外す。DIDComm group chat も同じ relationship 経由で送るため、この分離はグループチャットにも及ぶ。

### 4.4 biset-mimi Self Vault を信頼する範囲

Self Vault hub は MLS application/handshake message の内容を復号しない——providerがVault plaintextやSegmentKeyを知ることはない。一方、Self Vault groupのroom URI、参加device数、epoch/sequence、payload size、時刻は観測できる。checkpointペイロード自体もAES-GCM暗号化されており、hubはmanifest（coveredSeq、transferId、chunkCount、payloadHash）だけを見る。

### 4.5 外部 peer と archive

Peer restore は現在の MLS member による署名と current-epoch grant を要求する。Recovery archive は独立した 32-byte Recovery Key で AES-GCM 暗号化され、利用者自身が archive と鍵を別途管理する。biset-core は archive 本体も Recovery Key も保持しない。

## 5. Identity と did:webvh

### 5.1 Identity の生成

`createNewIdentity`（`src/identity/bootstrap.ts`）は以下を一続きで実行する。

1. 32-byte master seed を生成する。
2. seed を 24-word BIP39 mnemonic として利用者に提示する。
3. SLIP-0010 の `m/0'` から Ed25519 Root Key を導出する。
4. 独立のSpare Keyを生成し、phraseをRoot phraseと別に提示する。
5. `updateKeys=[Root]`、`nextKeyHashes=[hash(Spare)]`とrouting pointerを含むdid:webvh genesisを作る。pre-rotationはこの時点から永久にactiveである。
6. `registerDevice`が端末固有のMLS leaf signature key（random Ed25519）とRoot/Sign二重署名のMLS device credential（`MlsDeviceCredentialV2`）を導出する。

Self/Vault group（MIMI room）への参加は、この時点では**行わない**。identity生成は`deviceKid`/`deviceSignaturePrivateKey`という純ローカルな値をIdentityRecordへ書き込むだけで終わり、Self Vault groupの作成・external joinは`main.ts`のboot flowが`ensureMimiVaultRoom`経由で別途駆動する（2026-09-02の設計変更——旧ARC.mdが記述していた「genesisと同一トランザクションでself-groupを作成/external joinする」フローはもう存在しない）。

メール address は独立して発行せず、`did:webvh:{scid}:{username}.{apexDomain}` の domain から `{username}@mail.{apexDomain}` を導出する。`routing.json.alsoKnownAs` にも best-effort で掲載する。

### 5.2 mnemonic によるログイン

Onboarding UI は入力 domain が既に resolve できる場合、signup から login へ切り替える。`restoreIdentity`はRoot phraseに加えてcurrent Sign phraseを要求し、did:webvh current `updateKeys`と照合する。初回rotation前はRootがSignを兼ねるため、同じRoot phraseを両方に入力する。`restoreIdentity`も`createNewIdentity`と同様、この時点ではSelf Vault groupに触れない——`registerDevice`でこの端末のdeviceKid/署名鍵を作るところまでで終わる。

現行 UI は既存の他端末が生きているかどうかを区別しない。mimiVaultConfigured（`mimiSelfBaseUrl`と`deviceKid`が揃っている）な boot は必ず`ensureMimiVaultRoom`を呼び、routing.jsonに記録されたroom URIが見つかればexternal join、見つからなければ新規roomを作成する。新規作成の場合、その端末はSelf Vaultの唯一のmemberとして始まり、Vault delivery の pull と archive/peer restore（§9.4）は依然として boot path に接続されていないため、mnemonic login だけで過去の Vault 本体が復元されるわけではない。

### 5.3 公開文書

| 文書 | 内容 | 更新認可 |
|---|---|---|
| `did.jsonl` | hash chain、updateKeys、verificationMethod、move | did:webvh proof / current update key |
| `did.json` | 任意の did:web mirror | current did:webvh state による検証 |
| `routing.json` | DIDComm service/keyAgreement、mediator、Self VaultのMIMI room URIポインタ、alsoKnownAs、name、OpenPGP 公開鍵 | Root/current update key の Data Integrity proof |

`routing.json` は operational data を署名付き PUT で管理するが、did:webvh hash chain 自体には含まれない。DIDComm を有効化すると、signed log には `#routing` pointer が追加される。Self Vault の room URI（`mimiVaultRoom`フィールド、`setRoutingMimiVaultRoom`/`mimiVaultRoomFromRouting`）もこの同じ署名付き文書経由で公開・発見される——別のlookup serviceは存在しない。

### 5.4 Domain move

Identity は SCID を維持したまま新しい domain へ移転できる。`moveWebvhIdentity`（`src/identity/webvh/move.ts`）は次を行う。

- 新 location に moved did:webvh log を作り、最後に old location に move を記録する。
- 移転を実行する端末の MLS device credential を新 DID prefix へ更新する。
- `routing.json` を新 location へ移し、埋め込まれた DID prefix を置換する。
- identity record、Vault object store、local MLS self-group state row（Self Vault room metadata・deliveryCursorを含む、同一row内に格納されているため自動的に引き継がれる。§6.3参照）を新 DID key へ re-key する。
- DID を埋め込んだ既存 KeyPackage pool を clear し、次回補充させる。

biset-core roster、Self Vault room自体は raw DID ではなく SCID または移転後のDIDそのもので管理し、移転で列を分割しない。

移転に関係しなかった sibling device は、boot 時の `adoptPendingMove` で old DID を resolve し、document の現在の `id` が異なれば local record を追従させる。追従は一回の boot につき一 hop である。複数回の移転中に中間 domain が廃止されると、自動追従できない。

### 5.5 署名鍵解決の三つの場所

同一の「この kid の鍵は正当か」という検査が三層に存在する。

- core HTTP/roster 認証: `core/identity/webvh-signing-key-resolver.ts`
- MLS Authentication Service: `mls/webvh-authentication-service.ts`
- DIDComm sender 解決: `didcomm/webvh-resolve.ts`

Domain move は document 内の DID prefix を一括変更するため、三者とも caller の古い完全 kid ではなく `#fragment` を current document の `doc.id` に結合して照合する。Core resolver は解決済み `(kid, key)` も process lifetime 中 cache する。DIDComm routing は old domain ではなく、verified log が示す current `doc.id` から取得する。

## 6. Self Vault MLS group

### 6.1 用途

一つの identity に一つの Self Vault MLS group（MIMIの`self`モードroom）が対応する。用途は三つある——旧ARC.mdの二用途（roster + VEK導出境界）に加え、Vault mutationのapplication messageチャネルという三つ目の役割がある（§2.1参照）。

- 現在信頼されている device leaf の roster
- MLS exporter secret から current VEK を導出する暗号境界
- `flushMimiVaultOutbox`/`synchronizeMimiVault`（`src/vault/mimi-vault-sync.ts`）が送受信する、Vault delivery pack をチャンク化したMLS application message（PrivateMessage）そのものの搬送

メール本文や DIDComm Basic Message は依然として MLS application message として送られない——それらはDIDCommのauthcrypt/anoncryptで運ばれる（§12）。Self Vaultが運ぶapplication messageの中身は、あくまで各端末が既に確定させたVaultイベント/オブジェクト/SegmentKeyWrapの暗号化パックであり、ユーザーが読む本文そのものではない。

### 6.2 Lifecycle

Self Vault roomのroom IDは、旧ARC.mdが記述していた「SCIDから決定論的に導出するself-group ID」ではなく、**random**な `mimi://{providerHost}/r/vault-{32 random bytes}` である（`createMimiVaultRoom`）。決定論的なSCID派生ID（`selfGroupIdHex`、`src/mls/self-group.ts`）は今も存在するが、これはbiset-core roster projection（`installCurrentRosterProjection`、mail ingress認可用、§9.1）のためだけに使われる別のラベルであり、Self Vaultそのものの識別子ではない。復旧端末は`routing.json`の署名付き`mimiVaultRoom`ポインタからroom URIを発見する（§5.3）——lookup serviceなしという原則自体は保たれているが、その根拠がSCID決定論からrouting.json発見へ移った点が旧ARC.mdとの実質的な違いである。

- 最初の端末は`createMimiVaultRoom`でroomを作成し、初期commitに`app_data_update`拡張（franking agent、participant list、room metadata）を含めて公開する。
- 後続端末は`joinMimiVaultRoom`でRFC 9420 §11 external commitにより参加する。hubがGroupInfo/ratchet treeをHPKEで新端末のkeyへ封印し、参加後の`deliveryCursor`はこの端末自身のexternal join commitがhub上で見つかったseqから開始する（それ以前のapplication messageはforward secrecyにより復号できないため）。
- boot時に`ensureMimiVaultRoom`が(a)routing.jsonからroomを発見してjoinするか、(b)既存stateをロードするか、(c)新規作成するかを決める。
- 他端末の revoke は`removeMimiVaultDevice`によるRemove + 必須UpdatePathのcommitで行う（2026-09-02実装、"zombie device"個別削除）。削除された端末は新 epoch の exporter secret を導出できない。retired CoordinatorのMLS DS（`removeDeviceFromSelfGroup`/`rotateSelfGroupGeneration`）はどちらもCoordinator専用transportに固定されておりMIMI経路では使えないため、この関数がその代替として新規実装された。
- epoch 更新時、旧 active segment を seal して新 segment を作り、旧 segment の同じ SegmentKey を current VEK で re-wrap する self-grant sweep（`repairCurrentLocalSegmentKeyWraps`）を行う。

`ensureMimiVaultRoom`は`main.ts`のboot内で二度呼ばれる——一度目はUIのread/write setupより**前**（他のself-groupリーダーがこのroomの存在を前提にするため）、二度目はSelf Vaultのpolling/watchを起動する箇所（そこでは単に既存stateの高速読み出し + best-effortなrouting再publishになる）。

### 6.3 Vendored ts-mls

`src/mls/vendor/` は ts-mls v1.6.2 の fork で、利用する ciphersuite を `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` に限定し、noble ベース HPKE を使う。主な差分は以下である。

1. 1 member Remove にも UpdatePath を必須化する security fix。
2. self-remove 後の無限走査回避と application sender leaf attribution。
3. Domain move のため、committer 自身の UpdatePath で credential を置換できる additive hook。

差分には `// biset:` marker があり、`src/mls/vendor/VENDOR.md` に記録される。`test/mls-core.test.ts` と `test/mls-crypto.test.ts` は現行 tree に存在し、fork の主要操作を検査している。この節はARC-MLS.mdのvendored fork記述と食い違わない。

## 7. 鍵と秘密の一覧

| 鍵・秘密 | 単位 | 保存 | 公開・伝播 | 更新状況 |
|---|---|---|---|---|
| Master seed / 24-word Root Key phrase | identity | Client local `IdentityRecord` に hex 平文 | mnemonic を利用者が外部保管 | 自動 rotation なし |
| Root Ed25519 key | identity | Client local `IdentityRecord` に private key 平文 | did:webvh updateKeys、routing.json 署名 | pre-rotation で権限移行可能 |
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

代表的 event kind は `message.add/edit/tombstone`、`mailbox.set`、`keyword.set`、`transport.result`、`didcomm.control`、`contact-key.set`、OpenPGP/DIDComm credential である（`src/protocol/vault.ts`の`VAULT_EVENT_KINDS`が唯一の正本リストであり、`vault/delivery-pack.ts`のdecode allow-listもこの同じ定数を直接参照する——旧ARC.mdが指摘していた「decode allow-listが別に定義されていて`credential.didcomm.set`が漏れている」という不整合は解消済みである）。Raw RFC 5322 と JMAP metadata は別々の encrypted object として一つの `message.add` から参照される。

### 8.2 Segment と epoch

同一 segment の object は同じ random SegmentKey を使う。SegmentKey は current epoch の VEK で AES-GCM wrap され、grantor device の署名を付ける。Self Vault epoch が変わると active segment を seal し、新 segment を作る。過去 segment は鍵自体を変えず、current VEK 向け wrap を追加する。

復号時は必ず current Self Vault state を読み、current epoch の有効な member が署名した wrap だけを受け入れる。古い epoch の wrap へ自動 fallback しない。

### 8.3 IndexedDB transaction

`biset-vault-core` database は、object、event、chunk、segment、key wrap、manifest、projection、JMAP state、各種 durable outbox/receipt/cursor、restore session、transport statusに加え、Clientだけが知るAnchor↔Vault binding、private MLS state、期限付きpending join KeyPackage秘密鍵を持つ。

Ingress commit、local mutation、Vault delivery ingest は、record、projection、JMAP state、次の network ACK/outbox を同一 transaction に書く。Network 送信に失敗しても、次回 retry すべき ACK または delivery intent が local に残る。重複 event/ingress は unique key と content hash で idempotent に扱う。

### 8.4 Projection

Local JMAP projection は cache/read model であり正本ではない。Reducer は event を決定論的順序で適用し、offline の競合を収束させる。壊れた projection は全 event/object を検証・復号して再構築できる。必要な current-epoch wrap が一つでもなければ部分結果を返さず失敗する。

Local garbage collection は実装されていない。Tombstone や completed outbox は一部削除されるが、長期 Vault record の compact/retention policy はない。

## 9. 配送モデル

### 9.1 外部 ingress

Mail または legacy DIDComm adapter は、宛先 identity、offer 時点の device snapshot、expiry、metadata/source evidence、payload hash、opaque payload を core ingress store へ積む。公開 HTTP は adapter offer を公開せず、認証済み device の `/v1/ingress/pull` と `/v1/ingress/ack` だけを提供する。

Pull は一端末に短い exclusive lease（既定 60 秒）を与える。端末は payload hash と protocol を検証し、Vault record、projection、ACK outbox を atomic commit してから署名 ACK を送る。ACK 後、core は payload を消去して tombstone だけを残す。

既定 quota は一 payload 25 MiB、identity あたり pending 100 MiB / 128 件。Mail ingress TTL は 30 日、legacy core DIDComm ingress TTL は 24 時間である。

core のこの ingress-pull 認可（`rosterBackedVaultDeliveryAuthorizer`）は MIMI Self Vault の membership とは完全に独立した、core 自身のroster projectionを見る。MIMI駆動のidentityがこのrosterに載っていなければmail ingressのpullは永久に拒否される（"ingress pull is not authorised"）ため、`ensureMimiCoreRoster`が`installCurrentRosterProjection`（`src/mls/self-group.ts`）経由で、boot のたびにこのidentityをcoreのrosterへ反映する。二台目以降の端末が既存rosterへ参加するには、依然として既存の信頼済み端末がオンラインで一度その反映を行う必要がある——この制約はCoordinator時代から変わっていない。

### 9.2 MIMI Self Vault delivery（現行）

一端末で確定した Vault mutation は、`VaultDeliveryOutboxReader`から読み出され、`flushMimiVaultOutbox`（`src/vault/mimi-vault-sync.ts`）が`splitMimiVaultPayload`でチャンク化し、各チャンクを`PersistedMimiVaultSession.sendApplication`経由でMLS PrivateMessageとして暗号化し、Self Vault roomへ`POST /update/{roomId}`で送信する。1件のoutbox entryのすべてのchunkが受理されて初めてoutbox recordを削除する。

- HTTP応答が失われても、`pending`フィールド（同一identityId row内）に暗号化済みバイト列とdeliveryIdが永続化されているため、次回attemptは同じciphertextを同じdeliveryIdで再送する——プレーンテキストを新しいratchet stateで再暗号化することはない。
- 受信側の`synchronizeMimiVault`は`pullMimiVaultPages`でbounded pull（1ページ32件、最大1024ページ）し、`decodeMimiVaultBatch`でチャンクを再構成する。
- checkpoint（後述、§9.4）は chunk と manifest が別々の非atomicな送信であるため、pull windowがその境界をまたぐと今回のbatchだけでは再構成できないことがある。`recoverSplitCheckpoints`がより広いpull windowで一度だけ再試行する。
- 4種類の名前付きrecovery strategy（`recoverSplitCheckpoints`／`applyCheckpoints`／`ingestDeliveries`／`synchronizeMimiVault`内のepochTooOldリトライ）がそれぞれ独立した関数として切り出されており（2026-09-03の書き直し、commit `71821c3`）、いずれも一件の失敗をbatch全体の失敗に波及させない。失敗は`MimiVaultSyncGap`（`kind`+`detail`）として構造化されたレポートに蓄積され、`synchronizeMimiVault`自体は例外を投げない。呼び出し側（`main.ts`）は`gaps`に`outbox-flush-failed`があれば明示的に例外へ変換し、UIのVault cardをerror状態にする。
- **checkpoint自動再作成のpoisoning対策**（2026-09-03）: 自分のローカルVaultがこのラウンドで一件でも不完全（undecryptable、ingest失敗、checkpoint restore失敗等）であれば、`result.gaps.length === 0`のガードにより新しいcheckpointを作成しない。ローカルが不完全な端末が「最新」を騙って他端末の復元を汚染する問題（2026-09-02発見）への対策である。

### 9.3 現行 Client の接続状態

MIMI Self Vaultのprotocol、SQLite store（hub側）、HTTP transport、projector、outbox/checkpoint、boot/poll loop、live SSE watch（`watchMimiVaultDeliveries`、`mimi-vault-watch.ts`）はすべてブラウザ製品経路へ接続済みであり、複数端末への同一メッセージ配送を実機で確認済みである（`PLAN-SIMPIFY.md`が記録する2026-09-02〜03の一連の"found live"修正がその実運用の証跡になっている）。`message.add`が直接transportとVault delivery projectorの二経路から届く場合は、base projectionに同一immutable metadataがあれば冪等化し、同一batch内の重複または異なるmetadataは競合として拒否する。

legacy core Vault delivery（`/v1/vault-delivery/*`）は、MIMI未設定（`mimiVaultConfigured`が false）の場合の fallback として `main.ts` に残るが、production configは`mimiSelfBaseUrl`を設定済みであるため、現行の実運用経路ではない。

### 9.4 Restore

完全復元の正規経路は biset-mimi Self Vault checkpoint である。

1. Client は event/object と全 SegmentKey を canonical Recovery Archive snapshot にする。MLS exporter secret と device signing key は含めない。
2. root phrase と Self Vault の room ID（旧来のCoordinator `vaultId`に相当する位置に room ID を使う）、provider origin から HKDF-SHA256 で recovery KEK を導出する。
3. fresh random data key で snapshot を AES-GCM 暗号化し、その data key を recovery KEK で wrapする。外側 envelope に DID/SCID/domain/mail address を含めない。
4. `createPortableCoordinatorCheckpoint`/`openPortableCoordinatorCheckpoint`（`src/vault/vault-checkpoint.ts`）——**関数名に "Coordinator" が残っているが、Coordinatorプロセス自体は存在しない**。ドキュメントコメント自身が明言する通り、v2フォーマットは「Vault operatorの間で移植可能」という設計であり、v1（廃止済みCoordinatorが書いたcheckpointの読み込み専用互換）とv2（現在書き込む唯一の形式、biset-mimi向け）を区別する。関数名のリネームは未実施のまま残る技術的負債である。
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

1. 以前の poll interval / Self Vault watch handle / mediator poll handle をすべて停止する（logout の再入で古いidentityのポーリングが残らないようにする）。
2. identity record、MLS/Self Vault、Vault IndexedDB を開く。
3. domain move を passive adoption する（`adoptPendingMove`）。
4. 最初の identity で read model を構成し、**ここで一度目の`ensureMimiVaultRoom`を呼ぶ**——後続のSegmentKeyWrap修復・migration読み出しがSelf Vault stateの存在を前提にするため。続けて`ensureMimiCoreRoster`でcore roster projectionを反映する。
5. 全local identityについて`repairCurrentLocalSegmentKeyWraps`/`migrateLocalSegmentKeysToStorageRoot`を実行する。
6. account UI を構成する（device一覧、removeVaultDevice、editName、moveIdentity）。
7. core 設定と device kid があれば Vault mutation boundary を作り、DIDComm/OpenPGP credential を best-effort で provision し、compose/reply、DIDComm group chat、mail ingress、mediator watch（SSE）を構成する。
8. inbox を描画し、mail ingress を直ちに同期する。
9. mail ingress と DIDComm outboxを 10 秒間隔で poll する。
10. mimiVaultConfigured なら**二度目の**`ensureMimiVaultRoom`（軽量な再読み出し）を経て`synchronizeMimi`を即時実行し、続けて`watchMimiVaultDeliveries`（SSE）を起動する。DIDComm 1:1/group chatの受信もmediator SSE watch（`watchMediator`、ポーリングではない——2026-09-01にConversation Groupの3-message handshakeが15秒poll intervalで数十秒待たされる問題を機にSSEへ切り替えた）経由である。

core 設定がなければ UI は local projection の read-only viewer として起動する。

## 11. Mail transport

### 11.1 受信

Core は Bun TCP listener 上に byte-oriented SMTP state machine を構成する。EHLO/HELO、MAIL、RCPT、DATA、RSET、NOOP、QUIT、STARTTLS を扱い、25 MiB 制限を広告・強制する。SMTPUTF8 と AUTH は提供しない。宛先 `{user}@mail.{apexDomain}` を `{user}.{apexDomain}` の did:webvh identity と roster へ解決し、raw RFC 5322 byte を変更せず ingress へ積む。

TLS certificate/key が設定されれば STARTTLS を提供する。未設定でも server は起動し、plaintext SMTP となる。接続元、HELO、envelope sender、TLS 使用有無を source evidence として保存する。

Client は ingress を pull し、raw message と表示 metadata を Vault に確定する。MIME 全体を構造化するのではなく、bounded header summary と本文表示のための最小処理を行う。

`src/mediator/mail-plugin/`（`bridge.ts`/`listener.ts`/`index.ts`）は、legacy core SMTP + ingress-pull 経路とは別の、受信メールをそのままDIDComm Forward（`MAIL_BRIDGE_INBOUND`）としてmediator経由で配送する代替実装である。`main.ts`側の`onMessage`ハンドラは`MAIL_BRIDGE_INBOUND`型のプレーンテキストを既に処理できるが（§12.5）、送信側（`buildMailSubmitter`/`CoreMailSubmissionTransport`）はまだこの新方式に切り替わっておらず、`main.ts`内のTODOコメントが「plugin側の`submit`メッセージ型ができ次第、置き換える」と明記する未完了の移行である。専用のbuildスクリプトはpackage.jsonにまだない。

### 11.2 送信

Client はまず local Vault に outbox message を commit する。`EmailSubmission/set` は device leaf key で raw RFC 5322、MAIL FROM、recipient、時刻を署名し、`/v1/mail/submit` へ送る。Core は current roster と did:webvh 公開鍵で認証してから MX lookup と SMTP delivery を行う。

成功時は `transport.result` と `mailbox.set(sent)` を Vault に記録する。失敗時は temporary-failure として outbox に残すが、自動 retry scheduler と DSN はない。複数 domain の一部失敗も全体を temporary-failure に畳むため、recipient 単位の再送制御は未実装である。

### 11.3 OpenPGP

実装済みの endpoint primitive は、OpenPGP credential 生成、Vault への private key 保存、routing.json への public certificate 公開、RFC 3156 encrypted packet 抽出、packet 復号と署名検証である。

一方、`main.ts` の compose/send は常に plaintext RFC 5322 を構築し、recipient public key 解決や encrypt/sign を呼ばない。受信 UI も OpenPGP decrypt primitive を呼ばない。よって現在の OpenPGP は **鍵 provision と検証済み部品まで** であり、実際の mail E2EE は製品経路に未接続である。Autocrypt header の生成・peer state もない。

## 12. DIDComm

### 12.1 Public front door

Boot 時、最初の端末が identity-shared X25519 credential を Vault に作り、routing.json の一つの `keyAgreementVerificationMethod` として公開する。Sibling は同じ encrypted credential を Vault 同期経由で読む設計である。Mediator URL が設定されていれば各 mediator へ Coordinate Mediation 2.0 で登録し、成功した endpoint だけを DIDCommMessaging service として公開する。全 mediator が失敗した場合は legacy core `/v1/didcomm/ingress` を fallback とする。

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

Standalone mediator は自身の did:peer identity、connection keylist、queueを**SQLite**（`src/mediator/sqlite-store.ts`）に保存する（旧ARC.mdが記述していた単一JSONファイル永続化は現行コードに存在しない）。Coordinate/Pickup request は DIDComm authcrypt の sender X25519 keyで認証する。did:webvh sender は公開 routing を resolve し、did:peer sender は self-certifying DID から鍵を得る。

Queue は recipient kid あたり最大 256 件、保持 30 日で、満杯時は古い正当 message を捨てず sender を拒否する。Pickup は non-destructive delivery の後、`messages-received` ACK で削除する。Connection は最大 10,000、connection ごとに最大 32 kid。Replay guard は既定 10 分 / 50,000 ID、resolved key cache TTL は 10 分で stale-while-refresh 動作をする。HTTP surfaceは単一の `POST /` （DIDCommメッセージ種別で内部分岐）、`GET /.well-known/did.json`、`GET /stream`（SSE、client側の`watchMediator`が使う）の3経路である。

`relay-poller.ts`は、あるmediatorが別のupstream mediatorへ自分自身をclientとして登録し（`MEDIATOR_RELAY_UPSTREAM_URL`）、自分宛のForwardをunwrapして自分のqueueへ再Forwardする、任意のmulti-hop中継機能である。routing.jsonの`routingKeys`（outermost-first）でこの中継段を名指しできる。dispatch()自体はこの機能の有無で変わらない——upstream側からは通常のend-user deviceに見え、downstream側からは通常のForward requestに見える。

DBファイルへの書き込み失敗の扱いはSQLite化により旧ARC.mdの「JSON書き換え失敗はwarningのみ」という記述とは前提が変わっている——本書では未検証のため、この点は次回調査で確認すべき既知の空白として残す。

### 12.5 Legacy core DIDComm path

Core の `/v1/didcomm/ingress` と client の core ingress projector は残っており、mediator 未設定時の fallback になる。新しい独立 mediator path と二重に存在するため、運用時は routing.json がどちらを広告しているかを明示する必要がある。同じ`onMessage`ハンドラが`MAIL_BRIDGE_INBOUND`型のメッセージ（§11.1のmail-plugin bridge）も処理する——mediator watchループは、DIDComm 1:1、DIDComm group chat control/content、mail bridgeの3種のペイロードを型タグで振り分ける単一の受信経路である。

### 12.6 DIDComm group chat

2026-09-03（commit `1004436`）に追加された、複数人チャットの現行かつ唯一の実装。`src/didcomm/group-chat.ts`と`group-chat-store.ts`（IndexedDB、device-localなroster cache）、`main.ts`側の`createAndSendDidCommGroup`/`sendDidCommGroupMessage`/`handleDidCommGroupInvite`/`handleDidCommGroupContent`から構成される。MLS共有group stateを一切使わない full-mesh pairwise fan-out であり、1:1チャットと同じ`ContactKeyV1`関係を再利用する。

- アドレススキームは`didcomm-group:<groupId>`（compose/replyの`toAddrs`が2件以上のDIDのとき自動的にグループ作成へ分岐する）。
- グループ作成（`createAndSendDidCommGroup`）は各招待者へ`GROUP_INVITE`（version, groupId, 送信者含む完全なmembers一覧, name）を送り、続けて`sendDidCommGroupMessage`で founding message を送る。招待の一部が失敗しても founding message は全メンバー分キューに積まれ、outboxのretryで後から届く。
- 受信側の`handleDidCommGroupInvite`は招待メッセージを`groupChatStore`へmergeし、まだ`ContactKeyV1`を持たない各メンバーとの handshake を非同期に(awaitせず)開始して mesh を完成させる。
- v1スコープは意図的に狭い——グループ作成後のメンバー変更、端末間でのroster同期（同一identityの複数端末は個別にrosterを持つ）、改名、退出、メッセージの編集/削除/リアクションはいずれも未実装。
- **2026-09-03に修正された既知の鋭利な角（commit `11f0a62`）**: グループメッセージは1つの`emailId`をN人のrecipientで共有するが、outbox flushはかつて`mailbox.set{sent:true}`という per-email フラグだけを見て「送信済みだから削除してよいoutbox行」を判定していた。1人目のrecipientへの送信成功がそのフラグを立てると、同じflushパス内の他のrecipient行が「クラッシュ後の残骸」に見えて実際には一度も送信されずに削除される——2人以上の招待を伴うグループ作成メッセージが最初の1人にしか届かない、という形で現れた。修正後は各recipient行ごとに`noteDidCommOutboxAttempt`で試行を記録し、per-email フラグに頼る早期削除を行わない。同じコミットで、1recipientの送信失敗が同一flushパス内の他recipientへの配送を止めてしまう`break`も`continue`に直した。

## 13. Core API と保存状態

### 13.1 HTTP surface（biset-core）

| Prefix / path | 役割 |
|---|---|
| `/healthz` | 常時利用可能な health |
| `/.well-known/did.jsonl` | did:webvh log GET/PUT/POST |
| `/.well-known/did.json` | did:web mirror GET/PUT |
| `/.well-known/routing.json` | operational routing GET/PUT |
| `/v1/roster/*` | signed roster install/read（Self Vault memberの反映先。§9.1） |
| `/v1/ingress/pull`, `/ack` | endpoint claim と durable ACK |
| `/v1/vault-delivery/append`, `/pull`, `/ack` | legacy Vault delivery（MIMI未設定時のみの fallback、§9.3） |
| `/v1/restore/*` | request/offer/pull/cancel の control のみ |
| `/v1/mail/submit` | signed outbound SMTP submission |
| `/v1/didcomm/ingress` | legacy DIDComm ingress fallback |

旧ARC.mdが記載していた `/v1/mls/*`（group create/commit/external commit/GroupInfo/KeyPackage/delivery）は現行の`src/core/app.ts`に存在しない——Self Vaultのgroup管理はbiset-mimi自身のHTTP surface（§13.2）が担い、core はもはやMLS DSを一切hostしない。

全 route に CORS `*`、許可 header `Authorization, Content-Type`、method `GET, POST, PUT, OPTIONS` を付ける。認証は CORS ではなく payload signature と current roster で行う。

### 13.2 HTTP surface（biset-mimi）

IETF draft-ietf-mimi-protocol §5.2/§5.3のprovider-facing routesを実装する（`src/mimi/http.ts`）。主なpathは、well-known protocol directory、`GET /stream`（deliveries、SSE watch tokenで認可）、franking agentデータ、asset proxy download、`POST /notify/*`（federation fanout受信）、`POST /groupInfo/{roomId}`（external join、`allowExternalJoin`が有効なdeploymentのみ既定拒否を解除——`self`モードだけがこれを有効化する）、abuse report、consent request/update、identifier query、`POST /keyMaterial/{targetUser}`、`POST /keyPackage`、`POST /update/{roomId}`（room作成・external join commit・通常commit・checkpoint application messageのいずれも、この単一endpointを通る）である。すべてのbodyはbiset独自のprovider-internal credential signature（`authorizer.ts`）で認証し、Anchor OIDCトークンは要求しない——membershipとMLS leaf署名だけが認可根拠である。

### 13.3 Fail-closed composition

`DATABASE_PATH` がなければ core は health endpoint だけを公開する。Full deployment には `DATABASE_PATH` と `APEX_DOMAIN` が必須である。`WEBVH_DATA_DIR` を省けば public document route を公開せず、mail hello name がなければ library composition 上は mail submit route を公開しない。Optional component 欠落時に open relay へ fallback しない。biset-mimiも同様に`MIMI_DATABASE_PATH`必須で、未設定時は起動時に例外で落ちる（healthのみ公開という緩やかなfallbackはない）。

一つの SQLite database に roster、bounded ingress、legacy Vault delivery、restore control を置く（core側）。Self Vault/group chatのMLS状態はbiset-mimi自身の別プロセス・別SQLiteファイルに置く（`MimiDeploymentOptions.mode`ごとに専用DBファイルが必須）。Webvh/routing files は `WEBVH_DATA_DIR` に置く。Plaintext mailbox projection、private identity key、SegmentKey、MLS exporter secret はどちらのSQLiteにも置かない。

### 13.4 Hosting limits

- did.jsonl: request 1 MiB、identity ごと最大 10,000 entry / 16 MiB
- did.json と roster/restore/ingress control: 小さい bounded body
- routing.json: 1 MiB
- mail submit: 25 MiB

Core の expiry sweep は多くの場合 request 時に実行される。常時 timer/job による vacuum はなく、tombstone と SQLite file の物理縮小も運用者責任である。

## 14. 可用性、失敗、冪等性

- Client の local transaction を network ACK より先に行うため、response loss は再送で回復できる。
- biset-mimi Self Vault送信は`pending`フィールドへ暗号化済みciphertextとdeliveryIdを先に永続化してから送信するため、HTTP応答喪失は同一ciphertextの再送で回復し、平文の二重暗号化を起こさない（§9.2）。
- Ingress lease により複数端末が同じ外部 body を同時処理しない。Lease expiry 後は別端末が retry できる。
- Core の TTL/quota gap は `restoreRequired` として明示し、空の catch-up と区別する——ただしこのシグナルをUIへ配線する処理自体は未接続である（§9.4）。
- DIDComm mediator SSE watch と mail ingress poll は network error を log して次周期/再接続に retry する。
- Outbound mail temporary failure は durable outbox に残るが scheduler がないため、利用者操作なしには retry されない。
- OpenPGP / DIDComm provision、domain move adoption、Self Vault maintenanceの一部は boot を止めない best-effort であり、警告が console にしか出ない。
- `routing.json` 更新は fetch-merge-put だが version/ETag compare-and-swap がなく、複数端末の同時更新で last-write-wins となり得る。
- MIMI Vault syncの各recovery strategyは失敗を`gaps`として記録し、一件の失敗が他の全項目の適用を止めない（§9.2）——これは今日一日で6種類のretry/skipロジックを個別`if`として積み増した末に、名前付き関数へ整理し直した結果である（`PLAN-SIMPIFY.md` B完了）。

## 15. Security properties と限界

### 15.1 実装されている主な性質

- Vault object は authenticated encryption、content-derived ID、ciphertext hash で改ざんを検出する。
- Vault event と SegmentKeyWrap は current MLS member device の Ed25519 signature を要求する。
- Device revoke 後の新 epoch は UpdatePath により rekey され、removed member は将来 VEK を導出できない。
- biset-core は roster install caller に recipient snapshot を選ばせず、current roster から固定する。
- 新規端末は過去 delivery recipient へ遡及追加されない。
- External ingress ACK は durable Vault commit 後だけ送る。
- DIDComm mediator は未登録 recipient への open forwarding を拒否する。
- Relationship ごとの pairwise DID により、継続会話（1:1・group chat 双方）を公開 identity front door から分離する。
- biset-mimi hub は MLS application/handshake message の内容を復号しない（§4.4）。
- Canonical encoding と domain-separated signing/hash labels を protocol 全体で使う。

### 15.2 未解消リスク

1. **Local secret at rest（高）** — master seed、Root private key、DIDComm private cache、SegmentKey が IndexedDB 平文。Passkey/WebAuthn PRF sealing が必要。
2. **Restore UI/boot 未接続（高）** — TTL gap や端末全損時に、実装済みcheckpoint/peer/archive primitive を利用者が起動できない（§9.4）。
3. **Credential revoke gap（高）** — device revoke だけでは既取得の identity-shared DIDComm/OpenPGP private key を無効化できない。Rotation/republication/re-encryption policy がない。
4. **端末/鍵管理の概念分裂（高、`PLAN-SIMPIFY.md`が新たに明文化）** — Coordinator撤去でSign Key rotationの一括世代交代機構（旧`rotateKeyRotation`）が代替なしに消えた。MIMI room membership（個別device除去）とSpare Key rotationは今なお別々のコードパスであり、統一設計がない（§20）。
5. **OpenPGP mail E2EE 未接続（中）** — 鍵を公開するため相手は暗号化可能だが、通常 UI が復号しない。公開 capability と製品挙動が一致しない。
6. **Relationship handshake 非永続（中）** — reload で ACCEPT を復号不能にする。DIDComm group chatのmesh-completion handshakeも同じ揮発性state（`pendingByOwnKid`/`pendingByCounterparty`）に乗るため、同じ制約を受け継ぐ（§12.2、§12.6）。
7. **DIDComm dedupe lookup 未接続（中）** — projector の `alreadyProcessed()` は常に false。同一 message ID は reducer conflict で拒否されるが、静かな idempotent skip ではない。
8. **Routing update race（中）** — ETag/CAS なし。複数端末同時更新で field loss の可能性。
9. **Domain multi-hop adoption（中）** — 一 boot 一 hop、中間 domain 廃止で停止。
10. **DIDComm group chatのクロスデバイスroster未同期（中、新規）** — `group-chat-store.ts`はdevice-localなIndexedDBキャッシュであり、同一identityの複数端末間でグループroster自体は同期されない（v1の既知の受容済み制約）。
11. **DIDComm group chatとMIMI Self Vaultの機構重複（低〜中、未調査）** — 両者とも「暗号化した内容をhub経由で複数宛先に配る」を別々のchunk機構・別々のretry設計で解いている。共有可能な部分の有無は`PLAN-SIMPIFY.md`が今後の調査課題として明示的に保留している（§3.1、§20のD）。
12. **No background/push（運用）** — page が閉じている間は pull せず、30 日を越えると restore が必要。
13. **Mediator relay-poller/DB write failureの挙動未検証（運用、新規）** — SQLite化（§12.4）後のDB書き込み失敗時の扱いは本調査では未確認。

## 16. Protocol versioning

Wire record は原則 `version: 1` を持ち、decoder は shape、canonical serialization、hash、署名、identity/epoch binding を検証して fail closed する。Opaque ID は domain-separated hash または UUID として扱う。

互換性を保つ際は、TypeScript union に event kind を追加するだけでは不十分である。Wire decoder の allow-list、Vault reducer の explicit no-op/application rule、archive decoder、delivery projector、テスト fixture を同時更新する必要がある。`src/protocol/vault.ts`の`VAULT_EVENT_KINDS`を`vault/delivery-pack.ts`のdecoderが直接参照する現行の実装は、この cross-layer checklist を単一の正本へ収束させた一例である（§8.1）。

Legacy core DIDComm ingress と standalone mediator は並存している。廃止時には routing publication、client polling、core route、adapter test を一括で移行し、中途半端な二重 delivery を避ける。legacy core Vault delivery（§9.3）とMIMI Self Vaultも同じ意味で並存しており、廃止する場合は同様の一括移行が必要になる。

## 17. Build、設定、運用

### 17.1 Client

- `bun run build` — `src/main.ts` と `src/sw.ts` を browser IIFE に bundle し、`scripts/inline.mjs` で `dist/index.html` に inline 化する。対象commitでの実測は app.js 約1.1MB、inline HTML約1195KB。
- Runtime config — `window.__BISET_CONFIG__` の `apexDomain`、`coreBaseUrl`、`mediatorUrls`、`mimiSelfBaseUrl`、`anchorBaseUrl`、`anchorOidcClientId`。
- `mediatorUrls` は未設定時空配列でlegacy core DIDComm pathへfallbackする。`mimiSelfBaseUrl`が未設定であればMIMI Self Vault機能全体が起動せず、legacy core Vault delivery（§9.3）が代わりに使われる。production configは両方とも設定済みである。

### 17.2 Core environment

| 変数 | 必須性 / 既定 |
|---|---|
| `PORT` | 既定 8787 |
| `DATABASE_PATH` | full deployment に必須。未設定は health only |
| `APEX_DOMAIN` | DATABASE_PATH と同時に必須 |
| `WEBVH_DATA_DIR` | public document hosting に必要 |
| `SMTP_PORT` | 既定 25 |
| `SMTP_HOSTNAME` | 既定 `0.0.0.0` |
| `SMTP_HELLO_NAME` | 既定 `mail.{APEX_DOMAIN}` |
| `SMTP_MAIL_DOMAIN` | 任意の受信 mail domain override |
| `SMTP_TLS_CERT_PATH`, `SMTP_TLS_KEY_PATH` | 両方あれば STARTTLS |

`bun run build:core` は Linux x64 向け standalone Bun binary を生成する。

### 17.3 Mediator environment

| 変数 | 必須性 / 既定 |
|---|---|
| `MEDIATOR_PUBLIC_URL` | 必須 |
| `MEDIATOR_DATABASE_PATH` / `MEDIATOR_DATA_DIR` | いずれか必須（SQLiteファイルパス。§12.4） |
| `PORT` | 既定 8791（8790のlegacy coreと衝突させない） |
| `MEDIATOR_HOST` | 既定 `127.0.0.1` |
| `MEDIATOR_ALLOWED_ORIGINS`、`MEDIATOR_MAX_REQUEST_BYTES`、`MEDIATOR_RATE_LIMIT_PER_MINUTE`、`MEDIATOR_MAX_CONNECTIONS`、`MEDIATOR_MAX_KEYS_PER_CONNECTION`、`MEDIATOR_MAX_QUEUE_ITEMS`、`MEDIATOR_MAX_QUEUE_BYTES`、`MEDIATOR_MAX_MESSAGE_BYTES`、`MEDIATOR_QUEUE_TTL_MS`、`MEDIATOR_REPLAY_TTL_MS`、`MEDIATOR_MAX_REPLAY_IDS` | いずれも既定値ありの運用チューニング |
| `MEDIATOR_RELAY_UPSTREAM_URL` | 任意。設定すればmulti-hop relay pollerを起動する（§12.4） |

`bun run build:mediator`（`build:didcomm-mediator`のalias）で Linux x64 binary を生成する。`src/mediator/mail-plugin/`は独立したbuildスクリプトを持たない（§11.1）。

### 17.4 MIMI environment

| 変数 | 必須性 / 既定 |
|---|---|
| `MIMI_DATABASE_PATH` | 必須 |
| `MIMI_MODE` | 必須。`normal` または `anon`（`self`はdeployment.tsの`mode`オプション経由——index.tsのCLI env経路自体は`normal`/`anon`しか受け付けない点に注意） |
| `MIMI_PUBLIC_BASE_URL` | 任意。protocol directoryが広告する公開origin |
| `MIMI_ALLOW_EXTERNAL_JOIN` | 既定false。`true`でSelf Group向けexternal join（`POST /groupInfo`）を有効化 |
| `PORT` | 既定 8793 |

`bun run build:mimi` で Linux x64 binary を生成する。

## 18. 検証状況とコード品質

対象 commit（`11f0a62`）で以下を実行した。

- `bun run typecheck` — `tsc --noEmit`（root/browser）+ `tsconfig.anchor.json` + `tsconfig.core.json` + `tsconfig.mediator.json` + `tsconfig.mail-plugin.json` + `tsconfig.mimi.json` の6設定すべて成功。旧ARC.mdの「browser/core/mediatorの三設定」から、anchor・mail-plugin・mimiの3設定が増えている。
- `bun run build` — 成功。`app.js` 約 1.1 MB、`sw.js` 183 bytes、inline HTML 約 1195 KB（旧ARC.mdの約1.07MBから増加——biset-mimi client transport一式の追加が主因と見られる）。
- `bun run test` — `find test -name '*.test.ts'` で数えて **140個** の `*.test.ts` file（旧ARC.mdの「133個」から7増加）を serial 実行し、すべて成功（0 fail）。

テストは canonical protocol、Vault crypto/store、ingress/legacy delivery/restore、SQLite、Self Vault MLS、domain move、SMTP、OpenPGP primitive、DIDComm crypto/mediator/private relationship/group chat mesh、MIMI Vault sync/chunks/client transport/room/session/room-migrationを広く覆う。`test/vault-mimi-sync.test.ts`は意図的に一部エラーログ（undecryptable application entry、checkpoint chunk不足）を出力しながらpassする——それらは§9.2の各recovery strategyが正しくgapとして記録して回復することを検証するテストである。一方、`main.ts` の boot wiring を browser E2E として網羅しておらず、「部品のテスト成功」と「製品経路への接続」を検出できていない箇所がある。

`bun run knip` は失敗する（exit code 1）。現状の debt は次のとおりである。

- unused files: 11（`src/context.ts`、`src/mediator/identity.ts`、`src/mls/keypackage-store.ts`、`src/mls/vendor/codec/json.ts`、`src/mls/vendor/customCredential.ts`、`src/oid4vp/file-bridge.ts`、`src/oidc/client.ts`、`src/protocol/mls-ds-wire.ts`、`src/route.ts`、`src/state.ts`、`src/types.ts`）
- unused dependencies: 5（`@scure/bip32`、`bittorrent-dht`、`cborg`、`hash-wasm`、`jmap-jam`）
- unused devDependencies: 2（`@hpke/core`、`@types/wicg-file-system-access`）
- unlisted binaries: 2（`tsc`、`knip`）
- unresolved imports: 4（`scripts/pkarr-smoke.mjs`が参照する`src/did/keys.ts`等4ファイル——旧did:dht/Pkarr実装の残骸。did:webvh一本化後もこのスクリプトだけ削除されずに残っている）
- unused exports: 418
- configuration hints: 4（`deploy.sh`のignoreBinaries、`src/core/index.ts`/`src/anchor/index.ts`/`src/mediator/index.ts`のentry pattern重複）

したがって `bun run check`（typecheck && knip && test）は typecheck/test が正常でも knip で非 zero になる。旧ARC.mdの「unused file 6、unused dependency 4、unused devDependency 1」から負債は増加しており、Coordinator撤去・Conversation Groups撤去に伴う未使用コードの掃除（`src/route.ts`/`src/state.ts`/`src/types.ts`等が新たにunused filesへ入っている可能性が高い）がまだ追いついていない。

## 19. 実装状態の総括

| 領域 | 状態 | 判定 |
|---|---|---|
| did:webvh create/resolve/update/pre-rotation/domain move | UI まで接続 | 実装済み |
| Self Vault MLS group、roster、individual device removal、VEK | UI/boot と biset-mimi(self) に接続 | 実装済み |
| Local encrypted Vault + JMAP projection | UI read/write に接続 | 実装済み |
| SMTP ingress/outbound | Core と UI に接続 | 実装済み（retry/DSN は未完成） |
| Core bounded ingress | 10 秒 poll に接続 | 実装済み |
| MIMI Self Vault delivery（checkpoint含む） | poll/SSE watch/outbox/gaps report まで UI に接続 | 実装済み |
| legacy core Vault delivery | protocol/store/testあり、MIMI未設定時のみのfallback | 部分実装（現行本番では不使用） |
| Mnemonic login | identity/device joinとSelf Vault external joinまでUI接続 | 部分実装 |
| Anchor OpenID4VP login | Verifier、credential、session、Wallet enrollment/presentation、file bridge、OIDC PKCE callback/token検証 | 実装済み（consent UIは未実装） |
| Peer/archive restore | primitive と test あり、UI/boot なし | 部品実装済み |
| OpenPGP | key provision/publication/crypto primitive あり、mail path 未接続 | 部分実装 |
| DIDComm public front door + legacy core ingress | UI/boot に接続 | 実装済み |
| Standalone mediator（SQLite永続化） | binary、protocol、SSE watch、relay-poller あり | 実装済み、deployment 設定なし |
| Private relationship DIDComm 1:1 | UI send/receive と mediator E2E あり | 実装済み、pending durability なし |
| DIDComm group chat | UI send/receive、mesh-complete招待、mediator SSE経由の受信まで接続 | 実装済み、v1スコープ限定（roster同期・メンバー変更等なし） |
| ~~MLS Conversation Groups~~ | ~~ソース削除済み~~ | 廃止（2026-09-03） |
| biset-mimi normal/anon（一般group chat hub） | サーバーとして稼働、client呼び出し経路なし | 部品実装済み |
| Multi-device product experience | Self Vaultにより大きく前進したが、account switching・端末/鍵管理の統合は未完成 | 部分実装 |
| Remote JMAP account | transport/router のみ | 部品実装済み |
| ActivityPub | adapter なし | 未実装 |
| Web Push / background sync | Service Worker shell のみ | 未実装 |

## 20. 推奨する次の作業順

本節はアーキテクチャ全体の観点からの次の一手であり、`PLAN-SIMPIFY.md`が今日の障害対応の延長として立てた作業計画（A・B完了、C・D未着手）そのものではない。両者を踏まえた上で、以下を推奨する。

1. **端末/鍵管理を1つの概念に統合する**（`PLAN-SIMPIFY.md` C、最優先）。「MIMI Self Vault roomのmember = このidentityの端末」という前提のもとで、追加・削除・ローテーションを1つのAPIへまとめる。Coordinator撤去で失われたSign Key rotationの一括世代交代（旧`rotateKeyRotation`相当）をこのタイミングで作り直す必要がある（§15.2のリスク4）。
2. `restoreRequired`を専用UIへ接続し、biset-mimi checkpoint・Peer/Archive restoreを開始できるようにする。現在はsystem messageまでで止まる（§9.4、§15.2のリスク2）。
3. OpenID4VPのconsent/account chooser UIとcredential管理/revoke UIを追加する。Verifier、session、永続provider compositionは実装済み。
4. Relationship handshake（1:1・group chat招待の双方が使う`pendingByOwnKid`/`pendingByCounterparty`）をcrash-safeにする。DIDComm group chatが今日追加された今、この一点の脆さが波及する経路が増えている（§15.2のリスク6）。
5. Device revoke後のidentity/DIDComm/OpenPGP credential rotationをcrash-safeにする（§15.2のリスク3）。
6. DIDComm group chatとMIMI Self Vaultの機構重複を調査する（`PLAN-SIMPIFY.md` D）。B・Cが片付いた後で、共有できるchunk/retry設計があるかを検討する——現時点では推測でしかない。
7. Peer restoreとRecovery archive export/importをUIへ接続し、identity復旧と履歴復旧を分けて表示する。
8. knip debtとlegacy dependency/scriptを整理し、`bun run check`をrelease gateとして通す。特に`scripts/pkarr-smoke.mjs`（did:dht/Pkarr、既に廃止済みの機構）と、Coordinator/Conversation Groups撤去後に取り残されたと見られるunused files（`src/route.ts`/`src/state.ts`/`src/types.ts`等）の要否を精査する。
9. `createPortableCoordinatorCheckpoint`/`openPortableCoordinatorCheckpoint`（`src/vault/vault-checkpoint.ts`）など、Coordinator撤去後も残る名称上の負債をリネームする。動作に影響しないが、次にこのコードを読む人が同じ調査（「Coordinatorはまだ動いているのか」）をやり直す原因になる。

## 21. 主要ソース案内

| 関心 | 主なファイル |
|---|---|
| Client composition | `src/main.ts`, `src/ui/*`, `src/ui/config.ts` |
| Identity lifecycle | `src/identity/bootstrap.ts`, `src/identity/record-store.ts` |
| did:webvh / Anchor | `src/identity/webvh/*`, `src/anchor/webvh/*`, `src/anchor/oidc*.ts`, `src/anchor/oid4vp.ts`, `src/oid4vp/*` |
| Self Vault MLS | `src/mls/self-group.ts`（roster projectionのみ生存）, `src/mls/group.ts`, `src/mls/mimi-vault-room.ts`, `src/mls/mimi-vault-session.ts`, `src/mls/mimi-vault-watch.ts`, `src/mls/mimi-client-transport.ts`, `src/mls/vendor/VENDOR.md` |
| Vault | `src/vault/store.ts`, `objects.ts`, `events.ts`, `crypto.ts`, `delivery-pack.ts`, `restore-*`, `vault-checkpoint.ts` |
| MIMI Vault sync（client側data plane） | `src/vault/mimi-vault-sync.ts`, `src/vault/mimi-vault-chunks.ts` |
| biset-mimi（hub本体） | `src/mimi/index.ts`, `deployment.ts`, `http.ts`, `store.ts`, `wire.ts`, `protocol-types.ts`, `authorizer.ts`, `fanout.ts`, `room-policy.ts` |
| Local JMAP | `src/local-jmap/gateway.ts`, `reducer.ts`, `vault-mutation-sink.ts`, `indexeddb.ts` |
| biset-core composition | `src/core/index.ts`, `src/core/deployment.ts`, `src/core/app.ts` |
| SMTP | `src/core/adapters/mail-smtp-*`, `src/mail/*`, `src/mediator/mail-plugin/*` |
| DIDComm 1:1 | `src/didcomm/relationship.ts`, `basicmessage.ts`, `send-message.ts`, `ingress-projector.ts`, `src/vault/contact-key*`, `src/vault/didcomm-*` |
| DIDComm group chat | `src/didcomm/group-chat.ts`, `src/didcomm/group-chat-store.ts` |
| Standalone mediator | `src/mediator/index.ts`, `deployment.ts`, `server.ts`, `sqlite-store.ts`, `queue.ts`, `connections.ts`, `relay-poller.ts` |
| Wire schemas | `src/protocol/*` |
| Tests | `test/`, 特に `test/protocol/*`, `test/mediator-relationship-handshake.test.ts`, `test/vault-mimi-sync.test.ts`, `test/didcomm-group-mesh.test.ts`, `test/mls/mimi-*.test.ts` |

---

この文書は「意図」ではなく上記 commit の現状を記録する。将来の変更でコードと本書が食い違った場合は、まず実行経路と wire compatibility をコード・テストで確認し、その後この調査基準 commit と実装状態表を更新する。
