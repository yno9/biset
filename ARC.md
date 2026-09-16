# Biset アーキテクチャ

> MLS の vendored fork（ciphersuite、UpdatePath fix、vendor diff の一覧）については `src/protocol/mls/VENDOR.md` を参照する。**ただし MLS は現行のクライアント経路では使われていない**——複数端末同期は MIMI Self Vault から DIDComm 上の **Vault Sync**（§9）へ全面的に置き換わった。残った MLS 資産の現況は §6 と §19 にある。

> 調査基準日: 2026-09-16（Asia/Tokyo）
> 調査対象: `~/biset` の作業ツリー（`PLAN_vault-sync-redesign.md` の Phase 0〜4 実装完了時点）。
> 前回基準（2026-09-06）からの最重要変更は五つ——
>
> 1. **MIMI Self Vault / MLS self-group による複数端末同期の廃止**
> 2. **DIDComm 上の record 同期（Vault Sync）への全面移行**——メタデータだけを運ぶ delta ではなく、
>    event・暗号文 object・SegmentKeyWrap を**同じ経路で一緒に**運ぶ
> 3. **Yjs CRDT の除去**と、**ログ層 / projection 層**の二層分離（§8・§9）
> 4. **汎用 JMAP 形式の export / import**（複数の不完全なファイルから差分的に収束する、§9.4）
> 5. **File System Access API による Markdown ミラーの再実装**（§10.4）
>
> 状態: 現行コードを正とした実装アーキテクチャ。将来案は明示的に区別する。
>
> **⚠️ メールは実装されていない。** native login と一緒に削除され、再実装には did.md 側の
> mediator が必要（§11、`tasks/W3-wallet-mail-design-proposal.md`）。
> DIDComm による 1:1・グループチャット・複数端末同期は動作する。
>
> **実機 2 台での同期の通し確認だけが残っている。** typecheck / test（100 file）/ build / reachability は
> すべて通っており（§18）、2026-09-15 前後に実機で観測された個別障害——mediator の 503、
> `current contact key is ambiguous`、`checkpoint archive object identity does not match`、
> device list が自端末しか出ない——はいずれも根因まで潰してある（§20-1）。

## 1. この文書の目的

Biset は、メールと DIDComm のデータを利用者の端末側で長期保管し、サーバーを恒久的なメールボックスやメッセージ履歴にしない通信クライアントである。本書は、現行コードの構成、信頼境界、暗号鍵、状態遷移、配送・復旧経路、運用方法、および未完成部分を一つの資料にまとめる。

リポジトリ直下の `PLAN.md` は did.md Wallet login の設計を扱う。
**複数端末同期の再設計（本書 §6・§8・§9 の設計判断と、その実装チェックリスト）の正本は
[`PLAN_vault-sync-redesign.md`](PLAN_vault-sync-redesign.md) である。**
本書はそれらを参考にしつつ、実際に `src/` と `test/` に存在し、呼び出し経路へ接続されているものを
「実装済み」と判定する。クラスやテストだけが存在し、ブラウザの起動経路へ未接続のものは「部品実装済み」とする。

> `REPORT.md` / `NOTE.md` / `WORKSHEET_vault-sync.md` は 2026-09-15 以前の Yjs 設計を前提とした
> 作業記録であり、**現行コードと矛盾する**。読む場合はその前提で読むこと（§20-8）。

**この節の背景（2026-09-03〜04の変化）**: 前回調査（commit `11f0a62`）時点では `biset-core`（`src/core/`）がAnchor・Mediator・Vault・biset-mimiと並ぶ五番目の主要コンポーネントとして存在し、SMTP受信、outbound mail relay、did:webvh/routing.json公開文書ホスティング、device rosterに基づくmail ingress-pull認可とlegacy Vault delivery、legacy DIDComm ingress fallbackを一手に担っていた。commit `99e08c0`（2026-09-03「core: remove src/core/ entirely, retired 2026-09-03」）で`src/core/`はディレクトリごと削除され、以後のcommitでその責務は次のように再配分された。

- SMTP受信・outbound mail relay → `src/server/mediator/mail-plugin/`（standalone mediatorの deployment variant、§3・§11）
- did:webvh/routing.json公開文書ホスティング → core撤去後は Anchor が唯一の host だったが、**その Anchor も 2026-09-05 に削除された**。現在は外部の did.md がホストする（§3・§13.1）
- device rosterに基づくmail ingress-pull認可、legacy Vault delivery、legacy DIDComm ingress fallback → **後継なしに消滅**。roster機構自体（`rosterBackedVaultDeliveryAuthorizer`、`ensureMimiCoreRoster`、`src/mls/self-group.ts`（削除済み）のroster projection関連コード）も削除された。mail認可はdid:webvh update keyの署名検証へ置き換わり（§11.2）、legacy Vault delivery/DIDComm ingressのコードは残骸ごと削除済みである（§12.5）。

## 2. 設計原則と非目標

### 2.1 原則

- **長期正本は各 endpoint の暗号化 Vault である。** 具体的には IndexedDB 上の
  「暗号文 object + 署名済み event + SegmentKeyWrap」の三点セット（R3）であり、
  mediator でも biset-mimi でもない。複数端末同期は、**その同じ record を DIDComm で運ぶ**だけである（§9）。
  Coordinator も MIMI Self Vault も、専用の同期サーバーという概念そのものが存在しない。
- **ログ層と projection 層を分ける。** 署名済み immutable event が唯一の正本であり、
  UI が読む JMAP projection はそこから決定論的に再計算される派生物にすぎない。
  projection は壊れたら捨てて作り直せる（§8.4・§9.3）。
- **マージは join-semilattice でなければならない**——冪等・可換・結合的。
  `compareEvents`（`createdAt → actorDeviceId → actorSeq → id`）が唯一の全順序を与え、
  同一 entity への競合は **per-entity の LWW 再計算**で解決する。
  CRDT ライブラリ（Yjs）は使わない——正本が署名済み event である以上、
  収束のためにもう一つの可変状態を持つ必要がない（§9.2 の経緯）。
- Standalone mediator（および mail-plugin deployment variant）が保持するのは、
  DIDComm の blind queue と SMTP 境界の metadata に限る。
  Vault plaintext、SegmentKey、Vault Content Key は知る必要がない。
- UI と保存層の間には JMAP 形のローカル API を置き、暗号方式を UI へ漏らさない。
- **MLS はクライアント経路では使わない。** Vault の暗号境界は、did.md Wallet が Root key から
  決定論的に導出する **VCK（Vault Content Key）**である。世代番号を持ち、
  **利用者が明示的に操作したときだけ**ローテーションする（§6・§7）。
- 外部 ingress を ACK するのは、端末で検証・暗号化・永続化が完了した後だけとする。
- **復旧に必要な履歴本体を biset のサーバーに置かない。** 履歴の移送経路は二本だけである——
  (a) 起動中の兄弟端末からの Vault Sync、(b) 利用者が持ち運ぶ JMAP export ファイル（§9.4）。
  mediator の queue を「復旧用メールボックス」として使う backfill は**意図的に持たない**
  （blind queue に長期履歴を積む設計は、TTL・容量・プライバシーのいずれから見ても成立しない）。
- did:webvh の SCID を identity の安定した識別子として扱う。
- **identity の発行とホスティングは biset の責務ではない。** 外部の did IdP（did.md）が担い、
  biset は解決するクライアントに徹する。biset は公開文書を書かない。

### 2.2 現行スコープ外または未完成

- **メール**（§11）。native login と一緒にクライアント側の配線が削除されたまま。サーバー側（mail-plugin）は稼働している。
- MLS ベースの複数人グループチャット（旧 Conversation Group / biset-mls-ds）。2026-09-03 にソース一式が削除され、
  DIDComm group chat（§3.1、§12.6）に置き換わった。biset-mimi の `normal`/`anon` モードはサーバーとしては稼働しているが、
  client からの呼び出し経路がない。
- **MLS そのもの**。2026-09-15 の Vault Sync 移行で `src/client/mls/`（`group.ts` / `store.ts` /
  `keypackage-store.ts` / `webvh-authentication-service.ts` / `identity.ts`）と `src/client/mimi/` は
  本番経路から外れた。生きているのは `mls/device-credential.ts` だけで、これは
  did.md Wallet が発行する device credential の符号化・検証に使われる（§6.3・§19）。
- ActivityPub の実動 adapter。protocol enum に値は残るが、adapter、UI、配送経路はない。
- サーバー側の mailbox、全文検索、履歴 API、添付 archive。
- 完全な JMAP server。ローカル gateway は UI が必要とする最小メソッドだけを実装する。
- OpenPGP を用いた実際のメール送信時暗号化と UI での受信復号。
- Web Push。Service Worker は install/activate のみで、通知・バックグラウンド同期を行わない。
- **端末の削除（revoke）**。端末集合は DID Document の verificationMethod 集合であり、
  その編集と VCK ローテーションは did.md Wallet 側の操作である。biset 側に revoke API はない（§6.2）。

## 3. システム全体像

> **2026-09-15 の大きな変更**: 複数端末間の Vault 同期のバックエンドを、biset-mimi の Self Vault
> （MLS application message + checkpoint）から、**既存の DIDComm mediator 上を流れる Vault Sync**
> へ置き換えた。これにより biset が自分で運用するサーバーは **mediator 一種類だけ**になった
> （biset-mimi は稼働しているが、クライアントからの呼び出し経路を持たない）。

```text
┌──────────────────────── Biset Client（ブラウザ） ────────────────────────┐
│ UI ── JMAP projection（派生・再計算可能）                                │
│            ▲                                                             │
│            │ VaultProjector（唯一の writer、per-entity LWW 再計算）      │
│            │                                                             │
│  IndexedDB Vault = ログ層（暗号文 object + 署名 event + SegmentKeyWrap） │
│            │                                                             │
│  did:webvh 解決 / did.md Wallet セッション / VCK / DIDComm             │
└──┬────────────────────┬──────────────────────────┬──────────────────────┘
   │OAuth (DPoP-bound)  │ DIDComm v2 encrypted HTTP │ File System Access API
   │＋ derived secret   │ ・1:1 / group chat        │ ローカルの Markdown
   │＋ did:webvh 解決   │ ・Vault Sync（端末間同期）│ メールフォルダ（§10.4）
   │（読むだけ。biset は│ ・mail bridge inbound     │ ＋ JMAP export/import
   │ 公開文書を書かない）│ 受信も送信もこの一本     │ ファイル（§9.4）
   ▼                    ▼                          ▼
┌─ did.md（外部）──┐┌─ Mediator（"A"素のDIDComm／"B"mail-plugin同梱）┐  ローカルディスク
│identity provider ││"A" = src/server/mediator/index.ts              │
│did:webvh の発行・ ││  did:peer identity、SQLite queue、             │
│ホスティング      ││  Coordinate/Pickup/relay-hop、GET /stream(SSE) │
│OAuth 認可        ││"B" = 上記 + SMTP:25 listener(inbound bridge) + │
│derived secret    ││  submission HTTP:8792(outbound、独立Bun.serve) │
│（VCK・関係秘密）  ││  本番はBが稼働中（両者は同じsqliteを           │
│                  ││  奪い合う排他ターゲット）                      │
└──────────────────┘└────────────────────────────────────────────────┘
                          ▲ SMTP/DNS MXは"B"のSMTP listenerが直接受ける
                          │
                    外部メールシステム

┌─ biset-mimi (normal/anon/self) ─┐
│サーバーとしては稼働中だが、client からの呼び出し経路は 2026-09-15 に全て消えた。│
│self モード（旧 Self Vault）も含め、現行クライアントは biset-mimi に接続しない。│
└─────────────────────────────────┘
```

Biset が**自分で運用する**主要コンポーネントは、実質的に次の二つである。

1. **Mediator** — DIDComm の一時配送（store-and-forward）。`src/server/mediator/index.ts` を入口とする
   "A"（素の mediator）と、それに加えて SMTP inbound listener + outbound submission HTTP を同梱する
   `src/server/mediator/mail-plugin/index.ts` 入口の "B" の、二つの deployment variant がある。
   本番は "B" が稼働中（`mediator.biset.md`）——同じ `biset-didcomm-mediator.service` と SQLite を
   二つのバイナリが奪い合う排他関係であり、deploy.sh の `didcomm-mediator`/`mail-plugin` ターゲットは
   どちらか一方だけをデプロイする（§17.3）。永続化は SQLite（`sqlite-store.ts`）。
   **Vault Sync はこの mediator の通常の queue と SSE をそのまま使う**——専用の経路も専用の権限もない。
2. **Vault** — `src/client/app/main.ts` 内で動く Client local storage。
   暗号化長期正本（ログ層）、JMAP projection（派生）、秘密、server 間 binding を保持する。

**biset-mimi**（`src/server/mimi/index.ts`）は IETF `draft-ietf-mimi-protocol` に準拠した MLS Delivery Service で、
サーバーとしては引き続き動作し、テストも通る。しかし Vault Sync 移行により**クライアントからの呼び出し経路は
すべて消えた**——`self` モードを Vault 同期に使う設計そのものが廃止されたためである。
設計・実装状況の正本は [PLAN_biset-mimi-server.md](PLAN_biset-mimi-server.md)。

**did.md** は biset が運用するものではなく、依存する外部サービスである。identity（did:webvh）の発行とホスティング、
OAuth による認可、そして **Root key からの決定論的な secret 導出**（`urn:did.md:derived-secret:v1`——
VCK と関係秘密の供給元、§6・§7）を担う。biset 側は `src/client/identity/wallet/`
（`did-md-oauth.ts` / `did-md-store.ts`）でそのクライアントとして振る舞い、
**公開文書を書き込むことはない**——読んで解決するだけである（`src/protocol/webvh/` の resolver 系）。

`src/protocol/` は各境界が共有する wire schema、canonical encoding、ID、署名対象 byte 列を定義する。
browser、mediator、mail-plugin、mimi は別々の TypeScript 設定（`tsconfig.*.json`、4 設定）で型検査する。

### 3.1 メッセージング機構の現況

| 機構 | 用途 | 状態（2026-09-16） |
|---|---|---|
| DIDComm 1:1 chat | ペアワイズ・共有鍵なし | **稼働**。関係の開始（INIT）も応答（ACCEPT）も Wallet 経路から配線済み |
| DIDComm group chat | フルメッシュ・ペアワイズ fan-out、MLS 無し | **稼働**（§12.6） |
| **Vault Sync** | 単一 identity の複数端末同期（対人チャットではない） | **稼働**。DIDComm 上の PUSH / REQUEST（§9.2） |
| JMAP export / import | 端末を跨いだ履歴の持ち運びと、複数の不完全なファイルからの収束 | **稼働**（§9.4） |
| Markdown ミラー | ローカルディスク上のメールフォルダ（File System Access API） | **稼働**（§10.4） |
| Mail (SMTP/JMAP) | 従来のメール | **失われたまま**。クライアント側の送受信配線が無い。mediator 側は稼働（§11） |
| ~~MIMI Self Vault~~ | ~~単一 identity の複数端末同期~~ | **廃止**（2026-09-15）。Vault Sync が置き換えた |

- **DIDComm 1:1**（Mediator 経由）は 1:1 のダイレクトメッセージ専用。§12.2〜12.5 で詳述。
  関係の確立は `src/client/identity/wallet/relationship.ts` の `WalletRelationshipManager` が所有し、
  **同一 identity の複数端末が同じ相手へ同時に INIT しても同じ did:peer に収束する**よう、
  端末ごとの乱数ではなく **identity 全体で共有される関係秘密**から導出する（§12.2）。
- **Vault Sync** はユーザー対ユーザーのチャットではなく、一つの identity の複数端末間で
  Vault の record そのもの（event / 暗号文 object / SegmentKeyWrap）を配送する専用の DIDComm メッセージ型である。
  `https://biset.md/vault-sync/1.0/{update,state-request,state-response}` の三種で、
  mediator から見れば他の DIDComm メッセージと区別がつかない。

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

- did.md Wallet の device session（DPoP 鍵、device material）と、そこから得た
  **VCK（Vault Content Key、世代ごと）** および **関係秘密**（§7）
- 端末固有の署名鍵（Vault event の署名に使う Ed25519）と、did.md が認可した device credential
- Vault の暗号文 object、署名済み event、SegmentKey と wrap、JMAP projection
- identity 共有の DIDComm front-door credential
- relationship ごとの非公開 DIDComm credential（1:1・group chat 共通）
- Markdown ミラーのディレクトリハンドル（`biset-markdown-mirror` IndexedDB。
  ハンドル自体は権限つきの参照であり、内容は複製しない。§10.4）
- 復号済み本文と鍵を扱う実行時メモリ

Client は plaintext の最終処理点であり、侵害された client から既取得の秘密を取り戻すことはできない。
VCK のローテーション（§6.2）は**次の世代**の SegmentKeyWrap を新しい鍵で作り直すが、
過去にコピー済みの平文や旧世代の鍵を消去する機能ではない。

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

### 4.4 Mediator が Vault Sync について観測できる範囲

Vault Sync は専用の経路を持たず、通常の DIDComm authcrypt + Forward として mediator の blind queue に載る。
したがって mediator が見るのは他の 1:1 メッセージと同じ——recipient kid、接続、queue 数、時刻、
送受信元 IP、外側 Forward の routing metadata である。**同期の中身は二重に閉じている**:
内側の `VaultDeliveryPackV1` は現行世代の VCK による AES-GCM で暗号化され（AAD は
`biset/vault-sync/v1` と世代番号）、その中の Vault object はさらに SegmentKey で暗号化されている。

一方、**Vault Sync のトラフィックは「同じ identity の端末同士が話している」という事実を隠さない**——
Vault Sync の相手先は DID Document に公開された sibling の front-door kid そのものだからである
（relationship のような pairwise did:peer を使っていない）。これは受容した設計上の帰結である。

### 4.5 利用者が持ち出すファイル

JMAP export（§9.4）は**利用者の手に渡る平文または VCK 暗号化ファイル**である。
UI は既定で暗号化 export（`.biset`、現行世代の VCK で AES-GCM）を勧め、
平文 JSON export は明示的な確認を経たときだけ出力する。
暗号化 export は**その世代の VCK を持つ端末でしか開けない**——世代をローテーションした後に
古い export を読み戻すには、その世代の鍵が Wallet から再導出できる必要がある。

`recovery-archive.ts` / `recovery-archive-export.ts` は canonical な snapshot 形式として
コードとテストに残るが、**現在どの本番経路からも呼ばれていない**（§18 の reachability 実測）。
checkpoint 機構が廃止された時点で、この archive の唯一の利用者が消えた。

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

5. **VCK（Vault Content Key）と関係秘密**を、did.md の derived-secret API
   （`urn:did.md:derived-secret:v1`）から受け取る（§6.2・§7）

> **derived secret の context は、値が無いなら省略する。** did.md は `context: ''` を
> `The derived secret context is invalid` で拒否するため、関係秘密のように context を持たない purpose では
> フィールドごと落とす必要がある（2026-09-15 に実機で発覚した）。

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

端末の集合は **DID Document の `verificationMethod` 集合**である。
did.md Wallet で新しい端末を承認すると、その端末の X25519 公開鍵が
`#{deviceKidFragment(publicKey)}` という自己検証的な fragment を持つ verificationMethod として公開される。
biset 側は `vaultSyncSiblingDevices`（`src/client/didcomm/vault-sync.ts`）で
「fragment が公開鍵から導出した値と一致する」ものだけを端末として認め、自分自身を除いた集合を sibling とする。
**アカウント画面の device list はこの解決結果をそのまま表示する**——
過去の event の actor を並べるのではない（そうしていた頃は、
ローテーション後も過去のログイン端末が消えずに残っていた）。

新しい端末が履歴を引き継ぐ経路は二つで、どちらも**サーバー側の履歴保管を必要としない**。

1. **起動中の兄弟端末からの Vault Sync**（§9.2）。新端末は boot 時に自分の summary を添えて
   `state-request` を全 sibling へ送り、各 sibling が不足分を返す。
2. **JMAP export ファイルの import**（§9.4）。兄弟が一台も起動していない場合の唯一の経路であり、
   複数の時代の export を順不同で import しても同じ最終状態に収束する。

> **仕様として受け入れた制約**: 「兄弟が一台も起きておらず、export ファイルも無い」場合、
> 新端末は**空の Vault として始まる**。mediator に履歴を貯めてそこから backfill する案は
> 意図的に採らなかった（§2.1、§9.4 の設計判断）。

### 5.3 公開文書

| 文書 | 内容 | 更新認可 | ホスト |
|---|---|---|---|
| `did.jsonl` | hash chain、updateKeys、**端末ごとの X25519 verificationMethod**、`#didcomm` service、`#biset-vault` service（VCK 世代） | did:webvh proof / current update key | **did.md**（外部） |
| `did.json` | 任意の did:web mirror | current did:webvh state による検証 | **did.md**（外部） |
| `routing.json` | DIDComm service/keyAgreement、mediator、alsoKnownAs、name | Root/current update key の Data Integrity proof | **did.md**（外部） |

端末集合と VCK 世代は、いずれも **DID Document 本体**（`did.jsonl` の最新 entry）で公開される。

- **端末**: `verificationMethod` の各 entry。fragment が公開鍵の自己検証的な派生値であることを
  biset 側が毎回検証する（§5.2）。
- **VCK 世代**: `#biset-vault` service の `serviceEndpoint` が
  `urn:biset:vault-content-key:v1:{generation}` という URN で現行世代を示す
  （`vaultGenerationUrn` / `parseVaultGenerationUrn`、`vault-content-key.ts`）。
  ローテーションは「DID Document の編集」として可視化され、**ただの編集ではローテーションは起こらない**。

旧 Self Vault の `mimiVaultRoom` ポインタは、routing.json からも DID Document service テンプレートからも
削除された（`config.ts` の `didDocumentServices` は `#didcomm` と `#biset-vault` の二つだけを提案する）。

### 5.4 Domain move

> **この節は現行コードを説明していない。** ドメイン移転（`moveWebvhIdentity`、旧 `src/identity/webvh/move.ts`）は
> native login と一緒に 2026-09-05 に削除された。identity の発行と移転は did.md の責務である（§3）。
> 以下は削除前の挙動の記録として残す。

Identity は SCID を維持したまま新しい domain へ移転できた。`moveWebvhIdentity` は次を行っていた。

- 新 location に moved did:webvh log を作り、最後に old location に move を記録する。
- 移転を実行する端末の MLS device credential を新 DID prefix へ更新する。
- `routing.json` を新 location へ移し、埋め込まれた DID prefix を置換する。
- identity record、Vault object store、local MLS self-group state row（Self Vault room metadata・deliveryCursorを含む）を新 DID key へ re-key する。
- DID を埋め込んだ既存 KeyPackage pool を clear し、次回補充させる。

Self Vault room自体は raw DID ではなく SCID または移転後のDIDそのもので管理し、移転で列を分割しない。

> 上記はすべて削除済み機構の記録である。現行では Self Vault room も MLS self-group state も存在しない（§6）。

移転に関係しなかった sibling device は、boot 時の `adoptPendingMove` で old DID を resolve し、document の現在の `id` が異なれば local record を追従させる。追従は一回の boot につき一 hop である。複数回の移転中に中間 domain が廃止されると、自動追従できない。

### 5.5 署名鍵解決の場所

「この kid の鍵は正当か」という検査は、現行コードでは次の三箇所にある。

| 場所 | 用途 |
|---|---|
| `protocol/didcomm/webvh-resolve.ts` | DIDComm sender の鍵解決（1:1・group chat・**Vault Sync** 共通） |
| `client/didcomm/vault-sync.ts` の `vaultSyncSiblingDevices` | **兄弟端末の認定**。verificationMethod の fragment が公開鍵から導出した値と一致することを要求する（§5.2） |
| `protocol/webvh/resolver.ts` の `resolveCurrentUpdateKeys` | mail-plugin outbound submission の署名検証（§11.2） |

`client/mls/webvh-authentication-service.ts`（MLS Authentication Service）も同じ問いに答えるが、
**本番経路からは外れている**（§6.3）。

Domain move は document 内の DID prefix を一括変更するため、caller の古い完全 kid ではなく `#fragment` を current document の `doc.id` に結合して照合する。DIDComm routing は old domain ではなく、verified log が示す current `doc.id` から取得する。

## 6. 端末集合と Vault Content Key

> **この節は 2026-09-15 に全面的に置き換わった。** かつてここにあった「Self Vault MLS group」は、
> (a) 端末 roster、(b) VEK 導出境界、(c) Vault mutation の搬送チャネルの三役を兼ねていた。
> 現在その三つはそれぞれ **DID Document の verificationMethod**、**Wallet 由来の VCK**、
> **DIDComm 上の Vault Sync** へ分解された。MLS group はクライアント経路から消えている。

### 6.1 端末集合 = DID Document の verificationMethod

この identity の「現在信頼されている端末」は、DID Document に公開された X25519 verificationMethod の集合である
（§5.2）。この集合は did.md Wallet の認可操作でのみ変化し、biset 側から書き換える手段はない。
Vault Sync の宛先解決（`resolveVaultSyncSiblingRoutes`）と device list の表示は、
どちらもこの一つの解決結果を使う——**端末集合の正本は一箇所しかない**。

boot 時、自端末の kid がこの集合に含まれていなければ
`This device is not enrolled in the current Vault generation; reconnect did.md Wallet` で fail closed する。

### 6.2 VCK（Vault Content Key）とそのローテーション

VCK は did.md Wallet が **Root key から決定論的に導出**する 32 byte の鍵である
（`urn:did.md:derived-secret:v1`、purpose `biset:vault-content-key:v1`、context に世代番号）。

- **世代番号（generation）を持つ。** 現行世代は DID Document の `#biset-vault` service が公開する（§5.3）。
- **同じ identity の全端末が同じ VCK を得る。** 端末ごとの乱数ではないため、
  片方の端末が作った SegmentKeyWrap をもう片方が開ける——これが MLS epoch 鍵を不要にした理由である。
- **ローテーションは明示的な操作だけで起こる。** Wallet 側で新世代を承認し、DID Document を更新した後、
  biset は `rewrapVaultSegmentsForGeneration`（`vault-key-rotation.ts`）で
  **全 segment の SegmentKeyWrap を新世代の VCK で作り直す**。
  この rewrap は冪等で、完了マーカーが消えるまで boot のたびに再開される
  （`didMdVaultKeyRotationStatus` → `completeDidMdVaultKeyRotation`）。
  世代は一度に 1 だけ進む（`toGeneration === fromGeneration + 1` を型で強制）。
- **旧世代の VCK は捨てない。** 導出が決定論的である以上、過去世代の鍵はいつでも再導出できる。
  これは MLS の VEK が持っていた前方秘匿性を**意図的に手放した**ということであり、
  その代償として「epoch が進むと古い checkpoint が誰にも開けなくなる」という
  2026-09 前半を通じて実害を出し続けた性質も同時に消えた。

> **`WalletDerivedVaultKeyResolver`**（`vault-content-key.ts`）が、この Wallet 由来の鍵を
> 「epoch 鍵」という既存の抽象へ適合させる。`selfGroupId` にあたる値は定数
> `urn:biset:vault-content-key:v1` に固定される。storage 層と crypto 層は、
> KEK が MLS 由来か Wallet 由来かを知らない。

### 6.3 残った MLS 資産

| ファイル | 現況 |
|---|---|
| `client/mls/device-credential.ts` | **生きている**。did.md Wallet が発行する device credential（`MlsDeviceCredentialV2`）の符号化・検証。`did-md-oauth.ts` と `identity/bootstrap.ts` が使う |
| `client/mls/group.ts` / `store.ts` / `identity.ts` / `keypackage-store.ts` / `webvh-authentication-service.ts` | **本番経路から外れた**。`main.ts` に `memberKids` / `encodeMlsDeviceCredential` の import が残るが、どちらも呼び出されていない死んだ import である（§18・§20） |
| `client/mimi/client-transport.ts` / `client-routing.ts` | 同上。`MimiClientTransport` の import が `main.ts` に残るが未使用 |
| `protocol/mls/`（RFC 9420 vendored fork、98 ファイル） | biset-mimi サーバー側が引き続き使う。**中身は一切変更しない**方針も変わらない（`VENDOR.md`） |

`src/protocol/mls/` の fork は ts-mls v1.6.2 由来で、ciphersuite を
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` に限定し、noble ベース HPKE を使う。
主な差分は (1) 1 member Remove にも UpdatePath を必須化する security fix、
(2) self-remove 後の無限走査回避と application sender leaf attribution、
(3) committer 自身の UpdatePath で credential を置換できる additive hook。
差分には `// biset:` marker があり `VENDOR.md` に記録される。

## 7. 鍵と秘密の一覧

> **2026-09-15 に大きく変わった。** MLS exporter secret 由来の VEK は消え、
> Vault の KEK は did.md Wallet から決定論的に導出する **VCK** になった。
> identity の controller 鍵は引き続き did.md 側にあり、biset は保持しない。

| 鍵・秘密 | 単位 | 保存 | 公開・伝播 | 更新 |
|---|---|---|---|---|
| did.md device session（DPoP 鍵、device material） | device | `biset-did-md-wallet` IndexedDB。**非抽出の browser AES 鍵で封印**（`did-md-store.ts`） | しない | Wallet 側から失効可能 |
| **VCK（Vault Content Key）** | identity + 世代 | 同上（封印済み device material 内に世代ごとに保持） | しない。**全端末が Wallet から同じ値を導出**する | 明示的なローテーション操作のみ（§6.2） |
| **関係秘密（relationship secret）** | identity | 同上 | しない | ローテーション UI なし |
| device 署名鍵（Vault event の署名） | device | 封印済み device material | 公開鍵が DID Document の verificationMethod | 端末の再認可で置き換わる |
| device credential（`MlsDeviceCredentialV2`） | device | 同上 | Wallet 認可の証跡として検証に使う | 端末の再認可 |
| SegmentKey | Vault segment | `vault_segments.segmentKey` に平文保存 | VCK で暗号化した signed wrap を同期 | 鍵は固定、wrap を世代ごとに作り直す |
| Relationship X25519 + Ed25519 | counterparty | encrypted `contact-key.set` Vault object | service-bearing `did:peer:2`、Vault Sync で全端末へ | `supersedesKid` chain |
| Identity front-door DIDComm X25519 | device | 封印済み device material | DID Document の verificationMethod | 端末の再認可 |
| JMAP export の暗号化鍵 | export ファイル | 保存しない | **現行世代の VCK そのもの**（§9.4） | — |

**関係秘密（`biset:relationship-front-door:v1`）**は、VCK と同じ `urn:did.md:derived-secret:v1` の仕組みで
Root key から導出される identity 全体の秘密である（context は付けない——did.md は空文字列の context を拒否するため、
**フィールドごと省略する**）。`deriveRelationshipPeerIdentity`（`protocol/didcomm/peer.ts`）が
この秘密と相手 DID から did:peer を決定論的に導出するので、
**同じ identity の二台が同じ相手へ同時に初回接触しても、同一の関係鍵に収束する**——
乱数で生成していた頃は、どちらも supersede しない二つの `ContactKeyV1` が残り、
以後ずっと `current contact key is ambiguous` で送信不能になっていた（2026-09-15 に実機で発生）。

### 7.1 保存時（at rest）の保護状況

**did.md Wallet の device material は封印されている。** 非抽出（`extractable: false`）の
AES-GCM 鍵を IndexedDB に置き、その鍵で private key・VCK・関係秘密を包む。
鍵自体は JS から取り出せないため、IndexedDB のダンプだけでは平文に戻せない。

**一方、Vault 側の `VaultSegmentRecord.segmentKey` は local IndexedDB に平文で保持される。**
Vault object と同期 payload は暗号化されるが、端末 local storage 全体が別鍵で封印されているわけではない。
したがってこの構成は server compromise と配送経路上の漏洩を主に抑えるものであり、
**browser profile / local IndexedDB を読み取れる攻撃者に対する at-rest protection は Vault 側で未完成**である。

**Markdown ミラー（§10.4）を有効にすると、その端末のローカルディスク上に平文の `.md` が置かれる。**
これは「ローカルのメールフォルダ」という機能そのものであり、利用者が明示的にディレクトリを選んだときだけ起動する。

### 7.2 消えた鍵

| かつて | 現状 |
|---|---|
| Master seed / 24 語 Root Key phrase | **無い**。identity は did.md が発行する |
| Root / Sign / Spare Ed25519 key と pre-rotation | **無い**。鍵ローテーションは did.md の責務 |
| **VEK（Vault Epoch Key、MLS exporter 由来）** | **無い**。VCK が置き換えた（§6.2）。MLS self-group ごと廃止 |
| **checkpoint の data key** | **無い**。checkpoint 機構自体が廃止された（§9.4） |
| OpenPGP private credential | reader/sink は R2 で削除。record 型だけが過去 event の復号のため `mutation-records.ts` に残る |
| Recovery Key（利用者管理 archive 用） | `recovery-archive.ts` はコードとテストに残るが、本番経路から到達しない（§4.5・§18） |

## 8. Vault

### 8.1 データモデル

Vault の長期正本は immutable な二種類の record からなる。

- **VaultObjectV1** — 32-byte SegmentKey と AES-256-GCM で暗号化した content-addressed object。nonce、AAD、ciphertext hash、plaintext length を ID に含める。
- **VaultEventV1** — actor device、actor sequence、kind、target、object reference、parents、timestamp を MLS leaf Ed25519 key で署名した event。event ID は canonical body と署名から導出する。

代表的 event kind は `message.add/edit/tombstone`、`mailbox.set`、`keyword.set`、`transport.result`、`didcomm.control`、`contact-key.set`、OpenPGP/DIDComm credential である（`src/protocol/vault.ts`の`VAULT_EVENT_KINDS`が唯一の正本リストであり、`vault/delivery-pack.ts`のdecode allow-listもこの同じ定数を直接参照する）。Raw RFC 5322 と JMAP metadata は別々の encrypted object として一つの `message.add` から参照される。

### 8.2 Segment と世代

同一 segment の object は同じ random SegmentKey を使う。SegmentKey は**現行世代の VCK** で AES-GCM wrap され、
grantor device の署名を付ける（`SegmentKeyWrapV1`）。VCK 世代が進むと、
`rewrapVaultSegmentsForGeneration` が全 segment について新世代の wrap を作る（§6.2）。
SegmentKey 自体は変わらない——変わるのはそれを包む鍵だけである。

復号時は現行世代の wrap を使う。**旧世代の wrap へ暗黙に fallback はしない**が、
VCK が決定論的に再導出できるため、
「その世代の鍵が Wallet から得られるなら開ける」という点が MLS VEK 時代との決定的な違いである。

### 8.3 IndexedDB transaction

`biset-vault-core` database は **schema version 14** である（`store.ts` の `DATABASE_VERSION`）。
object、event、chunk、segment、key wrap、manifest、projection、JMAP state、
各種 durable outbox/receipt/cursor、transport status を持つ。v14 で追加・削除された要素は次のとおり。

| 要素 | 内容 |
|---|---|
| `vault_actor_sequences`（新規） | `[identityId, deviceId]` を key とする **actorSeq の採番カウンタ**。`reserveActorSeq` が「カウンタ」と「既存 event の最大 actorSeq」の両方の上限を取って一つのトランザクションで払い出すため、import / restore で後から過去の record が入っても採番が重複しない |
| `vault_projection_meta`（新規） | projection の**永続 tombstone 集合と pending 集合**（§9.3）。projection 本体と違い、これは「消えた」「まだ materialize できない」という判断を再起動を跨いで保つ |
| `vault_events` の index（新規 2 本） | `by_target_id`（`targetIds` の multiEntry——ある email に触った event だけを引く）と `by_actor_sequence`（`[identityId, actorDeviceId, actorSeq]`——採番と summary 計算に使う） |
| ~~`vault_crdt_state`~~（削除） | Yjs の CRDT state。v14 の upgrade で `deleteObjectStore` される。**削除の直前に `rescueLegacyCrdtEvents` が走り**、delta 経路でしか届いていなかった event を R3 の event store へ救出する（`legacy-crdt-migration.ts`。現行 tree で `yjs` を import する唯一のファイル） |

Local mutation、ingress commit、Vault Sync の受信適用は、record・projection・JMAP state・
次の network ACK/outbox を同一 transaction に書く。Network 送信に失敗しても、次回 retry すべき intent が local に残る。
重複 event は event ID と `(actorDeviceId, actorSeq)` により冪等に扱う。

### 8.4 Projection（派生であって正本ではない）

Local JMAP projection は cache/read model である。**唯一の writer は `VaultProjector`**
（`src/client/store/vault/projector.ts`、§9.3）であり、
ログ層に record が入った後に呼ばれて必要な範囲だけを再計算する。
壊れた projection、あるいは 200 件を超える一括変更は `rebuildAll` で全 event/object から作り直す。

必要な現行世代の wrap や object がまだ届いていない email は、**失敗ではなく `pending`** として記録され、
後続のチャンクで材料が揃った時点で自動的に materialize される。
Local garbage collection は実装されていない。

## 9. 配送モデル

### 9.1 メール受信（mail-plugin bridge）

**旧biset-coreのbounded ingress store/pull/ack機構は完全に消滅した。** 現行の受信経路は次のとおりで、pull ではなく push であり、TTL/quotaを持つ独立バッファも存在しない。

1. `src/server/mediator/mail-plugin/listener.ts`（"B" deployment）が port 25 で生SMTPを受ける。EHLO/HELO、MAIL、RCPT、DATA、RSET、NOOP、QUIT、STARTTLSを扱い、既定25 MiB制限を広告・強制する。SMTPUTF8とAUTHは提供しない。TLS certificate/keyが設定されればSTARTTLSを提供するが、未設定でもserverは起動しplaintext SMTPとなる（旧biset-coreのSMTP listenerと同じ挙動——`smtp-socket-server.ts`/`mail-smtp-protocol.ts`は`src/core/adapters/`から2026-09-03にこのディレクトリへ物理的に移設されただけで、ロジックは変わっていない）。
2. RCPT TO時点で`bridge.ts`の`resolveMailRecipientRoute`が宛先アドレスの**routing.jsonをdomainだけから直接resolveする**（`identityDomainForMailAddress`が`mailFromForIdentity`の決定論的逆関数——SCID lookupもsigned-log resolveも経由しない）。宛先がDIDComm keyAgreement/serviceを公開していなければ550で拒否する。
3. DATA受理時、同じ`bridge.ts`の`packInboundMailForward`が受信メッセージを`MAIL_BRIDGE_INBOUND`型のDIDCommプレーンテキストへ包み、mail-pluginが自分で保持する専用の`did:peer`送信元identity（`SqliteMediatorStore.loadMailPluginIdentity`、real end-user identityとは別）からauthcryptし、宛先のmediator（Forward hop chainを含む）へ`OutboundDelivery`としてPOSTする——**core時代のingress store/pull/ackという独立した概念がなく、通常のDIDComm 1:1/group chatメッセージと全く同じmediator queueに載る**（§12.5）。
4. Client側は他のDIDCommメッセージと同じ`DidCommIngressProjector`/mediator SSE watch経由でこれを受け取る（§12.5）。deviceごとのlease/quota/ACKという概念はもう存在しない。

roster（device集合の認可情報）はこの経路のどこにも登場しない——宛先解決がrouting.jsonの公開情報だけで完結するため、"このidentityの端末集合をmail認可のために知っておく"という前段そのものが不要になった。roster を担っていた `rosterBackedVaultDeliveryAuthorizer` / `ensureMimiCoreRoster` は、MLS self-group ごと削除済みである（§6）。

### 9.2 Vault Sync（層 1: ログの同期）

> **2026-09-15 の全面置き換え。** かつてここにあった MIMI Self Vault delivery
> （MLS application message + bounded pull + checkpoint）は、
> **DIDComm 上の record 同期**に置き換わった。以下がその設計である。

同期されるのは、ログ層の三点セット——**署名済み event / 暗号文 object / SegmentKeyWrap**——を
一つにまとめた `VaultDeliveryPackV1` である。
`src/client/didcomm/vault-sync.ts` の `VaultSyncClient` が全体を所有し、
メッセージ型は次の三つだけである（`protocol/didcomm/vault-sync-protocol.ts`）。

| 型 | 向き | 意味 |
|---|---|---|
| `.../vault-sync/1.0/update` | PUSH | 「今これを確定した」。**ヒントであって保証ではない** |
| `.../vault-sync/1.0/state-request` | PULL 要求 | 「私の手元はこうだ」（summary を添える） |
| `.../vault-sync/1.0/state-response` | PULL 応答 | 不足分の record。`hasMore` で続きの有無を示す |

**(1) 何を持っているかの表現 = version vector。**
`VaultSyncSummary` は `Record<actorDeviceId, { max: number; gaps: number[] }>` である。
「この端末の actorSeq は max まで見えていて、そのうち gaps が欠けている」という形で、
**Yjs の state vector が担っていた役割を、署名済み event 自身の属性だけで表す**。
ある actor に採番の重複が検出された場合（`findDuplicateActorSequences`）、
その actor の `max` は 0 に落とされ、全件が「不足」として扱われる——壊れた採番を黙って信用しない。

**(2) PUSH は content-carrying である。**
旧設計の致命的な欠陥は、**非同期に流せる push 経路が Yjs delta（メタデータ）しか運ばず、
暗号文 object と SegmentKeyWrap は「両端末が同時に起動している全量 pull」でしか渡らなかった**ことである。
現行の `update` は、対象 event が参照する object と、その segment の key wrap を必ず同梱する。

**(3) PUSH の後は必ず summary を突き合わせる。**
`receive()` は `update` を適用した後、送信元へ自動的に `state-request` を返す。
PUSH をヒントとしてしか扱わないので、その通知より前に確定していた record や、
チャンクに載りきらなかった record が取り残されない。

**(4) 応答は必ず有界である。**
`missingEvents` は「相手に無い event」を**新しい順**に並べ、
`VAULT_SYNC_CHUNK_BYTES`（**128 KB**）に収まるところで打ち切り、`hasMore: true` を立てる。
受信側は `hasMore` を見てもう一度 `state-request` を出す。
**この 128 KB という値は mediator の `MEDIATOR_MAX_MESSAGE_BYTES`（既定 1 MB）から逆算したものである**——
DIDComm の封入は base64 を重ねるため wire サイズは約 **3.2 倍**に膨らみ、
旧設定の 500 KB は mediator 側で `QueueFullError` → **HTTP 503** を引き起こしていた
（2026-09-15 に実機で発生。アプリ側は普通の 503 を返し、そのサイトには access log が無かったため、
mediator のログには何も出ていなかった）。この比率は回帰テストで固定している（§18）。

**(5) 適用は record 単位で skip する。**
`applyIncoming` は object の完全性検証、event の署名検証、key wrap の形式検証を個別に行い、
落ちたものを `skippedObjects` / `skippedEvents` / `skippedKeyWraps` として数えるだけで、
**一件の不正が batch 全体を落とすことはない**。
また「先のチャンクで来た event が、後のチャンクの object でようやく materialize できる」ケースのために、
object だけのチャンクでも、それによって解けた event の `targetIds` を projector へ通知する。

**(6) 送信は指数バックオフで再試行する。**
`mediatedVaultSyncTransport` は 6 回まで、250ms から倍々で待って再送する。
宛先の経路は**毎回 DID Document から解決し直す**ので、送信中に端末集合が変わっても古い宛先に送り続けない。

**(7) 全体が現行世代の VCK で暗号化される。**
pack は `encryptUpdate` で AES-GCM 暗号化され、AAD に `biset/vault-sync/v1` と世代番号が入る。
世代が合わない update は `Vault Sync update generation is unavailable; reconnect your did.md Wallet` で拒否される。

### 9.3 VaultProjector（層 2: projection の再計算）

ログ層に record が入った後、`VaultProjector`（`src/client/store/vault/projector.ts`）が
**唯一の writer として** JMAP projection を更新する。

- **per-entity の LWW 再計算。** `recomputeEmails(identityId, emailIds)` は、
  対象の email に触れた event だけを `by_target_id` index で引き、その email だけを畳み直す。
  event 全体を毎回 replay しない。
- **順序は `compareEvents` に従う**（`createdAt → actorDeviceId → actorSeq → id`）。
  これが全順序なので、どの端末がどの順に record を受け取っても同じ結果に収束する。
- **tombstone は永続化する。** `message.tombstone` を見たら `vault_projection_meta` の
  tombstone 集合へ入れ、以後その email は projection に現れない——
  後から届いた古い `message.add` が削除済みメッセージを蘇らせない。
- **材料待ちは pending 集合に入る。** 復号できない、または reducer が弾いた email は
  `pending` として覚えておき、**次の再計算のたびに要求分と一緒に必ず再試行される**。
- **一括変更は全再構築へ落ちる。** 対象が 200 件を超える、または projection がまだ無い場合は `rebuildAll`。

`main.ts` の boot はこの `rebuildAll` を try/catch で包む——
projection の再構築に失敗しても、ログ層と同期は動き続けるべきだからである。

### 9.4 履歴の移送（restore / export / import）

**checkpoint は廃止された。** MLS epoch の VEK で包む都合上、
「新端末が参加すると epoch が進み、その瞬間に既存 checkpoint が誰にも開けなくなる」
という構造的な欠陥を抱えており、2026-09 前半の障害の多くがここに起因していた。
現在、履歴の移送経路は次の二本だけである。

#### (a) 起動中の兄弟端末からの Vault Sync

新しい端末（または長く止まっていた端末）は boot 時に、
公開されている全 sibling へ自分の summary を添えて `state-request` を送る（§9.2）。
これが「復元」に相当する唯一のオンライン経路である。
**兄弟が一台も起動していなければ、その端末は空で始まる**——これは仕様として受け入れた制約である。

#### (b) 汎用 JMAP 形式の export / import

`src/client/store/vault/jmap-export.ts`。設計の要点は三つある。

1. **形式は純粋に汎用的な JMAP である。** `mailboxes` / `emails` / `blobs`（blobId → base64url の生 RFC 5322）で、
   biset 固有の概念を JMAP の外へ持ち出さない。
2. **収束に必要な順位情報を、JMAP の拡張プロパティ 1 つだけで運ぶ。**
   `https://biset.md/jmap/ns:stateRank`（定数 `JMAP_STATE_RANK`）に、
   `keywords` / `mailboxIds` / `content` の**三つの独立した順位キー**を入れる。
   三つに分けているのは、既読フラグの変更と mailbox の移動と本文の編集が
   それぞれ別の時点で起きるからで、**一つの値で三つを代表させると必ず片方が巻き戻る**。
   順位キーの形は `createdAt|actorDeviceId|actorSeq(20 桁ゼロ埋め)|eventId` で、
   文字列比較が `compareEvents` と同じ順序になるように作ってある。
3. **import は差分的に収束する。** 既存の email については、
   上記三つの順位をそれぞれ現在の projection の順位と比較し、
   **より新しい側だけを合成イベントとして書き込む**。
   合成イベントは**元の順位キーが持つ `createdAt` を継承する**ので、
   「古いファイルを後から import した」だけで新しい状態が上書きされることはない。
   本文の無い email（`blobs` に対応する blob が無い）は `missingBodies` として除外する。

この性質により、**複数の時代の、それぞれ不完全な export ファイルを、順不同で何度 import しても、
最終的に同じ一つの完全な集合に収束する**——パズルのピースを埋めていくように使える。
import 結果は `{ added, skipped, excluded, missingBodies }` として UI に表示され、
生成された合成イベントはそのまま Vault Sync で兄弟端末へ push される。

export は既定で **現行世代の VCK による AES-GCM 暗号化**（`.biset`、`JmapExportEnvelopeV1`）であり、
平文 JSON は明示的な確認を経たときだけ出力する（§4.5）。

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

`bootClient`（`src/client/app/main.ts`）は、まず前回セッションの mediator watch / poll を**無条件に**停止し、
次に OAuth callback を消費してから、保存済みの did.md Wallet セッションで
`configureWalletAccountIfPresent` へ入る。**Wallet セッションが唯一のアカウント経路である。**

1. Wallet の device session と **VCK 一式**を開く（`openDidMdWalletBisetDevice` / `openDidMdWalletVaultContentKeys`）。
   VCK の identity が device の DID と一致しなければ即座に fail closed する。
2. Vault IndexedDB を開く。**この中で v14 の upgrade が走り、その直前に
   `rescueLegacyCrdtEvents` が旧 Yjs store から event を救出する**（§8.3）。
3. 現行の端末集合を DID Document から解決する（`refreshVaultDevices`）。
4. **VCK ローテーションが `rewrap` フェーズで中断していれば、ここで完了させる**（§6.2）。
   公開されている世代と Wallet が返した世代が食い違えば fail closed する。
5. actorSeq の採番器（`buildActorSequencer`）、暗号境界、read model、`VaultProjector` を組む。
6. export / import ハンドラ（§9.4）と **Markdown ミラー**（§10.4）を配線する。
   保存済みのディレクトリハンドルがあり、権限が残っていれば、ここでミラーが自動的に再開する。
7. **既存のローカル projection でまず inbox を描画する**——ネットワークを待たない。
   リロードが「Wallet アカウントの履歴を捨てた」ように見えないための明示的な措置である。
8. mediator へ登録し、`VaultSyncClient` を作る。自端末が現行の端末集合に含まれていなければ拒否する。
   ここで Vault カードを `connected` にする。
9. **全 sibling へ `state-request` を送る**（`void`、UI を待たせない）。これが「起動時の復元」である（§9.4a）。
10. `watchMediatorMultiplexed` で mediator の SSE を開く。**front-door と全 ContactKey の queue を
    1 本の EventSource に多重化する**——HTTP/1.1 の同一 origin 接続枠を ContactKey の数だけ食い潰さないため（§12.4）。
11. 保存済みの relationship watch を再開する（`restoreRelationshipWatches`）。
    **一つの counterparty の恒久的な失敗（ambiguous contact key など）で boot 全体を落とさない**——
    エラーコールバックを必ず渡し、その相手だけを諦める。
12. DIDComm outbox を flush し、10 秒間隔の再試行タイマーを張る。

受信した DIDComm メッセージは種別ごとに分岐する——Vault Sync なら `VaultSyncClient.receive`、
relationship の INIT/ACCEPT なら `WalletRelationshipManager`、
それ以外は ingress projector 経由で Vault へ。
**どの経路でも、新しく確定した event はそのまま sibling へ push される**（§9.2）。
Vault Sync の受信適用後は `VaultProjector.recomputeEmails`、
ingress の受信後も同様に再計算してから inbox を再描画する。

### 10.4 Markdown ミラー（ローカルのメールフォルダ）

File System Access API で利用者が選んだディレクトリに、スレッドを Markdown として書き出す機能である
（`markdown-mirror.ts` / `markdown-directory.ts`。設定画面のトグルから有効化する）。
**2026-09 のリライトで一度失われ、2026-09-15 に再実装した。**

- **ディレクトリは正本ではない。** 書き出しは常に projection から**作り直す**方向であり、
  ファイル側から取り込むのは**利用者が書ける二箇所だけ**——frontmatter の `status` と、
  メッセージブロック（`- - -` 区切り）より前の下書き本文である。
  メッセージ本体は読み取り専用として扱う。
- **レイアウト**: `{mailbox 名}/{相手}_{MMDDhhmm}.md`。未読スレッドは先頭に `_` が付く。
  frontmatter は `subject` / `contact` / `id`（threadId） / `status`。
  `Drafts/_new.md` が常に置かれ、新規作成の雛形になる。
- **`status` が JMAP の変更に翻訳される**（`markdownStatusMutation`）——
  `seen` / `follow` は keyword、`archived` / `spam` は mailbox の移動、`deleted` は destroy。
- **下書きの送信**: 本文に `!b` だけの行を入れて保存すると、そのスレッドへの返信として送信し、
  ミラーからそのファイルを削除する。
- **自己書き込みループの防止**: `MarkdownSelfWriteGuard` が書いた内容の SHA-256 を覚えておき、
  observer から返ってきた**その一回だけ**を無視する。
  ハッシュが一致しない変更——つまり利用者が直後に手で編集したもの——は正しく拾う。
- **監視**: `FileSystemObserver` があれば 500ms のデバウンス付きで再帰監視する。
  無いブラウザでは `observerSupported` が false になり、設定画面の手動再スキャンだけが使える。
- **ハンドルの永続化**: `biset-markdown-mirror` IndexedDB に identity ごとに保存し、
  boot 時に `queryPermission` で権限を確認する（無ければ黙って無効のままにする）。

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

**front-door key は端末ごとに固有であり、did.md Wallet の認可時に DID Document へ公開される。**
公開される verificationMethod の fragment は公開鍵から導出した自己検証的な値であり（§5.2）、
biset 側はこの導出一致を毎回検証してから端末として扱う。
DIDCommMessaging service（`#didcomm`）は Wallet が認可した mediator の URI と routing key を指す。
biset はこれらの公開文書を**書かない**——書くのは did.md である。

boot 時、この端末は自分の X25519 秘密鍵の所持を mediator に証明して登録する
（`registerWithMediator`）。Wallet が認可した mediator がこのデプロイの `mediatorUrls` に
含まれていなければ fail closed する（§17.1）。
mediator の routing key が Wallet 認可時から変わっていた場合も拒否する。

Identity front-door key の用途は二つである——新規関係の発見と `RELATIONSHIP_INIT`、
そして**兄弟端末との Vault Sync**（§9.2）。後者は pairwise did:peer を使わないため、
mediator から見て「同じ identity の端末同士の通信」であることが分かる（§4.4）。

### 12.2 Private relationship

初回送信者は relationship 専用の X25519/Ed25519 pair と service-bearing `did:peer:2` を用意し、
その peer kid を mediator に **INIT より先に**登録する。受信者も専用 peer identity を用意・登録し、
双方の公開情報と自分の秘密鍵を encrypted `contact-key.set` として Vault に保存し、
登録済みの initiator peer へ `RELATIONSHIP_ACCEPT` を返す。

**この peer は乱数ではなく、identity 全体で共有される関係秘密から決定論的に導出する**
（`deriveRelationshipPeerIdentity(relationshipSecret, counterpartyDid, service)`、§7）。
乱数だった頃は、同じ identity の二台が同じ相手へほぼ同時に初回接触すると、
**互いを supersede しない二つの `ContactKeyV1`** が残り、
`credential-store.ts` の `selectUnsuperseded` が fail closed して
`current contact key is ambiguous; explicit rotation is required` が永続化していた（2026-09-15、実機）。
同じ理由で、リロード後に同じ相手の INIT を受け直しても、mediator に古い did:peer を登録し残さない。

確立後の Basic Message 2.0（1:1）と DIDComm group chat の INVITE/MESSAGE（§12.6）は、
どちらも同じ relationship kid 間の authcrypt だけを使う。継続 JWE と mediator connection owner に
公開 did:webvh front-door kid を含めない。Current relationship credential は boot 時に Vault から読み、
peer kid ごとに mediator の SSE watch を再開する（多重化されて 1 本の EventSource に載る、§12.4）。

**同じ counterparty への同時 `ensureContact` は直列化される**（`WalletRelationshipManager` の `ensuring` map）。
outbox が同じ宛先の 2 件を並列に flush しても、initiate が二重に走らない。
また、caller 側の 60 秒タイムアウトは**待つのをやめるだけ**で、
登録済みの private receiver と pending state は保持される——
SSE の一時切断の後に届いた ACCEPT を復号できなくして、mediator の queue に永久に詰まらせないため。

**crash 耐性は依然として無い。** pending state は `pendingByOwnKid` / `pendingByCounterparty` という
2 つのメモリ上の Map にしかなく、INIT 後 ACCEPT 前に reload すると private pending key を失う。
ただし関係秘密からの決定論的導出により、**同じ相手へやり直せば同じ peer が再構成される**ため、
以前のように「二度と復旧できない」状態にはならない（§15.2）。

### 12.3 暗号形式

- Authcrypt: `ECDH-1PU+A256KW` + `A256CBC-HS512`
- Anoncrypt Forward: `ECDH-ES+A256KW` + `A256CBC-HS512` を生成し、受信は `XC20P` も許容
- 任意の hybrid authcrypt: X25519 + ML-KEM-768 を独自 alg identifier で KDF に混ぜる

Hybrid は recipient routing に ML-KEM key がある public-DID path の primitive として存在する。Relationship credential schema は X25519/Ed25519 だけで、継続 private relationship は ML-KEM hybrid を使わない。

### 12.4 Mediator

Standalone mediator は自身の did:peer identity、connection keylist、queueを**SQLite**（`src/server/mediator/sqlite-store.ts`）に保存する。Coordinate/Pickup request は DIDComm authcrypt の sender X25519 keyで認証する。did:webvh sender は公開 routing を resolve し、did:peer sender は self-certifying DID から鍵を得る。

Queue は recipient kid あたり最大 256 件、保持 30 日で、満杯時は古い正当 message を捨てず sender を拒否する。Pickup は non-destructive delivery の後、`messages-received` ACK で削除する。Connection は最大 10,000、connection ごとに最大 32 kid。Replay guard は既定 10 分 / 50,000 ID、resolved key cache TTL は 10 分で stale-while-refresh 動作をする。共有HTTP surfaceは単一の `POST /` （DIDCommメッセージ種別で内部分岐）、`GET /.well-known/did.json`、`GET /stream`（SSE）の3経路であり、これは"A"（素のmediator）と"B"（mail-plugin同梱）で完全に共通（`deployment.ts`）である。`GET /stream` は複数の `token` queryを受け取り、client側の`watchMediatorMultiplexed`が同じmediator上のfront-door/ContactKey queueを1本のEventSourceへ多重化する。これはHTTP/1.1の同一origin接続枠をContactKey数だけ占有しないためで、単一tokenも互換として維持する。"B"はこれに加えてSMTP:25とsubmission HTTP:8792を独立に持つ（§3・§11）。

`relay-poller.ts`は、あるmediatorが別のupstream mediatorへ自分自身をclientとして登録し（`MEDIATOR_RELAY_UPSTREAM_URL`）、自分宛のForwardをunwrapして自分のqueueへ再Forwardする、任意のmulti-hop中継機能である。routing.jsonの`routingKeys`（outermost-first）でこの中継段を名指しできる。dispatch()自体はこの機能の有無で変わらない——upstream側からは通常のend-user deviceに見え、downstream側からは通常のForward requestに見える。

DBファイルへの書き込み失敗時の挙動は、本調査でも未検証のまま次回調査で確認すべき既知の空白として残る。

### 12.5 メッセージ振り分け（1:1・group chat・mail bridge）

**旧「Legacy core DIDComm path」節は本調査で全面的に置き換えた——core自体が存在しないため、`/v1/didcomm/ingress`というサーバー route はどこにも実装されていない。** mediatorのSSE watchループが受け取るのは、型タグで振り分けられる単一のqueueに載った次の3種のペイロードだけである。

1. DIDComm 1:1（Basic Message 2.0、§12.2・§12.3）
2. DIDComm group chat control/content（GROUP_INVITE等、§12.6）
3. **Vault Sync**（`update` / `state-request` / `state-response`、§9.2）
4. `MAIL_BRIDGE_INBOUND`（§9.1・§11.1のmail-plugin bridgeが変換したメール）

`DidCommIngressProjector`（`src/client/didcomm/ingress-projector.ts`）が復号と鍵選択を行い、`ingestTransportIngress` が Vault へ確定させる。**core 時代の legacy ingress 経路（`CoreIngressTransport`、`coreBaseUrl`）はコードごと削除済みで、`src/` 全体に残骸は無い。** 動く経路は mediator SSE watch の 1 本だけである。

Vault Sync の 3 型（§9.2）は、この同じ queue と同じ watch で届くが、`ingress-projector` ではなく `VaultSyncClient.receive` へ振り分けられる。

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

クライアント側で対応するのは `src/protocol/webvh/` の resolver 系（`resolver.ts` `log.ts` `log-io.ts` `proof.ts` ほか）で、
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

> **現行クライアントはこの HTTP surface を一切呼ばない**（2026-09-15、§3）。
> サーバーとしては稼働し続けており、以下の記述はそのまま有効である。

IETF draft-ietf-mimi-protocol §5.2/§5.3のprovider-facing routesを実装する（`src/server/mimi/http.ts`）。主なpathは、well-known protocol directory、`GET /stream`（deliveries、SSE watch tokenで認可）、franking agentデータ、asset proxy download、`POST /notify/*`（federation fanout受信）、`POST /groupInfo/{roomId}`（external join、`allowExternalJoin`が有効なdeploymentのみ既定拒否を解除——`self`モードだけがこれを有効化する）、abuse report、consent request/update、identifier query、`POST /keyMaterial/{targetUser}`、`POST /keyPackage`、`POST /update/{roomId}`（room作成・external join commit・通常commit・checkpoint application messageのいずれも、この単一endpointを通る）である。すべてのbodyはbiset独自のprovider-internal credential signature（`authorizer.ts`）で認証する——membershipとMLS leaf署名だけが認可根拠であり、外部の認証トークンは要求しない。この節は core 撤去にも Anchor 削除にも影響を受けていない。

### 13.4 Fail-closed composition

Mediator（"A"/"B"共通）は`MEDIATOR_PUBLIC_URL`と`MEDIATOR_DATABASE_PATH`/`MEDIATOR_DATA_DIR`のいずれかが必須。"B"（mail-plugin）はさらに`MAIL_PLUGIN_APEX_DOMAIN`が必須。biset-mimiは`MIMI_DATABASE_PATH`必須で、未設定時は起動時に例外で落ちる（healthのみ公開という緩やかなfallbackはない）。

一つの SQLite database（mediator側）に did:peer identity、connection、queueを置く。**Vault Sync もこの同じ queue を使うだけで、専用のテーブルも専用の権限も持たない**（§9.2）。biset-mimi は自身の別プロセス・別SQLiteファイルを持つ（`MimiDeploymentOptions.mode`ごとに専用DBファイルが必須）が、現行クライアントはそこへ接続しない（§3）。**did:webvh/routing files は biset のどのサーバーにも置かれない**——did.md がホストする（§13.1）。Plaintext mailbox projection、private identity key、SegmentKey、**VCK** はどのサーバー側storageにも置かない。

### 13.5 Hosting limits

- did.jsonl / did.json / routing.json のサイズ上限は、ホストである **did.md 側の関心事**である。
  かつて Anchor が課していた上限（did.jsonl: request 1 MiB、identity ごと 10,000 entry / 16 MiB、他は 1 MiB）は、
  Anchor ごと削除された
- mail submit body: 25 MiB（mail-plugin `/v1/mail/submit`）
- inbound SMTP message: 既定25 MiB（mail-plugin SMTP listener、`MAIL_PLUGIN_MAX_MESSAGE_BYTES`）

biset-coreが持っていた「多くの場合request時に実行する」expiry sweep（roster/ingress/vault-deliveryのTTL管理）は、それらの機構自体が消滅したことで不要になった。常時timer/jobによるvacuumがない点、tombstoneとSQLite fileの物理縮小が運用者責任である点は変わらない。

## 14. 可用性、失敗、冪等性

- Client の local transaction を network ACK より先に行うため、response loss は再送で回復できる。
- **Vault Sync の PUSH はヒントにすぎず、到達保証を持たない。** 取りこぼしは受信側が
  PUSH 適用後に自動的に返す `state-request`（summary 突き合わせ）で回収される（§9.2-3）。
- **Vault Sync の送信は 6 回・指数バックオフで再試行する**。宛先の経路は毎回 DID Document から
  解決し直すので、送信中に端末集合が変わっても古い宛先へ送り続けない。
- **一件の不正 record が batch 全体を落とさない**——object / event / key wrap は個別に検証され、
  落ちたものは skip カウンタに計上されるだけである（§9.2-5）。
- **materialize できない email は失敗ではなく `pending`** であり、材料が届いた次の再計算で自動的に解ける（§9.3）。
- **チャンクサイズは mediator の上限から逆算されている。** 128 KB × wire 膨張 3.2 倍 < 1 MB。
  この関係は回帰テストで固定してある——破ると mediator が `QueueFullError` を返し、
  クライアントには **HTTP 503** としてしか見えない（2026-09-15 の実障害）。
- **VCK のローテーションは中断に耐える。** `rewrap` フェーズは冪等で、
  完了マーカーが消えるまで boot のたびに再開される（§6.2）。
- **projection の再構築失敗は boot を止めない**（try/catch）。ログ層と同期は動き続け、
  projection は次の機会に作り直せる。
- **一つの counterparty の恒久的な失敗が boot 全体を落とさない**（`restoreRelationshipWatches`、§10.3-11）。
- mail-plugin bridge の inbound mail は、DIDComm Forward として mediator queue に積まれた時点で
  標準の queue TTL（30 日、§12.4）の対象になる。
- Outbound mail temporary failure は durable outbox に残るが scheduler がないため、
  利用者操作なしには retry されない。
- `routing.json` 更新は fetch-merge-put だが version/ETag compare-and-swap がなく、
  複数端末の同時更新で last-write-wins となり得る。
- **`main.ts` の boot wiring は browser E2E で覆われていない。** 2026-09-04 の
  `coreBaseUrl` gate regression（DIDComm/mail/group chat が本番で静かに全停止していたのに
  typecheck/build/test はすべて通っていた）は、この隙間から出た実例である。§18・§20 を参照。

## 15. Security properties と限界

### 15.1 実装されている主な性質

- Vault object は authenticated encryption、content-derived ID、ciphertext hash で改ざんを検出する。
- Vault event と SegmentKeyWrap は、did.md Wallet が認可した device credential に紐づく
  Ed25519 signature を要求する（`VaultEventVerifier`）。
- **Vault Sync は二重に閉じている**——pack 全体が現行世代の VCK で AES-GCM 暗号化され
  （AAD に世代番号を含むので世代のすり替えが落ちる）、その中の object はさらに SegmentKey で暗号化されている。
- **同期の適用は fail-closed かつ record 単位である**——署名・完全性検証に落ちた record は
  skip されるだけで、正当な record の適用を妨げない（§9.2-5）。
- **merge は join-semilattice である**——`compareEvents` の全順序と per-entity LWW により、
  受信順序に依存せず同じ状態に収束する（§9.3）。
- **削除は永続 tombstone として記録される**ので、後から届いた古い `message.add` が
  削除済みメッセージを復活させない。
- **actorSeq の採番はトランザクション内で単調に払い出される**——
  カウンタと既存 event の最大値の両方を上限として取るため、import/restore 後も重複しない（§8.3）。
- **JMAP import は順位を比較して新しい側だけを取り込む**ので、
  古い export を後から読み込んでも新しい状態を巻き戻さない（§9.4b）。
- Mail submission は identity の current did:webvh update key による署名検証を要求し、
  mailFrom が署名者自身のアドレスと一致しない申告を拒否する（§11.2）。
- Mail 受信の宛先解決は公開 routing.json のみに基づき、非公開状態を必要としない（§9.1）。
- DIDComm mediator は未登録 recipient への open forwarding を拒否する。
- Relationship ごとの pairwise DID により、継続会話（1:1・group chat 双方）を公開 identity front door から分離する。
- Canonical encoding と domain-separated signing/hash labels を protocol 全体で使う。

### 15.2 未解消リスク

1. **Local secret at rest（高）** — SegmentKey が IndexedDB 平文。Wallet の device material は
   非抽出鍵で封印されているが、Vault 側は未完成（§7.1）。
2. **全端末喪失時の復旧手段が無い（高）** — 履歴の移送は「起動中の兄弟」か
   「利用者が持つ export ファイル」の二本だけである（§9.4）。
   **export を取っていない利用者が全端末を失えば履歴は戻らない。**
   現状これを利用者に警告する UI は無い。
3. **VCK は前方秘匿性を持たない（中）** — Root key から決定論的に導出されるため、
   Root key の漏洩は**過去世代の VCK もすべて再導出可能にする**。
   これは MLS VEK の「epoch が進むと古い checkpoint が開けなくなる」という
   運用上致命的な性質と引き換えに、意図して受け入れたトレードオフである（§6.2）。
4. **credential revoke gap（高）** — 端末の revoke は did.md Wallet 側の DID Document 編集であり、
   既に取得済みの identity 共有 DIDComm credential や過去世代の VCK を無効化しない。
5. **Relationship handshake 非永続（中）** — pending state はメモリ上の Map にしかない。
   決定論的導出により復旧不能ではなくなったが、reload 直後の ACCEPT は取りこぼす（§12.2）。
6. **Vault Sync の相手先は pairwise ではない（中）** — 兄弟端末との同期は
   DID Document に公開された front-door kid 宛に送るため、
   mediator から「同じ identity の端末同士が話している」ことが観測できる（§4.4）。
7. **DIDComm dedupe lookup 未接続（中）** — projector の `alreadyProcessed()` は常に false。
8. **Routing update race（中）** — ETag/CAS なし。複数端末同時更新で field loss の可能性。
9. **DIDComm group chat のクロスデバイス roster 未同期（中）** —
   `group-chat-store.ts` は device-local な IndexedDB キャッシュである（v1 の受容済み制約）。
10. **死んだ MLS/MIMI import（低）** — `main.ts` に `memberKids` / `encodeMlsDeviceCredential` /
    `MimiClientTransport` の import が残るが、いずれも呼び出されていない。
    reachability チェックはこれを「本番から到達可能」と数えてしまうため、
    `client/mls/group.ts` や `client/mimi/` が生きているように見える（§6.3・§20）。
11. **`recovery-archive.ts` が到達不能なまま残っている（低）** — checkpoint 廃止で唯一の利用者を失った。
    テストだけが使っている（§18）。
12. **No background/push（運用）** — page が閉じている間は同期しない。
13. **Mediator relay-poller / DB write failure の挙動未検証（運用）**（§12.4）。
14. **gitignore 対象の tracked 外 test file（運用、既知）** — 現存する 100 個の `*.test.ts` のうち
    **7 個は git が追跡していない**（`.gitignore` が隠す untracked file）。
    `git worktree` ベースの隔離環境にはこれらが複製されないため、worktree 内での test 実行は
    常にその分だけ過小になる。§18 参照。
15. **未コミットの大規模変更（運用）** — Vault Sync への移行は working tree 上にあり、
    HEAD にはまだ入っていない（削除された 20 個の旧 test file を含む）。§18 の数値はすべて
    working tree の実測である。

## 16. Protocol versioning

Wire record は原則 `version: 1` を持ち、decoder は shape、canonical serialization、hash、署名、
identity binding を検証して fail closed する。Opaque ID は domain-separated hash または UUID として扱う。

互換性を保つ際は、TypeScript union に event kind を追加するだけでは不十分である。
Wire decoder の allow-list、Vault reducer の explicit no-op/application rule、
`VaultProjector` の再計算対象判定、export/import の順位比較、テスト fixture を同時に更新する必要がある。
`src/protocol/vault.ts` の `VAULT_EVENT_KINDS` を `vault/delivery-pack.ts` の decoder が直接参照する実装は、
この cross-layer checklist を単一の正本へ収束させた一例である（§8.1）。

**JMAP export の拡張プロパティ `https://biset.md/jmap/ns:stateRank` は、
この repository が定義する唯一の JMAP 拡張である**（§9.4）。
これを解さない汎用 JMAP クライアントから見ても、export は素直な mailbox/email/blob の集合として読める——
順位情報を失うだけで、構造が壊れることはない。この性質は意図的に維持する。

旧 MIMI Self Vault の wire 型（`mimi-vault-sync.ts` / `mimi-vault-chunks.ts` / `vault-checkpoint.ts`）は
2026-09-15 にファイルごと削除された。schema v14 の upgrade が旧 `vault_crdt_state` store を消す前に
`rescueLegacyCrdtEvents` が走る（§8.3）ことだけが、旧形式に対する唯一の後方互換措置である。

## 17. Build、設定、運用

### 17.1 Client

- `bun run build` — `src/client/app/main.ts` と `src/client/app/sw.ts` を browser IIFE に bundle し、
  `scripts/inline.mjs` で `dist/index.html` に inline 化する。
  **`bun build` 単体では不十分で、必ず `bun run build` で inline まで走らせる。**
- Runtime config — `window.__BISET_CONFIG__`（`ui/config.ts` が読む唯一の場所）。
  | キー | 用途 |
  |---|---|
  | `apexDomain` | このデプロイの apex ドメイン |
  | `mediatorUrls` | 登録先の DIDComm mediator。**Vault Sync もこの mediator を使う** |
  | `walletDeviceName` | did.md Wallet に見せる端末名 |
  | `didDocumentServices` | Wallet 認可時に提案する DID Document service テンプレート。既定は `#didcomm` と `#biset-vault`（VCK 世代）の二つ |
  | `mimiSelfBaseUrl` | **現在は未使用。** 型と既定値は残るが、参照する client 経路が無い（§3） |
- did:webvh の発行・更新・鍵ローテーションは biset 側に無い。DID Document の編集は
  すべて did.md Wallet の認可フローが行う（§3.2・§5）。
- `mediatorUrls` が空、または Wallet が認可した mediator がこのデプロイの設定に含まれていなければ、
  `Wallet-authorized mediator is not configured by this Biset deployment` で fail closed する——
  mediator 無しでは DIDComm も Vault Sync も成立しないためである。

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

2026-09-16、main working tree（`/Users/n/biset`）で実測した。

| コマンド | 結果 |
|---|---|
| `bun run typecheck` | ✅ 成功。`tsc --noEmit`（root/browser）+ mediator + mail-plugin + mimi の **4 設定**すべて |
| `bun run knip` | ✅ **成功（exit 0）**。unused file / unused dependency / unused export の debt は解消済みで、残るのは configuration hints 3 件（`deploy.sh` の ignoreBinaries、mediator/mail-plugin の entry pattern 重複）だけ |
| `bun run reachability` | ✅ 本番エントリから 161/259 到達、テストからのみ 19、**どこからも到達しないもの 0**（vendor 除く） |
| `bun run test` | ✅ **100 個**の `*.test.ts` を serial 実行しすべて成功（exit 0） |
| `bun run build` | ✅ `app.js` **573 KB**、`sw.js` 183 bytes、inline HTML **685 KB**（前回調査の 1188 KB から大幅減——MLS/MIMI 経路が bundle から落ちたため） |

したがって **`bun run check`（typecheck && knip && reachability && test）は現在すべて通る**。
前回調査時点で knip が非 zero だったため release gate として使えなかった状態は解消した。

テストは canonical protocol、Vault crypto/store、**Vault Sync（summary / チャンク分割 / 適用 / wire サイズ回帰）**、
**VaultProjector（LWW 再計算 / tombstone / pending）**、**JMAP export/import の収束**、
**Markdown ミラー（描画 / 解析 / self-write guard / status 変換）**、
DIDComm crypto/mediator/private relationship/group chat mesh、mail-plugin bridge/listener、SQLite、
domain move、SMTP、MIMI サーバーを覆う。

**テストで store を偽装しないという方針を明示的に採っている。** 2026-09-15 に
`checkpoint archive object identity does not match` を取り逃がした直接の原因は、
統合テストのモック store が本物の store の検証（`identityId` の必須性）を再現していなかったことである
（TypeScript のメソッド引数 bivariance がインタフェースと実装の型の食い違いを隠していた）。
現在は当該モックが本物と同じ検証を行う。

**reachability がテストからしか到達しないと報告する 19 ファイル**のうち、
`recovery-archive*.ts` / `manifest.ts` / `delivery-projector.ts` は checkpoint 廃止で利用者を失ったもの、
`client/mls/*` / `client/mimi/client-routing.ts` は Vault Sync 移行で外れたものである（§6.3・§20）。
なお `client/mls/group.ts` と `client/mimi/client-transport.ts` はこのリストに**出てこない**——
`main.ts` に死んだ import が残っているために「到達可能」と数えられているだけで、実際には呼ばれていない。

**残る最大の検証上の空白は `main.ts` の boot wiring である。** browser E2E が無いため、
「部品のテスト成功」と「製品経路への接続」を機械的に区別できない。§14 の
coreBaseUrl gate regression も、2026-09-15 の一連の同期障害も、すべてこの隙間から実機に出た。

## 19. 実装状態の総括

| 領域 | 状態 | 判定 |
|---|---|---|
| did:webvh **解決** | UI/boot に接続。`src/protocol/webvh/` の resolver 系 | 実装済み |
| did:webvh create/update/pre-rotation/domain move | **削除済み**。発行と鍵ローテーションは did.md の責務 | 廃止 |
| **did.md Wallet login** | OAuth + DPoP-bound device session、boot の唯一の入口 | 実装済み |
| **VCK（Wallet 由来の Vault 鍵）と明示的ローテーション** | 導出・世代公開・中断耐性のある rewrap まで接続 | 実装済み |
| Local encrypted Vault（ログ層 = event/object/keyWrap） | UI read/write に接続。DB schema v14 | 実装済み |
| **Vault Sync（端末間同期）** | PUSH/REQUEST/RESPONSE、summary、有界応答、record 単位 skip、バックオフ再送まで接続 | 実装済み |
| **VaultProjector（projection 層）** | per-entity LWW 再計算、永続 tombstone、pending 集合、単一 writer | 実装済み |
| **JMAP export / import（差分収束）** | 暗号化/平文 export、`stateRank` による収束 import、UI 接続済み | 実装済み |
| **Markdown ミラー（File System Access API）** | 書き出し、status 反映、下書き送信、self-write guard、ハンドル永続化 | 実装済み |
| **mediator SSE の多重化** | front-door と全 ContactKey queue を 1 本の EventSource に | 実装済み |
| DIDComm public front door | UI/boot に接続 | 実装済み |
| Private relationship DIDComm 1:1 | 送受信・関係確立（INIT/ACCEPT）とも動作。**関係秘密からの決定論的導出**で収束する | 実装済み |
| DIDComm group chat | 作成・招待・fan-out・受信・roster 表示まで接続 | 実装済み |
| Standalone mediator（"A"/"B"、SQLite 永続化） | binary、protocol、SSE watch、relay-poller あり | 実装済み、"B"が本番稼働中 |
| Mail 受信 / 送信 | **クライアント側の配線が無い**（2026-09-05 に削除）。mediator 側は稼働 | 部品実装済み |
| ~~MIMI Self Vault delivery~~ | ~~MLS application message による端末間同期~~ | **廃止**（2026-09-15） |
| ~~Self Vault checkpoint~~ | ~~VEK で包む復元 snapshot~~ | **廃止**（2026-09-15）。§9.4 が置き換えた |
| ~~Yjs CRDT ログ~~ | ~~delta 同期~~ | **廃止**（2026-09-15）。救出 migration だけが残る |
| ~~MLS Self Group / VEK~~ | ~~roster + 鍵導出 + 搬送~~ | **廃止**（2026-09-15）。§6 が置き換えた |
| `client/mls/`（device-credential 以外）、`client/mimi/` | 本番経路から外れた。死んだ import が `main.ts` に残る | 撤去待ち |
| `recovery-archive*.ts` | checkpoint 廃止で到達不能。テストのみ | 撤去待ち |
| biset-mimi normal/anon/self | サーバーとして稼働、client 呼び出し経路なし | 部品実装済み |
| Remote JMAP account | transport/router のみ | 部品実装済み |
| ActivityPub | adapter なし | 未実装 |
| Web Push / background sync | Service Worker shell のみ | 未実装 |

## 20. 推奨する次の作業順

2026-09-16 時点。Vault Sync への全面移行（`PLAN_vault-sync-redesign.md` Phase 0〜4）の完了直後である。

1. **実機 2 台での同期の通し確認**（唯一残っているチェック項目）。
   `PLAN_vault-sync-redesign.md` の検証要件のうち、これだけが未完である。
   確認すべきは最低限この四つ——(a) 二台目でログインしても device list が両方を出す、
   (b) 一台目が受けたメッセージが二台目に出る、(c) 一台目を落として二台目で編集し、
   再起動した一台目が追いつく、(d) 大きな履歴で 503 が出ない。
2. **死んだ MLS/MIMI コードの撤去**。`main.ts` の `memberKids` /
   `encodeMlsDeviceCredential` / `MimiClientTransport` の import を外し、
   `client/mls/`（`device-credential.ts` を除く）と `client/mimi/` を削除する。
   **import を外すまで reachability はこれらを「生きている」と数える**ため、
   次にこのコードを読む人が「MLS はまだ使われているのか」を調べ直す原因になる（§18）。
   `recovery-archive*.ts` / `manifest.ts` / `delivery-projector.ts` も同じ判断が要る。
3. **全端末喪失時に履歴が戻らないことを利用者に伝え、export を促す**（§9.4・§15.2-2）。
   現状 UI に警告は無い。「export を取っていない利用者が全端末を失えば履歴は戻らない」という
   性質は仕様であり、隠すべきものではない。
4. **メールの再実装**（最大の機能的欠落）。アドレス採番と送信署名鍵を mediator の責務として
   設計する方針は決まっている（§11.2、`tasks/W3-wallet-mail-design-proposal.md`）。
   **実装には did.md 側の mediator が必要で、このリポジトリ内では完結しない。**
5. **`main.ts` の boot wiring に対する統合テスト**。配線ミス由来のバグは現状 実機でしか見つからない（§18）。
6. **Relationship handshake を crash-safe にする**（§12.2・§15.2-5）。
7. **`bun run check` を release gate として CI に入れる**。**現在すべて通る**ので、
   通る状態を維持する仕組みを入れるのが次の一歩である（§18）。
8. **古くなった作業記録の整理**。`REPORT.md` / `NOTE.md` / `WORKSHEET_vault-sync.md` は
   2026-09-15 時点の Yjs 設計を前提とした記録であり、現行コードと矛盾する。

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
    mls/        device credential のみ現役。group 層は本番経路から外れた（§6.3）
    mimi/       MIMI クライアント。本番経路から外れた（§6.3）
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
`webvh-routing.ts`／`webvh-resolve.ts`（routing.json とその合成）、
**`vault-sync-protocol.ts`**（Vault Sync の 3 つの型 URI。biset 独自拡張であり DIF 登録型ではないが、
標準の DIDComm routing と Pickup 3.0 がそのまま運ぶ、§9.2）。

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

**現在の実利用者は biset-mimi サーバーだけである**（client 側の MLS 経路は 2026-09-15 に外れた、§6.3）。
差分には `// biset:` marker があり `VENDOR.md` に記録される。
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
**2026-09-15 以降、この配下は「ログ層」と「projection 層」に役割が分かれている**（§8・§9）。

**`store/vault/` — ログ層（暗号化された長期正本）**

| ファイル | 責務 |
|---|---|
| `store.ts` | IndexedDB 永続化層（schema **v14**）。object / event / key wrap / outbox / **actorSeq カウンタ / projection meta** を1つのトランザクション境界で扱う |
| `objects.ts` | 暗号化 object の封入と復号、SegmentKey 生成 |
| `events.ts` | immutable event の署名・検証 |
| `manifest.ts` | Merkle manifest と差分検出（**現在は本番から到達しない**、§18） |
| `crypto.ts` | VCK による SegmentKey の wrap と検証 |
| `active-segment.ts` | 書き込み可能な現行 segment の決定と検証 |
| `segment-key-resolver.ts` | 鍵解決のアダプタ境界。鍵は一時的で永続化しない |
| **`vault-content-key.ts`** | **VCK の世代 URN と、Wallet 由来の鍵を epoch 鍵抽象へ適合させる resolver**（§6.2） |
| **`vault-key-rotation.ts`** | **世代ローテーションの rewrap。冪等・再開可能** |
| **`commit.ts`** | **共有 Vault 状態を書く全経路が通る唯一の組み立て地点** |
| `mutations.ts` / `mutation-records.ts` | mutation の build と、検証してから復号する共通ステップ |
| `mail-message.ts` | メール形メッセージの event/object 生成 |
| `credential-store.ts` | private credential の汎用 reader / sink |
| `contact-key{,-reader,-sink}.ts` | ペアワイズ関係鍵（`ContactKeyV1`） |
| `didcomm-credential.ts` | DIDComm 鍵の記述子 |
| `openpgp-credential.ts` | OpenPGP 鍵の指紋正規化（過去 event の復号のためだけに残る） |
| `delivery-pack.ts` | **Vault Sync が運ぶ `VaultDeliveryPackV1` の正準ボディと decode allow-list** |
| `delivery-ingest.ts` / `delivery-projector.ts` | 共有 delivery の検証と projection（後者は現在到達しない） |
| `ingress-ingest.ts` | 外部 ingress の確定 |
| **`vault-sync-chunks.ts`** | **`VAULT_SYNC_CHUNK_BYTES = 128 KB` と、ハッシュ検証つきチャンク分割**（§9.2-4） |
| **`projector.ts`** | **projection 層の唯一の writer。per-entity LWW 再計算・tombstone・pending**（§9.3） |
| **`jmap-export.ts`** | **汎用 JMAP 形式の export/import と `stateRank` による差分収束**（§9.4b） |
| **`markdown-mirror.ts`** | **Markdown の描画・解析・self-write guard・status 変換**（§10.4） |
| **`markdown-directory.ts`** | **File System Access API 側。ディレクトリハンドルの永続化、走査、`FileSystemObserver`** |
| **`legacy-crdt-migration.ts`** | **schema ≤13 の Yjs store から event を救出する一度きりの橋。現行 tree で `yjs` を import する唯一のファイル** |
| `projection-rebuild.ts` | 全 projection の再構築（災害復旧経路） |
| `blob-reader.ts` | SegmentKey をメモリ上で解決する |
| `recovery-archive{,-export}.ts` | canonical な archive snapshot 形式。**checkpoint 廃止で本番から到達しない**（§4.5） |

**`store/projection/` — UI が読む JMAP 形の read model（派生）**

`gateway.ts`（型）、`reducer.ts`（検証済み event から決定的に組み立てる）、`indexeddb.ts`（永続化）、
`mutations.ts`（`Email/set` を Vault mutation intent へ）、`vault-mutation-sink.ts`（書き込み橋）、`transport.ts`。

> **削除されたファイル**（2026-09-15）: `crdt-log.ts`、`mimi-vault-sync.ts`、`mimi-vault-chunks.ts`、
> `vault-checkpoint.ts`、`recovery-archive-rewrap.ts`、`storage-root.ts`、
> `didcomm-device-key{,-reader,-sink}.ts`。

### 21.4 `client/didcomm/` — client 専用の DIDComm

`protocol/didcomm/` とは別で、こちらは Vault と結合している。どのサーバーからも到達しない。

| ファイル | 責務 |
|---|---|
| `send-message.ts` | 送信の入口。DID Document 解決から発送まで。`initiateRelationship` / `sendRelationshipAccept` もここ |
| `front-door-send.ts` | Vault 非依存の送信半分 |
| `relationship.ts` | ペアワイズ関係の wire 形（INIT / ACCEPT、mediator service 記述） |
| `basicmessage.ts` | Basic Message 2.0 |
| `trust-ping.ts` | Trust Ping 2.0 |
| `ingress-projector.ts` | 受信の鍵選択と Vault への projection |
| `group-chat.ts` | フルメッシュのグループチャット |
| `group-chat-store.ts` | グループ roster の端末ローカル保管（IndexedDB） |
| **`vault-sync.ts`** | **端末間同期の全体。summary、PUSH/REQUEST/RESPONSE、チャンク分割、適用、バックオフ再送、sibling 解決**（§9.2） |
| `mediator-sync.ts` | mediator 登録の self-heal |
| `mediator-watch.ts` | 1つの kid に対する SSE ライブ配送 |
| **`mediator-multiplex-watch.ts`** | **front-door と全 ContactKey queue を 1 本の EventSource に多重化する**（§10.3-10、§12.4） |

### 21.5 `client/identity/`、そして本番から外れた `client/mls/` と `client/mimi/`

**`client/identity/`** — `bootstrap.ts`（Vault 側の identity 境界。VCK による鍵解決、
SegmentKey wrap、各種 reader/sink の組み立て）、`idkey.ts`。

`identity/wallet/` — **アプリへの唯一の入口**である。

| ファイル | 責務 |
|---|---|
| `did-md-oauth.ts` | did.md OAuth。device session の確立、**derived secret（VCK と関係秘密）の取得**、DID Document 編集の要求 |
| `did-md-store.ts` | device session の暗号化保管（非抽出 AES 鍵で private key・VCK・関係秘密を封印） |
| `relationship.ts` | Wallet 起点の関係確立。**同一 counterparty への `ensureContact` を直列化**し、**関係秘密から did:peer を決定論的に導出**する（§12.2） |
| `didcomm-outbox.ts` | 送信 outbox と再送 |

`identity/webvh/` と `identity/web/` — `log-io.ts`（client からのみ使う log 入出力）と、
`create-genesis.ts` / `migrate.ts` / `web/*`（**本番から到達しないが、
残す側のコードのテストが実物の did:webvh log を組み立てる唯一の手段**として使っている）。

**`client/mls/` — 一つを除いて本番経路から外れた**（§6.3・§20-2）。

| ファイル | 現況 |
|---|---|
| `device-credential.ts` | **生きている**。did.md Wallet が発行する device credential の符号化・検証 |
| `group.ts` / `store.ts` / `identity.ts` / `keypackage-store.ts` / `webvh-authentication-service.ts` | 呼び出し元を失った。`main.ts` に死んだ import が残るだけ |

> `vault-epoch.ts`（VEK 導出）と `segment-key-membership.ts` は 2026-09-15 に削除された。
> Vault の鍵境界は MLS ではなく VCK になった（§6.2）。

**`client/mimi/`** — `client-transport.ts` / `client-routing.ts` のみが残り、
どちらも本番経路から外れている。`vault-room.ts` / `vault-session.ts` / `vault-watch.ts` /
`room-migration.ts` は 2026-09-15 に削除された。

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
