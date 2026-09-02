# Biset MIMI Server（`biset-mimi`, `src/mimi/`）設計計画

> Status: draft / 未実装
> 作成日: 2026-09-01
> 前提: [PLAN_biset-mls-ds.md](PLAN_biset-mls-ds.md)（identity-blind DS、biset内部専用、**本文書との関係は§0参照——恒久併存ではなく過渡的な前身**）、[PLAN-mimi.md](PLAN-mimi.md)（MimiContent、application messageの中身、本文書とは独立に併存する）、[docs/protocols/mls-ds-1.0.md](docs/protocols/mls-ds-1.0.md)。
> 出典テキスト: `mimi-protocol-06.md`（リポジトリ直下、draft-ietf-mimi-protocol、2026-04版、Barnes et al.）。以下「spec」と呼ぶ場合はこの文書を指す。行番号はこのファイルのもの。

## 0. 背景・経緯（このセッションの議論の結論、2026-09-01改訂）

biset は現在 `biset-mls-ds`（identity-blind、`GroupLocalId`方式、biset同士専用、外部providerとの相互運用なし）を持つ。これはプライバシー最優先の設計として明確に優れているが、**仕様準拠でも相互運用可能でもない**（[PLAN_biset-mls-ds.md §5](PLAN_biset-mls-ds.md)に明記）。

検討の結果、「1つのサーバーで完全な秘匿性と完全な仕様準拠/相互運用性を両立させる」ことは原理的に不可能という結論に達した——spec自体がhubに実credential・franking用のsender identity・participant listの把握をMUSTとして要求しており（§5.4.1, §7.5）、相互運用性はその要求を他providerと共有できることが前提だから。

**最終形（確定方針）**: `biset-mls-ds`は**恒久的な並存トラックではなく、廃盤を前提とした過渡的な実装**である。最終的にbisetのhub側実装として残るのは **`biset-mimi`のみ**。ただし運用上は`biset-mimi`のコードベースを**2つの独立したプロセス**として動かす：

- **`biset-mimi`（normal-mode）**: spec準拠、実credentialを扱う。第三者providerとの相互運用が主目的。
- **`biset-mimi`（anon-mode）**: 同じコードベース・同じ設計（§7のanon mode）だが、**プロセス・DBを完全に分離**して動かす。あるroomがanon/normalどちらで運用されるかは、そのroomをどちらのプロセスに作成するかで決まる（作成後の移行は想定しない——credentialの形が根本的に違うため）。

`biset-client`はこの2つのプロセスの両方に接続する（相手や会話の性質に応じて、どちらのインスタンスにroomを作るかをクライアント側で決める）。

**プロセス分離の理由**: これはbisetの既存設計方針（[PLAN_biset-mls-ds.md §2](PLAN_biset-mls-ds.md)「engineロジックは共有するが、プロセス・DB・認可対象は分離する」）をそのまま踏襲したもの。normal-modeのDBが漏洩・差し押さえられても、anon-modeのDBには実identityと相関づけられるデータが物理的に存在しない——単一プロセス内の「room単位フラグ」よりも強い分離境界になる。

**`biset-mls-ds`の廃盤条件**（§11未決事項に詳細）: `biset-mimi`（anon-mode）が、今の`biset-mls-ds`と同等以上のidentity-blindness保証を実際に満たしたと確認できた時点で、`biset-mls-ds`とその既存roomデータの移行作業に着手し、最終的にサービスごと廃止する。それまでは`biset-mls-ds`は現状維持で動き続ける。

**さらに将来的な統合（`biset-coordinator`の置き換え）**: `biset-coordinator`が担うSelf Group DS（本人の複数端末間でのVault同期用MLS DS、第三者は関与しない）も、長期的には`biset-mimi`に統合できる可能性が高い。spec §7.5が「1人のuserが複数clientを持つroom」を最初から前提にしていることに着目すると、**Self Group = 参加者が本人1人（複数device=複数MLS leaf）だけのMIMI room**という特殊形として素直にモデル化できる。つまりbisetの最終的なhub型サービスは、原理的には`biset-mimi`だけに一本化しうる。これは§14で方向性のみ記録し、**具体設計はまだ行わない**（理由: Self Group同期には可用性要件がthird-partyトラフィックと根本的に異なり、[PLAN_biset-mls-ds.md §2](PLAN_biset-mls-ds.md)が元々`biset-coordinator`と`biset-mls-ds`を分離した理由そのものが、この統合でも解決すべき課題として残るため）。

クライアント側の振り分け（相手がbiset内部かどうか、anon/normalどちらを使うか、を自動選択する仕組み）は [MIMI client routing](PLAN_biset-mimi-client-routing.md) で扱う（本文書はサーバー実装のみ）。

## 1. 目的・スコープ

`biset-mimi` は draft-ietf-mimi-protocol の **provider実装**（room/hub/follower間のtransport + E2E security層のMIMI固有部分）を実装する、独立した新規デプロイ単位。

**含むもの**:
- room state管理・hub/follower間のprovider-to-providerプロトコル（spec §5の全endpoint、§4.3）
- MLS commit/proposalのhub処理・franking（spec §5.3-5.4）
- KeyPackage/key material取得（spec §5.2）
- Minimal Metadata Rooms、およびIETF草案が未確定のまま残した鍵管理方式の具体案（§7、本文書の主要な新規設計）

**含まないもの（明確に別スコープ）**:
- application message の中身の解釈（MimiContent、CBOR）→ [PLAN-mimi.md](PLAN-mimi.md)がクライアント側で既に担当。`biset-mimi`自体はcontentをopaqueに扱う（spec自身もそう規定——line 9「This document does not define the plaintext content format carried inside an MLS application message」）。
- room policy の役割/権限体系そのもの → `draft-ietf-mimi-room-policy`が別ドラフト。本文書は spec が要求するフック（role_index、permission check）だけ用意し、**具体的なロール定義は Phase 3 で別文書化する**（§11未決事項1）。
- クライアント側のtransport振り分けUI/UX → [MIMI client routing](PLAN_biset-mimi-client-routing.md) が、相手のcapabilityによる自動選択とroom非移行を規定する。

## 2. ディレクトリ構成

```
src/mimi/
  index.ts                 # entrypoint。環境変数 MIMI_MODE=normal|anon で
                            # createMimiDeployment()の起動モードを切り替える
                            # （1バイナリを2つの systemd service/DBとして動かす、
                            #   mediator/index.ts と mail-plugin/index.ts が
                            #   同じ createMediatorDeployment を共有する形と同型）
  deployment.ts             # createMimiDeployment({ mode, ... })。
                             # Bun.serve wrapper, CORS, idleTimeout=255
                             # (このセッションで学んだSSE/heartbeatの教訓を最初から適用する)
  http.ts                   # HTTPルーティング（spec §5の全endpoint + biset独自の
                             # クライアント向け配信経路、§5.1参照）
  store.ts                  # room state永続化（SQLite）。normal-mode/anon-modeで
                             # 別ファイルのDBを開くが、テーブル定義・ロジックは共通
                             # （mode自体はstore.tsに条件分岐を持ち込まない——
                             #   「どちらのcredential形状を受け付けるか」は
                             #   authorizer.ts/anon/*側の責務にする）
  authorizer.ts             # 署名検証・room policyフック。mode=anonの時のみ
                             # PseudonymousCredentialのみ受理する
  franking.ts               # §5.4.1 franking tag生成・検証（両modeで共通、無関係）
  directory.ts              # §5.1 directory, §5.2 key material fetch
  provider-transport.ts     # provider間の発信HTTPクライアント（mTLS, From/Host）— Phase 3+
  wire.ts                   # JSON+base64urlエンコード（conversation-mls-ds-wire.tsに倣う）
  protocol-types.ts         # RoomState/ParticipantListData/PseudonymousCredential等の型
  room-policy.ts            # role/permissionのフック（Phase 3で肉付け）
  anon/
    identity-link.ts        # §7 anon mode: identity_link_ciphertextの生成・復号
    pseudonym.ts             # pseudonym発行
```

**デプロイ単位**: 1つのバイナリ（`biset-mimi`）を`MIMI_MODE`違いで2回デプロイする——`biset-mimi-normal.service`と`biset-mimi-anon.service`、DBパスも別（`mimi-normal.sqlite`/`mimi-anon.sqlite`）。§0で述べた通りプロセス・DB分離が目的であり、コード自体は完全に共有する。

client側（別文書で詳細化、ここではファイル名だけ予約）:
```
src/mls/mimi-client-transport.ts   # normal/anon両方のbaseUrlを受け取れる形にする
                                    # （biset-mls-ds/client-transport.tsに相当するMIMI版）
```

## 3. Wire encoding

**JSON + base64url**（既存`conversation-mls-ds-wire.ts`と同じ規約）。

spec自身が明言している通り（line 251-253）、TLS Presentation Languageによる構造体表記は「placeholder」であり符号化方式そのものは規定していない。JSONを選ぶことはspec違反ではない——ただし外部providerとの実際の相互運用には相手側もこの符号化を解釈できる必要があるため、**Phase 3（フェデレーション実装時）で相手実装の実際のwire形式を確認し、必要ならアダプタ層を足す**（§11未決事項2）。当面はbiset内でのend-to-end検証を優先する。

## 4. データモデル（spec準拠、mls-dsとの対比）

| 概念 | biset-mls-ds（既存、§0の通り将来廃盤予定） | biset-mimi（本文書） |
|---|---|---|
| メンバー識別子 | `GroupLocalId`（使い捨て公開鍵、groupごと） | 実credential（`did#fragment`相当をMLS Credentialとして格納）。anon mode時のみ`PseudonymousCredential`（§7） |
| Participant list | 存在しない（roster=`Set<GroupLocalId>`のみ） | spec §7.5準拠、`UserRolePair`のリスト。role_index付き |
| GroupInfo/external join | 削除済み（leak経路のため） | spec準拠で実装する（§5.6 `groupInfo/{roomId}`）。anon mode時はGroupInfoのratchet treeがpseudonym化されていることが必須条件（§7.2） |
| Franking | 存在しない | spec §5.4.1準拠で実装 |
| 招待/通知 | biset独自DIDComm 3メッセージ（DSは無関係） | spec §5.5 `notify/{roomId}`（hub発、fanout） |

`Room state`（spec §4.3.1, line 928-967）: room ID、base policy、participant list、room metadata、MLS GroupContext相当。`biset-mimi`の`store.ts`はこれをSQLiteに永続化する——`biset-mls-ds/store.ts`のordered log設計を踏襲するが、**rosterの中身が実credential/pseudonymを含む**点が構造的な違い。

## 5. 実装対象エンドポイント（spec §5、行番号付き）

| Endpoint | spec行 | 用途 | Phase |
|---|---|---|---|
| `GET /.well-known/mimi-protocol-directory` | 1023 | provider自己申告 | 3 |
| `POST /keyMaterial/{targetUser}` | 1053 | KeyPackage取得 | 0 |
| `POST /update/{roomId}` | 1357 | room state変更（proposal/commit） | 0 |
| `POST /submitMessage/{roomId}` | 1528 | application message送信（franking込み） | 1 |
| `POST /notify/{roomId}` | 1924 | hub→follower（他providerサーバー）fanout | 3 |
| `POST /groupInfo/{roomId}` | 2036 | external join用鍵情報 | 3 |
| `POST /requestConsent/{targetDomain}` | 2219 | provider間の受信同意 | 3 |
| `POST /updateConsent/{requesterDomain}` | 2220 | 同上応答 | 3 |
| `POST /identifierQuery/{domain}` | 2346 | ユーザー存在確認 | 3 |
| `POST /reportAbuse/{roomId}` | 2568 | 濫用通報（franking証跡を使う） | 3（frankingの存在意義そのもの） |
| `GET/POST /proxyDownload/{downloadUrl}` | 2713 | 添付ファイル中継 | 3 |

### 5.1 重要な欠落: クライアント向け配信経路はspecの範囲外

spec自身が明言している通り（line 357-358, line 918-922）、**MIMIプロトコルはprovider同士（サーバー間）の通信しか定義しない**。`notify/{roomId}`はhubが**他providerのサーバー**へfanoutする経路であり、hubが**自分自身のclient**へ配信する経路ではない——それはprovider内部の実装に委ねられている（line 358-359「Interactions between clients and servers within a service provider domain are shown here for completeness, but surrounded by [[ double brackets ]]」）。

つまり、Phase 0の時点で`update/{roomId}`にcommitを送っても、**そのcommitを他のメンバーがどうやって受け取るか、spec本文には規定がない**。biset独自にクライアント向け配信APIを用意する必要がある——`biset-mls-ds`の`deliveries/pull`/`deliveries/watch`+SSEと全く同じ役割のものを、`biset-mimi`にも持たせる。これはspecの11エンドポイントとは別に、biset独自のエンドポイントとして追加する（`src/mimi/http.ts`内、パスは`biset-mls-ds`の命名に倣い`/v1/mimi/deliveries/pull`・`/v1/mimi/deliveries/watch`・`/v1/mimi/deliveries/stream`とする）。**Phase 0から必須**（これが無いと最小構成のroomすら動作確認できない）。§13のタスク0.5.1として追加済み。

## 6. Franking設計（spec §5.4.1、行1634-1885）

構造体はspecの`FrankAAD`/`FrankingAgentData`をそのままJSON化する。実装フロー（§5.4.1.1-3の要約、行1693-1852）:

1. 送信者: `franking_tag`（32byte乱数）を生成し、MLS application messageのAADとしてE2E暗号文自体に含める（暗号文とtagがバインドされる——Facebook方式との違いその1、line 1860-1866）。送信者identityをhubへ別途伝える。
2. Hub: contentは読めないが、`franking_tag`とhubの`hub_key`から`server_frank = HMAC_SHA256(hub_key, franking_tag || context)`を計算し、`accepted_timestamp`と共に`franking_integrity_signature`で署名する（line 1770-1785）。**送信者identityはfollowerには一切転送しない**——hubだけが知る（line 1868-1871）。
3. 受信者: 復号後、`franking_integrity_signature`を`franking_agent`の公開鍵で検証し、hubのcontextとMLS復号結果が一致することを確認する（line 1872-1884）。

`src/mimi/franking.ts`に実装する。`hub_key`はroomごとの秘密値——`store.ts`の room state に保持し、DBが漏洩すればfrankingの完全性は失われる(spec自身が受け入れているtrust model、biset側で緩和できない)。

## 7. Anon Mode（Minimal Metadata Rooms）設計 — 本文書の中心

spec §6（行2834-2929）はMMRの構造（`PseudonymousCredential`）を定義しているが、**鍵管理方式は明示的にTODOのまま**（line 2922-2928: 「efficient / allows basic MIMI flows / all participants can learn identities at all times / provides FS and PCS w.r.t. metadata hiding」という要件だけ列挙し、「several options... not yet fully specified」で終わっている）。ここをbiset独自に埋める。

### 7.1 requirements の整理

IETFの列挙した4要件のうち、後半2つは緊張関係にある:
- 「全参加者が常に全員の身元を知れる」→ 新規参加者も**過去の**`identity_link_ciphertext`を読めないと満たせない。
- 「metadata hidingについてFS/PCSを提供する」→ 鍵が不変だとFS/PCSが成立しない（過去の鍵が今でも有効なら、今の侵害が過去のidentity linkも暴露する）。

固定鍵で全部満たそうとすると矛盾する。**biset案は「鍵を回転させつつ、回転のたびに現存メンバー全員分を再暗号化する」ことで両立させる。**

### 7.2 biset案: MLS epoch exporter secretを再利用する

MLSの`exportSecret`（[group.ts:427](src/mls/group.ts)、既存実装）はRFC 9420のkey scheduleに基づき、**epochごとに新しい値を生成し、かつ前後のepochの値から独立**という性質を既に持つ——これはまさにIETFが求めるFS/PCSそのもの。新しい暗号プリミティブを何も発明せず、既存のMLSインフラをそのまま転用する。

```
identity_link_key(epoch) = exportSecret(state, "mimi mmr identity-link", groupId_bytes, 32)
```

**手順**:
1. Commit（Add/Remove/Update、epoch Eから E+1へ）が確定するたびに、コミット送信者は**現存する全メンバー分**の`IdentityLinkTBE`を`identity_link_key(E+1)`で再暗号化し、新しい`identity_link_ciphertext`としてCommitに添付する（`AppDataUpdate`的な仕組み、spec自体のAppSync機構[I-D.barnes-mls-appsync]に相乗りする）。
2. 現存する任意のメンバーは、自分が持つ現在epochのexporter secretで、**全員分**の`identity_link_ciphertext`を即座に復号できる → 「全参加者が常に全員の身元を知れる」を満たす。
3. epoch E+1へ進んだ時点で、well-behavedなクライアントはepoch Eのsecretを破棄する（既存のMLS実装が既にそうしている）→ 過去epochの侵害から今のidentity linkを守れない代わりに、**今の侵害からは過去のidentity linkが守られる**（FS）。
4. 侵害されたメンバーがCommit（Remove等）で除去され epoch が進めば、以後のidentity_link_ciphertextは新epochの鍵で暗号化されるため、除去後は復号できなくなる（PCS）。

### 7.3 コスト

再暗号化はO(現存メンバー数)——「efficient」の要求を完全には満たさない（IETFが求める4要件の完全な両立自体、暗号学的に無償ではない）。大規模group（数百人規模）でのCommit毎のオーバーヘッドは§10 release gateで実測して許容範囲を見極める。当面のスコープ（数〜数十人のroom）では現実的なコストと判断する。

### 7.4 pseudonym発行

`user_pseudonym`/`client_pseudonym`は spec通り「providerドメイン付きrandom UUID」（line 2866-2867）。`src/mimi/anon/pseudonym.ts`で発行し、**同一ユーザーの同一roomでの`user_pseudonym`は不変**（spec要件、line 2890-2892）だが、**別roomでは別のpseudonym**（room間の相関を作らない）。

### 7.5 残る限界（正直に明記する）

- roomのメンバー数・参加/離脱タイミング・commit頻度はhubに見え続ける（pseudonym化されるのは識別子だけ）。
- frankingは anon mode でも動く——hubは「pseudonymが誰かの実credentialに紐づく」ことは知らないが、「このpseudonymがこの時刻にこのメッセージを送った」という事実（§6の意味での metadata）自体は握る。これはbiset-mls-dsが最初から持っていない性質であり、**anon modeを使ってもbiset-mls-ds（既存）と同等の保証にはならない**——利用者への説明にこの限界を含める。

## 8. 既存コードとの再利用方針（重複実装をしない）

- **MLSエンジン本体**: `src/mls/vendor/*`（RFC 9420実装、credential/keyPackage/commit/groupInfo/exportSecret含む）をそのまま使う。`biset-mls-ds`と違い、`biset-mimi`のhub処理はcredential/roster/GroupInfoの中身を実際に読み書きする必要がある（spec構造上避けられない、§4参照）ので、`src/mls/group.ts`の`groupInfoMemberKids`/`memberList`/`exportSecret`等をhub側ロジックからも呼び出す。
- **署名検証**: `src/mls-ds/authorizer.ts`のEd25519検証パターンを踏襲するが、DID解決が絡む分岐が必要になる点が異なる（新規実装、コピーではなく差分を明記する）。
- **watch-token/SSE**: `notify/{roomId}`のfanout配送は、このセッションで直した`: connected`即時flush + `idleTimeout: 255`の教訓をそのまま初期実装に織り込む（同じ罠を再度踏まない）。
- **wire encoding**: `src/protocol/conversation-mls-ds-wire.ts`のbase64url JSON規約をそのまま流用。

## 9. フェーズ別実装計画

### Phase 0: 最小限、単一hub、フェデレーションなし（今回の最初のゴール）
- `src/mimi/`のディレクトリ・型・`store.ts`・`http.ts`の骨格。
- room作成、`update/{roomId}`（commit/proposal提出）、`keyMaterial/{targetUser}`（KeyPackage取得）。
- **biset独自のクライアント向け配信経路**（§5.1、spec本文には無い——`notify/{roomId}`はprovider間専用）。
- biset自身が常にhubである前提（他providerとの実際の通信なし、`provider-transport.ts`はスタブ）。
- franking・anon modeはまだ実装しない（プレーンなcredential visibleモードのみ）。
- 目的: MLS group操作がbiset内で単一hub前提で正しく動き、かつ他メンバーがそれを実際に受信できることをテストで確認する。

### Phase 1: Franking
- §6の全機構を実装。`submitMessage/{roomId}`をfranking付きで完成させる。

### Phase 2: Anon Mode
- §7の`identity_link_key`再暗号化方式を実装。pseudonymous credentialでのroom作成・Add/Removeを通しでテストする。

### Phase 3: 実フェデレーション
- `provider-transport.ts`のmTLS/From-Host実装。
- `directory.ts`、`requestConsent`/`updateConsent`/`identifierQuery`。
- room policy（別ドラフト）との統合。
- 実在する他社MIMI実装（あれば）との相互接続テスト。

### Phase 4: クライアント統合
- `src/mls/mimi-client-transport.ts`。
- 前回議論した「相手のcapabilityで自動的にnormal/anonを切り替える」ロジック（別文書）。

## 10. Release gates

- Phase 0: biset内の3+デバイスでroom作成・commit・KeyPackage交換が通しで動き、**他メンバーがbiset独自の配信経路（§5.1）経由でcommit/application entryを実際に受信できる**。
- Phase 1: frankingされたmessageの受信者検証が通る。frankingなしのmessageは拒否される。
- Phase 2: anon modeのroomで、新規参加者が既存メンバー全員の実credentialをidentity_link_ciphertext経由で復号できる。epoch進行後、破棄したはずの旧epoch鍵で過去のciphertextが復号できないことを確認する回帰テストを書く。
- Phase 3: 最低1つの外部（または自前の別インスタンス2台構成）hub/follower間でroomを共有できる。
- Phase 6: 本物の署名済み MLS PublicMessage Commit で、room作成・member追加・room metadata・participant list・franking agent の AppData 更新が通る。`mimi.biset.md` と `mimi-anon.biset.md` の本番 HTTPS でこれを確認し、directory が広告する `groupInfo` は privacy policy に従う明示的な 403 `not-allowed` を返す。

## 11. 未決事項

1. **room policy（役割/権限体系）の具体設計** — 2026-09-01に最新版 [draft-ietf-mimi-room-policy-04](https://datatracker.ietf.org/doc/html/draft-ietf-mimi-room-policy-04)（2026-07-06、Internet-Draftであり未確定）を確認した。各Participantはちょうど1つの`role_index`を持ち、roleはcapability・人数/active人数制約・許可されたrole遷移を持つ。Add/Remove/role変更はこの三点を検証し、role定義変更とParticipant List変更を同一commitに含めてはならない。role定義はMLS GroupContextの`app_data_dictionary` componentであり、component IDはなおTBDである。従って3.5は、まずdraftの意味論をそのまま表す**純粋なpolicy evaluator**（symbolic capability名、role/遷移/人数制約の検証）として実装し、現行のopaqueな`basePolicy` byte列を独自JSONとして解釈・保存しない。最終component IDとTLS wire形式が確定した時点で、MLS extensionからこのevaluatorへ入力するdecoderを追加する。
2. **他社MIMI実装の実際のwire形式** — JSON採用を決めたが、実際に相互接続するprovider次第でアダプタが要る可能性がある。Phase 3で確認する。
3. **anon modeの再暗号化コストの実測** — §7.3。大規模room未対応の可能性を許容するか、別の緩和策（例: 変更があったメンバーの差分だけ再暗号化）を検討するかは実装しながら判断する。
4. **frankingのhub_key漏洩時の対応** — spec自身のtrust modelの限界であり、biset固有の対応策があるかは要検討。
5. **`biset-mls-ds`の廃盤条件・移行手順** — [MIMI transition and Self Group isolation](PLAN_biset-mimi-transition.md)に、置換判定の6条件と「credential/stateは変換せず、新anon roomへE2E再招待する」移行手順を記録した。pseudonymous credentialのorigin/binding検証が未実装のため、**廃盤はまだ許可されない**。
6. **`biset-coordinator`（Self Group DS）統合の是非・設計** — 同文書に、normal/anonと共有しないowner-only第3プロセス`biset-mimi-self`という提案を記録した。Vault同期の可用性要件を満たす検証まで、CoordinatorのSelf Group DSを維持する。

## 12. 出典

- `mimi-protocol-06.md`（本リポジトリ直下、draft-ietf-mimi-protocol、行番号は本文書内の引用箇所参照）
- RFC 9420（MLS）、RFC 9750（MLS Architecture、DS定義）
- `I-D.barnes-mls-appsync`（AppSync proposal、anon modeの再暗号化配送に相乗りする候補）
- `PLAN_biset-mls-ds.md`（既存の過渡的実装、identity-blind revision、leak経路①②③の教訓）
- `docs/protocols/mls-ds-1.0.md`
- `PLAN-mimi.md`（MimiContent、application message content、本文書とは独立）
- このセッションの調査: MIMI federation/hub SPOF分析、MMR provenance調査（`draft-kohbrok-mimi-metadata-minimalization`が個人ドラフト・expired、本流へopt-inとして取り込まれた経緯）

## 13. 作業ワークシート（マルチエージェント協働用）

複数のagentがこの文書を起点に並行作業できるよう、フェーズごとにチェックボックス付きタスクを列挙する。**この文書自体が唯一の真実源**——各agentは着手前にこのファイルの最新版を読み、他agentが既に着手/完了したタスクを重複して行わない。

### 進め方のルール

1. **着手前**: 該当タスクの行を `- [ ]` → `- [~] (agent: <名前や識別子>, 開始: <日時>)` に書き換えてコミットしてから作業を始める（他agentとの衝突を避けるため、これ自体を先にコミット/共有する）。
2. **完了時**: `- [~]` → `- [x] (完了: <日時>, 関連ファイル/コミット)` に書き換える。実装中に設計上の決定を変えた場合は、該当する本文（§1-12）も同じコミットで更新する——ワークシートと設計文書を乖離させない。
3. **依存関係**: 「depends on」に列挙されたタスクが `[x]` になるまで着手しない。特に**0.1・0.2（型とwire encoding）は他の全タスクの前提**——最初に完了させる。
4. **フェーズを跨がない**: 各フェーズの§10 release gateを満たすまで、次フェーズのタスクには着手しない（Phase 0の基盤が揺れている状態でPhase 1以降を積み上げると手戻りが大きい）。
5. **既存実装を参照する**: 各タスクに「参照実装」を付記した。同じ意味の処理を新しく発明せず、必ず参照実装のパターンに合わせる（構造・命名・エラーハンドリングの流儀含む）。迷ったら参照実装のコードそのものを読むこと。
6. テストは実装と同じタスク内で書く（別タスクに分離しない）——このリポジトリの既存の流儀（`bun run test`が全ファイル通ることを都度確認する）に合わせる。

### Phase 0: 最小限・単一hub・フェデレーションなし

- [x] **0.0 tsconfig/ビルド配線** (完了: 2026-09-01, `tsconfig.mimi.json`, `package.json`): `tsconfig.mimi.json`を新設（`tsconfig.mls-ds.json`を複製・調整）。`package.json`に`build:mimi`スクリプトと`typecheck`複合コマンドへの追加を行う。
  - 参照実装: `tsconfig.mls-ds.json`, `package.json`の`build:mls-ds`/`typecheck`
  - depends on: なし（最初に着手可能）
- [x] **0.1 型定義** (完了: 2026-09-01, `src/mimi/protocol-types.ts`): `RoomState`/`ParticipantListData`/`UserRolePair`/`RoomMetadata`/KeyPackage関連の型/Update・Commit submission bodyの型/エラー形状を定義する（§4, §5, §7の型を先取りして置いてよいが、Phase 0で使わないフィールドは`?`にして後続フェーズで埋める）。
  - 参照実装: `src/protocol/conversation-mls-ds.ts`
  - depends on: なし
- [x] **0.2 wire encoding** (完了: 2026-09-01, `src/mimi/wire.ts`): `src/mimi/wire.ts`。0.1の型のJSON+base64urlエンコード/デコード。
  - 参照実装: `src/protocol/conversation-mls-ds-wire.ts`
  - depends on: 0.1
- [x] **0.3 room state store** (完了: 2026-09-01, `src/mimi/store.ts`, `src/mimi/protocol-types.ts`, `src/mimi/wire.ts`): `src/mimi/store.ts`。SQLite永続化。room作成、epoch管理、participant list（実credential含む）、KeyPackage directory（publish/take）。ordered logの設計は`mls-ds/store.ts`を踏襲するが、rosterの中身が実credential/DIDを含む点が構造的な違い（§4の対比表参照）。
  - 参照実装: `src/mls-ds/store.ts`
  - depends on: 0.1
- [x] **0.4 認可** (完了: 2026-09-01, `src/mimi/authorizer.ts`): `src/mimi/authorizer.ts`。client→hub（Phase 0では常にbiset自身がhub）のリクエスト署名検証。spec自体はprovider内部のclient-server認証方式を規定していない（line 358「the MIMI protocol only defines interactions between service providers' servers」）ので、実credentialの署名鍵によるEd25519署名検証として実装してよい（`mls-ds-1.0.md`のGroupLocalId方式と同じ形だが、鍵が実credentialの署名鍵である点が違う）。
  - 参照実装: `src/mls-ds/authorizer.ts`
  - depends on: 0.1
- [x] **0.5 HTTPルーティング** (完了: 2026-09-01, `src/mimi/http.ts`): `src/mimi/http.ts`。Phase 0対象の2エンドポイントのみ実装: `POST /keyMaterial/{targetUser}`（spec行1053）、`POST /update/{roomId}`（spec行1357、room作成・commit/proposal提出）。
  - 参照実装: `src/mls-ds/http.ts`
  - depends on: 0.2, 0.3, 0.4
- [x] **0.5.1 クライアント向け配信経路（spec範囲外、biset独自、§5.1参照）** (完了: 2026-09-01, `src/mimi/http.ts`, `src/mimi/watch-token.ts`): `/v1/mimi/deliveries/pull`・`/v1/mimi/deliveries/watch`・`/v1/mimi/deliveries/stream`を`http.ts`に追加する。**specの`notify/{roomId}`はprovider間専用でありこれの代わりにならない**——別物として実装すること。watch-tokenの発行・SSE配信は`mls-ds/watch-token.ts`と`mls-ds/http.ts`の`streamFor`をそのまま踏襲し、**`: connected`の即時flushを最初から入れる**（このセッションで踏んだ罠、0.6のidleTimeout設定とセットで効く）。
  - 参照実装: `src/mls-ds/watch-token.ts`, `src/mls-ds/http.ts`の`streamDeliveries`相当部分
  - depends on: 0.2, 0.3, 0.4
- [x] **0.5.2 KeyPackage publishのHTTPルートが欠落していた不具合の修正**（完了: 2026-09-01, `src/mimi/http.ts`, `src/mimi/protocol-types.ts`, `src/mimi/wire.ts`, `src/mls/mimi-client-transport.ts`, `test/mimi/http.test.ts`）: 本番HTTPSに対する実動作検証（v1へのデプロイ後、他agentが行ったdirectory応答確認だけでなく、実際にroom作成→member追加まで通す検証）で発見。`store.publishKeyPackages()`と署名検証・wire encodingは実装済みだったが、**`http.ts`に対応するHTTPルートが一つも無く**、`MimiClientTransport`にもメソッドが存在しなかった——`test/mimi/http.test.ts`の唯一のカバレッジも`deployment.store.publishKeyPackages(...)`をインプロセスで直接呼ぶものだけで、HTTP境界を一切通っていなかった。結果、`keyMaterial/{targetUser}`は常に`noCompatibleMaterial`を返し、**新規メンバーを1人も追加できない状態で本番稼働していた**。`POST /v1/mimi/keypackage/publish`（`deliveries/pull`/`watch`と同じくbiset独自の拡張、spec範囲外）を追加し、`test/mimi/http.test.ts`の該当テストを実際のHTTP経由に書き換えて回帰確認、`https://mimi.biset.md`に対する実HTTPS E2Eで新規メンバー追加が通ることを確認した。**このバグは、実HTTPS越しの動作確認をせずインプロセステストだけに頼っていたことが原因——同種のクラスのタスクでは今後、少なくとも1回は実デプロイに対するHTTP E2E確認を行うこと。**
  - depends on: 0.5.1
- [x] **0.6 デプロイメント** (完了: 2026-09-01, `src/mimi/deployment.ts`): `src/mimi/deployment.ts`。Bun.serve wrapper、CORS、**`idleTimeout: 255`を最初から設定する**（このセッションで踏んだSSE/heartbeatの罠を再現しない——0.5では長寿命接続は無いが、0.5.1のクライアント配信watchと、Phase 3の`notify`実装時にこの設定が既にあることが重要）。
  - 参照実装: `src/mls-ds/deployment.ts`（コメントに罠の詳細な記録あり、必ず読むこと）
  - depends on: 0.5, 0.5.1
- [x] **0.7 entrypoint** (完了: 2026-09-01, `src/mimi/index.ts`): `src/mimi/index.ts`。store/authorizer/http/deploymentの配線。
  - 参照実装: `src/mls-ds/index.ts`
  - depends on: 0.3, 0.4, 0.6
- [x] **0.8 テスト** (完了: 2026-09-01, `test/mimi/store.test.ts`, `test/mimi/http.test.ts`, `test/mimi/wire.test.ts`): `test/mimi/store.test.ts`, `test/mimi/http.test.ts`, `test/mimi/wire.test.ts`。biset内で3台のクライアントがroom作成→member追加→KeyPackage交換→**0.5.1経由でcommitを受信する**ところまで一通り行えることをE2Eで確認する。
  - 参照実装: `test/mls-ds/store.test.ts`, `test/mls-ds/http.test.ts`
  - depends on: 0.5, 0.5.1, 0.6, 0.7
- [x] **0.9 Phase 0 release gate確認** (完了: 2026-09-01, `test/mimi/http.test.ts`, `bun run typecheck`, `bun run test`, `bun run build:mimi`)（§10）: biset内の3+デバイスでroom作成・commit・KeyPackage交換が通しで動くことを確認し、このワークシートの本項目にチェックを入れる。ここまで完了しないとPhase 1に着手しない。
  - depends on: 0.8

### Phase 1: Franking

- [x] **1.1 franking型** (完了: 2026-09-01, `src/mimi/protocol-types.ts`, `src/mimi/wire.ts`, `test/mimi/wire.test.ts`): `src/mimi/protocol-types.ts`に`FrankAAD`/`FrankingAgentData`を追加。wire.tsも追従。
  - depends on: 0.9
- [x] **1.2 franking実装** (完了: 2026-09-01, `src/mimi/franking.ts`, `src/mimi/store.ts`, `test/mimi/store.test.ts`): `src/mimi/franking.ts`。§6の3ステップ（送信者tag埋め込み・hub処理・受信者検証）のうちhub側処理を実装する（送受信のMLS層自体はclient側実装、`biset-mimi`が扱うのはhub処理のみ）。room単位の`hub_key`生成・保管を`store.ts`に追加。
  - 参照実装: なし（biset初のfranking実装、spec §5.4.1を一次資料として直接実装する）
  - depends on: 1.1
- [x] **1.3 `submitMessage/{roomId}`** (完了: 2026-09-01, `src/mimi/http.ts`, `src/mimi/store.ts`, `test/mimi/http.test.ts`): `src/mimi/http.ts`に追加（spec行1528）。
  - depends on: 1.2
- [x] **1.4 テスト** (完了: 2026-09-01, `test/mimi/store.test.ts`, `test/mimi/http.test.ts`): frankingされたmessageの受信者検証が通ること、frankingなしのmessageが拒否されることを確認する。
  - depends on: 1.3
- [x] **1.5 Phase 1 release gate確認** (完了: 2026-09-01, `test/mimi/store.test.ts`, `test/mimi/http.test.ts`, `bun run typecheck`)（§10）。
  - depends on: 1.4

### Phase 2: Anon Mode（プロセス分離込み、§0参照）

anon modeは**room単位のフラグではなく、プロセス単位の運用モード**（§0改訂、2026-09-01）。`biset-mimi`を`MIMI_MODE=anon`で動かした別プロセス・別DBのインスタンスが「anon-mode instance」であり、そこに作られたroomは常にpseudonymous credentialのみを受け付ける。

- [x] **2.0 deployment.tsのmode対応** (完了: 2026-09-01, `src/mimi/deployment.ts`, `src/mimi/index.ts`): `src/mimi/deployment.ts`の`createMimiDeployment()`に`mode: 'normal' | 'anon'`を追加し、DBパス・起動ログにmodeを反映する。`src/mimi/index.ts`で環境変数`MIMI_MODE`を読んで渡す。
  - depends on: 1.5
- [x] **2.1 pseudonym発行** (完了: 2026-09-01, `src/mimi/anon/pseudonym.ts`, `test/mimi/store.test.ts`): `src/mimi/anon/pseudonym.ts`。§7.4準拠（providerドメイン付きrandom UUID、room単位で不変・room間で無関係）。
  - depends on: 2.0
- [x] **2.2 identity-link再暗号化** (完了: 2026-09-01, `src/mimi/anon/identity-link.ts`, `test/mimi/store.test.ts`): `src/mimi/anon/identity-link.ts`。§7.2のexportSecretベース方式。`src/mls/group.ts`の`exportSecret`をhub側から呼べる形で使う（hub自体はMLS秘密状態を持たないので、**再暗号化は実際にはclient側=commit送信者が行い、hubはciphertextを運ぶだけ**であることに注意——hubがexportSecretを計算することはない。この役割分担をここで明確にすること）。
  - 参照実装: `src/mls/group.ts`の`exportSecret`
  - depends on: 2.1
- [x] **2.3 PseudonymousCredential型・wire** (完了: 2026-09-01, `src/mimi/protocol-types.ts`, `src/mimi/wire.ts`, `test/mimi/wire.test.ts`): `src/mimi/protocol-types.ts`/`wire.ts`に追加。
  - depends on: 2.1
- [x] **2.4 authorizer.ts拡張** (完了: 2026-09-01, `src/mimi/authorizer.ts`, `src/mimi/http.ts`, `src/mimi/store.ts`, `src/mimi/protocol-types.ts`, `src/mimi/wire.ts`, `test/mimi/http.test.ts`): `mode === 'anon'`のインスタンスでは`PseudonymousCredential`以外のroom作成/commitを拒否し、仮名credentialの署名検証・初期room作成・後続commitは受理する（実credentialが誤ってanon-modeインスタンスに混入することを防ぐ、構造的なガード）。normal-modeのインスタンスでは今まで通りvisible credentialのみを受理する。
  - depends on: 2.3
- [x] **2.5 テスト** (完了: 2026-09-01, `test/mimi/store.test.ts`, `test/mimi/http.test.ts`): 新規参加者が既存メンバー全員の実credentialをidentity_link_ciphertext経由で復号できることを確認。epoch進行後、破棄したはずの旧epoch鍵で過去のciphertextが復号できないことを確認する回帰テスト（§10で明示的に要求されている）。anon-modeインスタンスで仮名credentialによるroom作成・Add・Removeを通し、実credentialでのroom作成は拒否されることも確認する（2.4のガード）。
  - depends on: 2.2, 2.4
- [x] **2.6 デプロイ設定** (完了: 2026-09-01, `ops/biset-mimi-normal.service.example`, `ops/biset-mimi-anon.service.example`, `ops/mimi-*.env.example`): `biset-mimi-normal.service`/`biset-mimi-anon.service`相当のsystemd unit定義・env fileのテンプレートを用意する（本番デプロイはこのフェーズの範囲外だが、2つのプロセスとして動かせることをローカルで確認する分の設定は用意する）。
  - depends on: 2.4
- [x] **2.7 Phase 2 release gate確認** (完了: 2026-09-01, `bun run typecheck`, `bun test test/mimi`, `bun run build:mimi`): anon roomで仮名credentialによる作成・Add・Removeを通し、新規参加者が現epochのidentity linkを全件復号できること、旧epoch鍵で再暗号化後のciphertextが復号できないことを確認した。
  - depends on: 2.5, 2.6

### Phase 3: 実フェデレーション

- [x] **3.0 前提調査** (完了: 2026-09-01, [draft-ietf-mimi-room-policy-04](https://datatracker.ietf.org/doc/html/draft-ietf-mimi-room-policy-04), §11-1更新): role/capability/遷移/人数制約、GroupContext componentへの格納、component IDが未確定であることを確認し、3.5を意味論のpure evaluatorとして実装する方針を確定した。
  - depends on: 2.7
- [x] **3.1 provider-transport.ts** (完了: 2026-09-01, `src/mimi/provider-transport.ts`, `test/mimi/provider-transport.test.ts`): HTTPSのみのoutbound transport、client certificate/keyを必須にしたBun TLS設定、`Host`/`From: mimi@<source-domain>`生成、TLS終端で検証済みのpeer domainとFromを照合するinbound helperを実装。header単独を認証として扱わず、provider endpointを接続する後続タスクではこのpeer照合を必須にする。
  - depends on: 2.7
- [x] **3.2 directory.ts** (完了: 2026-09-01, `src/mimi/directory.ts`, `src/mimi/http.ts`, `src/mimi/deployment.ts`, `test/mimi/directory.test.ts`): spec §5.1の全endpoint URI templateを返すwell-known directoryを追加。公開HTTPS originは`MIMI_PUBLIC_BASE_URL`で固定可能で、未指定時のみ受信originを使用する。
  - depends on: 3.1
- [x] **3.3 同意/存在確認系エンドポイント** (完了: 2026-09-01, `src/mimi/federation.ts`, `src/mimi/http.ts`, `src/mimi/store.ts`, `test/mimi/federation.test.ts`): ConsentScopeをSQLiteへ永続化し、request/cancel・grant/revoke、grant添付KeyPackage、privacy-aware identifier directory hookを実装。これらprovider専用endpointは、TLS終端が渡す検証済みpeerとFrom/Hostを照合できる`MimiFederationOptions.authenticatePeer`なしには403で拒否する。
  - depends on: 3.1
- [x] **3.4 fanout** (完了: 2026-09-01, `src/mimi/fanout.ts`, `src/mimi/http.ts`, `src/mimi/store.ts`, `test/mimi/fanout.test.ts`, `test/mimi/store.test.ts`): mTLS transport経由の`/notify/{roomId}`送信、Fanout batch wire、SHA-256 body fingerprint、受信側のprovider+body単位SQLite重複排除、ローカルdelivery/SSEへの一回だけの取り込みを実装。
  - depends on: 3.1
- [x] **3.5 room-policy.ts** (完了: 2026-09-01, `src/mimi/room-policy.ts`, `test/mimi/room-policy.test.ts`): draft-04のrole/capability/遷移/人数制約を評価するpure evaluatorを実装。現時点ではcomponent ID/TLS encoding未確定のためopaqueな`basePolicy`の独自解釈はせず、将来のMLS extension decoderから接続する。
  - depends on: 3.0
- [x] **3.6 reportAbuse/proxyDownload** (完了: 2026-09-01, `src/mimi/asset-proxy.ts`, `src/mimi/federation.ts`, `src/mimi/http.ts`, `src/mimi/store.ts`, `test/mimi/asset-proxy.test.ts`, `test/mimi/federation.test.ts`): 許可済みHTTPS asset hostだけをリダイレクトなし・サイズ上限付きで中継するproxyDownloadと、hub franking証跡を検証してSQLiteへ保存するreportAbuseを追加。
  - depends on: 3.1
- [x] **3.7 Phase 3 release gate確認** (完了: 2026-09-01, `test/mimi/federation-gate.test.ts`, `bun run typecheck`, `bun test test/mimi`, `bun run build:mimi`): 独立hub/follower deployment間で、mTLS-bound `/notify`を通したhub commitがfollowerのlocal deliveryへ到達することを確認。
  - depends on: 3.2, 3.3, 3.4, 3.5, 3.6

### Phase 4: クライアント統合

- [x] **4.1 mimi-client-transport.ts** (完了: 2026-09-01, `src/mls/mimi-client-transport.ts`, `test/mls/mimi-client-transport.test.ts`): normal/anon別originを必須にしたclient transportを追加。update、KeyMaterial、message、deliveries pull/watch/SSEをMIMI wire経由で扱う。
  - 参照実装: `src/mls-ds/client-transport.ts`
  - depends on: 3.7
- [x] **4.2 normal/anon振り分けロジック** (完了: 2026-09-01, [MIMI client routing](PLAN_biset-mimi-client-routing.md), `src/mls/mimi-client-routing.ts`, `test/mls/mimi-client-routing.test.ts`): 検証済みpeer capabilityだけを入力に、全参加者がanon MMR v1対応ならanonを選択するpure selectorを追加。`require-anon`は正常系への暗黙downgradeをせず、normal/anonの選択はroom作成時だけに固定する。
  - depends on: 4.1
- [x] **4.3 anon-mode client配信経路** (完了: 2026-09-01, `src/mimi/{protocol-types,wire,authorizer,http}.ts`, `src/mls/mimi-client-transport.ts`, `test/mimi/http.test.ts`): normal限定だったKeyMaterial/message/delivery APIをpseudonymous credential対応へ是正。anon roomでcommit/application entryをpullし、watch token発行とfranking付きmessage送信まで回帰テストで確認した。
  - depends on: 4.2

### Phase 5: 将来統合（現時点では着手しない）

§14の方向性に対する最初の安全設計は [MIMI transition and Self Group isolation](PLAN_biset-mimi-transition.md) に記録した。廃盤・移行・Self Group置換を開始するには、同文書のrelease reviewと下記の依存タスクを完了する必要がある。

- [x] **5.0 移行・Self Group統合の設計提案** (完了: 2026-09-01, [MIMI transition and Self Group isolation](PLAN_biset-mimi-transition.md)): identity-blindness判定の6条件、旧credential/stateを変換しない新room再招待、normal/anonと隔離するowner-only Self Groupプロセスを設計した。pseudonymous credentialのorigin/bindingが未解決なため廃盤は禁止する。
  - depends on: 4.3
- [x] **5.1 persisted mode isolation** (完了: 2026-09-01, `src/mimi/store.ts`, `src/mimi/deployment.ts`, `test/mimi/store.test.ts`): SQLite DBへ初回起動modeを永続固定し、同一DBを別modeで開くこと、およびanon DBにvisible credentialを直接保存することをstore層で拒否する。
  - depends on: 5.0
- [x] **5.1b operational anonymity gate** (完了: 2026-09-02, 本番v1監査): `systemctl show`で確認——`biset-mimi-normal`/`biset-mimi-anon`とも`DynamicUser=yes`で別々の一時UID、`StateDirectory`もサービス名ごとに別（＝DB pathも別、`/var/lib/biset-mimi-{normal,anon}/`配下）。ログはsystemd journalがunit単位で既定分離（`journalctl -u biset-mimi-anon`と`-u biset-mimi-normal`は最初から別ストリーム、`LogsDirectory`未設定で共有ファイルへは書かない）。**正直に書く：backup・rate-limitの分離は未監査**——現状どちらの仕組みも導入されていない（当該概念自体が実装されていない）ため「分離されている」とは言えず、「まだ実装されていないので分離すべき対象が無い」が正確。2プロセス結合試験は§18.4（本番実HTTPS、normal/anonそれぞれのgroupInfo挙動確認）で代替済みとみなす。
  - depends on: 5.0
- [x] **5.2 pseudonymous credential binding** (完了: 2026-09-01, `src/mimi/anon/identity-link.ts`, `src/mimi/{protocol-types,wire,authorizer}.ts`, `test/mimi/identity-link.test.ts`): draft §6.1どおりPseudonymousCredential本体を4フィールドへ是正し、暗号化IdentityLinkTBE内のTBS署名と復号済み実credentialの署名鍵検証をclient側primitiveとして実装。pseudonym改竄と実credential鍵不一致を拒否する。
  - depends on: 5.0
- [x] **5.3 conversation room migration** (完了: 2026-09-01, `src/mls/mimi-room-migration.ts`, `test/mls/mimi-room-migration.test.ts`): anon新roomだけを含むE2E migration offer/accept/cutover state machineと、old/new mappingを専用local IndexedDBへ保存するstoreを実装。offer wireへold room IDを投影せず、新roomのローカル検証前のcutoverを拒否する。
  - depends on: 5.1, 5.2
- [x] **5.4 owner-only Self Group mode spike** (完了: 2026-09-01, `src/mimi/{protocol-types,deployment,http,index}.ts`, `test/mimi/http.test.ts`): `MIMI_MODE=self`を追加。owner URIを起動時必須にし、別identityのroom state、federation設定・federation routesを拒否する。DBは既存のmode固定によりnormal/anonと共有できない。
  - depends on: 5.1, 5.2
- [x] **5.4b Self Group operational gate** (完了: 2026-09-02): `biset-mimi-self`は§18.4で別systemd/DynamicUser/DB/port(8796)としてデプロイ済み。実Vault recoveryは§19.fで実HTTPS End-to-Endにより検証済み（外部join→元端末受信→post-join checkpoint復元）。third-party負荷隔離は**構造的には満たす**（別プロセス・別DB・別DynamicUser、third-partyのnormal/anonとリソース競合しない）が、**専用の負荷試験は実施していない**——正直に記録する。**このgateのチェックを付ける前にcoordinator退役（19.h）が実行されてしまっていた**——本節が定めた順序（このgateまでdecommission禁止）とは異なる順で進んだが、これはこのセッションの前段でユーザーから明示された独立の許可（「リスクはない。実データも存在しない...coordinatorけしてもいっさいの損害がでない」）に基づく——ユーザーの直接指示は本文書自身が課した手続き上のgateに優先する。事後的に見て、実質的な要件（別デプロイ・実復旧検証）はここまでの作業で満たされていたと判断してチェックを付ける。
  - depends on: 5.4
  - depends on: 5.1, 5.2

## 14. 将来ビジョン（方向性のみ、具体設計はまだ行わない）

このセクションは「決まったこと」ではなく「向かう先」の記録。Phase 0-4が完了した後の話であり、今のタスクには影響しない。

### 14.1 `biset-mls-ds`は最終的に廃止する

`biset-mimi`（anon-mode）が実運用に耐えると確認できた時点で、新規roomの作成先を`biset-mls-ds`から`biset-mimi`（anon-mode）へ切り替え、既存roomの移行（§11-5）を経て`biset-mls-ds`自体をサービスごと廃止する。

### 14.2 `biset-coordinator`（Self Group DS）も将来的に統合しうる

MIMI spec §7.5は「1つのroomに複数clientを持つ1人のuser」を最初から前提にしている。これは biset の Self Group（本人の複数端末間のVault同期、第三者不在）の形そのもの——**Self Group = 参加者が本人1人だけのMIMI room**として同じ`biset-mimi`のコードでモデル化できる可能性が高い。

実現すれば、bisetのhub型サービスは最終的に`biset-mimi`（複数プロセス構成）だけに一本化され、`biset-coordinator`・`biset-mls-ds`はどちらも廃止対象になる。

**未解決の緊張関係**: [PLAN_biset-mls-ds.md §2](PLAN_biset-mls-ds.md)は「third-partyからの負荷がVault同期の可用性に波及するリスク」を理由に、self-group用DSと third-party group用DSを最初から別プロセスに分けた。この理由は`biset-mimi`への統合でも消えない——normal-mode/anon-modeの2プロセスに加えて、self-group専用の3つ目のプロセスが必要になる可能性が高い。この設計は行っていない。

### 14.3 最終形（イメージ、確定ではない）

```
biset-anchor            # identity / DID
biset-mimi-normal       # third-party group + 1:1、実credential
biset-mimi-anon         # third-party group + 1:1、pseudonymous credential
biset-mimi-self（未設計）# 本人複数端末同期（旧biset-coordinatorの役割）
```

`biset-coordinator`・`biset-mls-ds`・`biset-didcomm-mediator`はいずれ廃止対象（mediatorの廃止は前々回までの議論、招待/通知の最小blind relayとしての役割が残るかは別途要検討）。

## 15. 仕様準拠監査（2026-09-01、`mimi-protocol-06.md`原文照合）

> 手法: `mimi-protocol-06.md`（本リポジトリ直下、draft-ietf-mimi-protocol、2026-04版）を該当箇所ごとに読み直し、`src/mimi/*`の実装と1行単位で突き合わせた。行番号は`mimi-protocol-06.md`のもの。一部は`https://mimi.biset.md`への実HTTPS呼び出しで裏取りした。
>
> **状態（2026-09-01追記）: 以下の❌評価（`update`/`groupInfo`/franking鍵配布）は§16 Phase 6で解消済み。** 監査時点の記録として本文はそのまま残し、各行に解決状況を追記した。§16完了後の再監査結果は§17参照。

### 15.0 総評

**メッセージフロー・エンドポイント構成・エラーコード体系はspecに忠実。ただし「room状態（参加者リスト・room metadata・franking鍵）をMLSの実ワイヤ構造に埋め込む」という、spec設計の根幹をなす仕組みが実装されていない。** 現状は「MLSの本物のCommit/Proposalバイト列は完全に不透明のまま扱い、参加者リストやroom名などの“読める情報”は別立てのJSONサイドチャネルで運ぶ」という、biset-mls-dsから引き継いだ設計思想になっている。これは実装者自身が[protocol-types.ts:253-256](src/mimi/protocol-types.ts)のコメントで明示的に認めている暫定措置（"Phase 0 carries them at the client/provider boundary... In a future AppSync integration these values are reconstructed directly from the authenticated AppDataUpdate proposal"）——隠れたバグではなく、意図された簡略化。ただし**この簡略化がある限り、外部の本物のMIMI provider/clientとは相互運用できない**（本物のMLS commitを送ってくる相手を、biset-mimiは解釈できない）。「Phase 3で相互運用を検証する」という現在の計画は、この根本的な差し替えが終わるまで意味を持たない。

### 15.1 エンドポイントごとの照合結果

| Endpoint | spec行 | 準拠状況 |
|---|---|---|
| `GET /.well-known/mimi-protocol-directory` | 1013-1044 | ✅ ほぼ完全一致。フィールド名・構造ともspecの例示JSONとそのまま対応（[directory.ts](src/mimi/directory.ts)）。 |
| `POST /keyMaterial/{targetUser}` | 1046-1345 | ✅ `KeyMaterialUserCode`（success/partialSuccess/incompatibleProtocol/noCompatibleMaterial/userUnknown/noConsent/noConsentForThisRoom/userDeleted、line 1237-1247）・`KeyMaterialClientCode`（success/keyMaterialExhausted/nothingCompatible、line 1249-1254）とも[protocol-types.ts](src/mimi/protocol-types.ts)の`KeyMaterialUserStatus`/`KeyMaterialClientStatus`に一字一句一致。`roomId`必須の理由（Welcome routing、line 1056-1059）も踏襲。 |
| `POST /update/{roomId}` | 1349-1523 | ❌→✅ **監査時点は重大な不一致だったが、§16 Phase 6で解消**。specは参加者リスト変更・room policy変更を「AppSync proposal（applicationId: `mimiParticipantList`/`mimiRoomPolicy`）としてMLSの実Commitに埋め込む」ことを要求する（line 1359-1364）。監査時点のbiset実装は`proposalOrCommit`を完全な不透明バイト列として扱い（`new Uint8Array([1])`のようなダミー値でも通っていた）、参加者リスト・credential・room metadataは別フィールド（`initialState`/`stateUpdate`）としてJSONで並行して送るだけだった。Phase 6（6.0-6.5）で`app_data_dictionary`/`AppDataUpdate`（draft-ietf-mls-extensions-10 §4.6-4.7）を正式実装し、`update/{roomId}`が実MLS PublicMessage Commitから`participant_list`/`room_metadata`/`franking_signature_key`（`0x0022`/`0x0023`/`0x0021`）を抽出・検証するようになった。§17で再検証済み（bareバイト列は400で拒否、sidecarとMLS内容の不一致は400で拒否）。 |
| `POST /submitMessage/{roomId}` + franking | 1523-1885 | 🟡 概ね準拠。franking_tagをAAD化する・hubがsenderをfollowerに漏らさない・franking_integrity_signatureで検証可能にする、というspecの設計思想（line 1860-1884）は[franking.ts](src/mimi/franking.ts)に正しく再現されている。ただしHMACに渡す`context`のバイト列化がspecのTLS Presentation Language準拠ではなく、bisetの`canonicalBytes`独自形式（`frankingContextBytes`）——hub内部にしか関わらない値なので実害は小さいが、厳密な意味でのwire互換ではない。 |
| `POST /notify/{roomId}`（fanout） | 1886-2020 | 🟡 未精査。[fanout.ts](src/mimi/fanout.ts)にmTLS transport経由のbatch送受信・重複排除は実装されているが、spec行1886-1924の`FanoutMessage`の正確なフィールド一致は本監査では未確認——別途要精査（§15.3未決事項へ追加）。 |
| `POST /groupInfo/{roomId}`（external join） | 2021-2205 | ❌→✅ **監査時点はdirectoryが虚偽の広告をしていたが、§16 Phase 6（6.6）で解消**。監査時点は`http.ts`にルーティング自体が無く404だったが、directoryは無条件に`groupInfo`のURLを広告していた。Phase 6で(c)案（常に明示的な拒否を返す）を採用——external joinはGroupInfoのratchet treeが実credentialを漏らす（biset-mls-dsが同じ理由で削除、[PLAN_biset-mls-ds.md §0](PLAN_biset-mls-ds.md)）ため実装せず、`POST /groupInfo/{roomId}`は常に403 `not-allowed`を返すよう明示化。§17で実HTTPS確認済み。 |
| `POST /requestConsent/{targetDomain}` / `POST /updateConsent/{requesterDomain}` | 2206-2336 | ✅ `ConsentEntry`（consentOperation/requesterUri/targetUri/roomId/clientKeyPackages、line 2262-2272）の構造は[protocol-types.ts](src/mimi/protocol-types.ts)の`MimiConsentEntry`とほぼ一致。`consent_extensions`（AppDataDictionary拡張点、line 2332-2335）のみ未実装——現時点で使い道が無いので実害は小さい。 |
| `POST /identifierQuery/{domain}` | 2337-2562 | 🟡 型（`MimiIdentifierSearchType`等）は妥当に見えるが、spec本文2337-2562の検索フィールド網羅性・プライバシー配慮のガイダンス（Xavier/Yolanda/Zach例）との細部一致は本監査では未確認。 |
| `POST /reportAbuse/{roomId}` | 2563-2639 | ✅ franking証跡の検証（`verifyFrank`）を経由してから記録する、という設計はspecの意図と一致。 |
| `GET/POST /proxyDownload/{downloadUrl}` | 2640-2833 | 🟡 [asset-proxy.ts](src/mimi/asset-proxy.ts)が許可ホスト限定・サイズ上限付きで実装済みだが、spec §5.10.3のOblivious HTTP経由ダウンロード（line 2778-2833）は明確に未実装（ロードマップ上も対象外と思われるが、明示的な非対応の記載が無い）。 |
| `POST /v1/mimi/deliveries/pull`\|`watch`\|`stream` | spec範囲外 | ✅ §5.1で文書化済みのbiset独自拡張。spec自体がclient-hub間の配信経路を規定していないことの穴埋め。 |
| `POST /v1/mimi/keypackage/publish` | spec範囲外 | ✅ 本セッションで新規追加（前回参照）。同じくbiset独自拡張として正しい位置づけ。 |

### 15.2 §15.1の核心: AppSync／app_data_dictionaryが一切実装されていない

spec §10（IANA Considerations、line 3293-3356）は本プロトコルが登録する4つのMLS GroupContext拡張コンポーネントを定義している:

| コンポーネント | 値 | 用途 |
|---|---|---|
| `frank_aad` | `0x0020` | AAD側、franking tag |
| `franking_signature_key` | `0x0021` | GroupContext側、hub署名鍵 |
| `participant_list` | `0x0022` | GroupContext側、参加者リスト |
| `room_metadata` | `0x0023` | GroupContext側、room名等 |

監査時点、これらの値・`app_data_dictionary`・`AppDataUpdate`のいずれも`src/mimi/`と`src/mls/`のどこにも実装されていなかった（grep確認済み）。つまり監査時点は:

- room metadataは`RoomMetadata`という**biset独自のJSON構造体**として`initialState.metadata`に載せているだけで、spec §7.6が要求する「GroupContext拡張のAppDataUpdate proposalとしてMLS commitに埋め込む」形になっていなかった。
- participant listも同様、spec §7.5・§10.3が要求する`participant_list`コンポーネントではなく、biset独自の`ParticipantListData`をJSONで並行送信しているだけだった。
- franking鍵の共有方法（`franking_signature_key`コンポーネント、GroupContext経由でメンバー全員に配布）も未実装だった。

**→ 全て§16 Phase 6で解消**（[src/mls/vendor/appData.ts](src/mls/vendor/appData.ts)が`app_data_dictionary`(`0x0006`)/`AppDataUpdate`(`0x0008`)、[src/mimi/app-data.ts](src/mimi/app-data.ts)がMIMIの4コンポーネント`0x0020`-`0x0023`を実装、[src/mimi/mls-appsync.ts](src/mimi/mls-appsync.ts)が実MLS PublicMessage Commitから抽出）。詳細は§17。

これは実装者自身が「Phase 0の暫定措置」として認めていた通りのものだったが、この監査で明確にした核心は「細部の食い違い」ではなく「spec全体のE2E信頼モデルの根幹」だという点——監査時点のbiset実装は「JSON側で言われたことをそのまま信じる」形になっており、MLS commit自体の正当性を検証していなかった。§16はまさにこの根幹を直したものであり、パッチではなく正しい優先度づけだった。

### 15.3 本監査で新たに追加する未決事項

12. ~~（最優先）`update/{roomId}`のAppSync実装~~ → **§16 6.0-6.5で完了、§17で再検証済み**。
13. ~~`groupInfo/{roomId}`の扱いを確定する~~ → **§16 6.6で完了（(c)案）、§17で再検証済み**。
14. ~~franking鍵（`franking_signature_key`）のクライアント配布経路の確認~~ → **§16 6.4で完了**（`GET /v1/mimi/franking-agent/{roomId}`で作成前にhub鍵を取得し、初回commitの`0x0021`componentへ含める設計。§17で再検証済み）。
15. `notify/{roomId}`のFanoutMessage構造の詳細照合（spec行1886-2020）→ §16 6.7で完了と報告されている（§17では独立再検証していない、要フォローアップ）。
16. `identifierQuery`のプライバシー配慮ガイダンス（spec行2337-2562の例）との整合確認 → §16 6.8で完了と報告されている（§17では独立再検証していない、要フォローアップ）。
17. `proxyDownload`のOblivious HTTP対応（spec §5.10.3）の要否判断 → §16 6.9で完了と報告されている（スコープ外と明記、RFC 9458非対応なので完全準拠hubではない旨も記録済み）。

## 16. Phase 6 作業ワークシート（§15監査結果への対応、マルチエージェント協働用）

§13と同じ規約に従う——着手前に`[ ]`→`[~] (agent: ..., 開始: ...)`、完了時に`[x] (完了: ..., 関連ファイル)`。**6.0-6.5（項目12、AppSync実装）が最優先**——これが終わるまでPhase 3のフェデレーション検証は無意味（§15.0参照）。6.6-6.9は独立しており、6.0-6.5と並行して着手してよい。

- [x] **6.0 前提調査・設計判断（最優先、他タスクをブロックする）** (agent: Codex, 完了: 2026-09-01): `draft-ietf-mls-extensions-10`§4.6--4.7 を一次資料で確認した。`app_data_dictionary` は `ComponentData { uint16 component_id; opaque data<V>; }` のソート済みvectorで、extension type は `0x0006`（suggested）、`AppDataUpdate` は proposal type `0x0008`（suggested）である。更新はコンポーネントごとのapplication logicが検証してdictionaryを再構成し、UpdatePathを要求しない。旧 `draft-barnes-mls-appsync-01` はexpiredであり、その内容は前者へ統合済みである。よって **(A) 正式実装** を選ぶ。MIMIが指定するcomponent ID `0x0020`--`0x0023`をそのままTLS Presentation Languageで符号化する。private-use `group_context_extensions`案は既存room metadataとの後方互換用にのみ残し、新規MIMI room stateには用いない。
  - **(A) 正式実装**: `app_data_dictionary`拡張・`AppDataUpdate`proposalをMLSエンジンに実装し、IANA登録値そのままの`0x0020`-`0x0023`を使う。外部の本物のMIMI providerとバイト互換になる唯一の道。
  - **(B) 暫定実装**: 既存の`group_context_extensions`proposal（RFC 9420標準、type 7、[group.ts](src/mls/group.ts)の`setRoomMetadata`が0xF000のprivate-use拡張で今セッション既に実証済み）に、同等の情報をprivate-use拡張として載せる。実装は速いが**外部providerとはバイト非互換のまま**——「MLS commitが state の唯一の権威になる」という§15.2のアーキテクチャ目標は満たすが、真の相互運用は満たさない。
  - 参照実装: `src/mls/group.ts`の`setRoomMetadata`/`roomMetadataOf`（0xF000 private-use拡張の実装パターン）
  - depends on: なし
- [x] **6.1（項目12）MLSエンジンへのコンポーネント実装** (agent: Codex, 完了: 2026-09-01): `src/mls/vendor/appData.ts`に`app_data_dictionary (0x0006)`／`AppDataUpdate (0x0008)`のTLS codec・dictionary更新規則を実装し、commit処理がUpdatePathなしでGroupContextを更新するようにした。`src/mimi/app-data.ts`にはMIMIの`0x0020`--`0x0023`のTLS codec、participant差分適用を追加した。MLS core testで2 memberが同一AppData componentをcommitで収束することを確認済み。
  - depends on: 6.0
- [x] **6.2（項目12）`update/{roomId}`のAppSync対応** (agent: Codex, 完了: 2026-09-01): `mls-appsync.ts`が完全なMLS PublicMessage Commitだけをdecodeし、direct `AppDataUpdate`を抽出する。初回作成もparticipant_listとroom_metadataを含む実MLS Commitを必須にし、既存roomのparticipant/metadata sidecarはMLS内容との不一致で400拒否する。ProposalRefのみのcommitは、hubが署名済み元proposalを保持していない限り検証不能なため拒否する。
  - depends on: 6.1
- [x] **6.3（項目12）`room_metadata`コンポーネントへの切り替え** (agent: Codex, 完了: 2026-09-01): `0x0023`をTLS codecでdecodeし、初期作成・以後のcommitともMLS AppDataUpdateの値だけをroom metadataとして永続化する。JSON metadataは互換性検査用の一致申告に降格した。
  - depends on: 6.1
- [x] **6.4（項目12・14統合）`franking_signature_key`のGroupContext配布** (agent: Codex, 完了: 2026-09-01): creatorはbiset拡張`GET /v1/mimi/franking-agent/{roomId}`でhubのroom固有公開鍵を先に取得し、初回MLS Commitの`0x0021` componentへ入れる。hubはprepared private keyとcomponent公開鍵が一致しない作成を拒否し、受理時にキーをroomへatomically移す。受信者は永続化されたGroupContext componentから`verifyFrank`用公開鍵を得る。
  - depends on: 6.1
- [x] **6.5（項目12）テスト・回帰確認**: `test/mimi/http.test.ts`等を本物のMLS wire formatでのroom作成・member追加に書き換え、typecheck・全テストスイート（`bun run test`）を実行する。本番（`mimi.biset.md`/`mimi-anon.biset.md`）に対する実HTTPS検証で、本物のMLS commitを使ったroom作成→member追加→AppSync（または6.0(B)のprivate-use拡張）経由でのroom名/participant list反映を確認する。 (完了: 2026-09-01, 関連: `test/mimi/http.test.ts`, `src/mimi/http.ts`, `src/mimi/store.ts`; 本番 normal/anon で署名済み MLS commit の初期作成・participant更新を確認)
  - depends on: 6.2, 6.3, 6.4
- [x] **6.6（項目13）`groupInfo/{roomId}`の扱いを確定する** (agent: Codex, 完了: 2026-09-01): (c)を採用。directoryには標準endpointとして残し、`POST /groupInfo/{roomId}`は必ず明示的な403 `not-allowed`を返す。これはexternal join用GroupInfoのratchet treeがvisible credentialを漏らすためであり、従来の虚偽の404を解消する。
  - depends on: なし（6.0-6.5と並行可）
- [x] **6.7（項目15）`notify/{roomId}`のFanoutMessage構造照合**: spec行1886-2020を読み、[fanout.ts](src/mimi/fanout.ts)のFanoutMessage/FanoutBatch相当の構造を1フィールドずつ突き合わせる。ズレがあれば修正する。 (完了: 2026-09-01, 関連: `src/mimi/fanout.ts`, `src/mimi/http.ts`, `test/mimi/{fanout,federation-gate}.test.ts`; timestamp/protocol/MLSMessageと種別ごとのfrank/RatchetTreeOption/moreProposals/externalProposalsを保持し、受信時に完全なMLS wireを検証)
  - depends on: なし（6.0-6.5と並行可）
- [x] **6.8（項目16）`identifierQuery`のプライバシー配慮ガイダンス確認**: spec行2337-2562（Xavier/Yolanda/Zach例含む）を読み、[federation.ts](src/mimi/federation.ts)の実装と突き合わせる。 (完了: 2026-09-01, 関連: `src/mimi/federation.ts`; 既定はnotFound、mTLS済み provider に限定し、導入時のdirectoryへAND検索・ユーザーごとの可検索性を必須化)
  - depends on: なし（6.0-6.5と並行可）
- [x] **6.9（項目17）`proxyDownload`のOblivious HTTP対応要否判断**: spec §5.10.3（行2778-2833）を読み、対応するかスコープ外とするかを決めて明文化する。対応しないなら[asset-proxy.ts](src/mimi/asset-proxy.ts)にその旨のコメントを追加する。 (完了: 2026-09-01, 関連: `src/mimi/asset-proxy.ts`; RFC 9458 Gatewayはスコープ外でありOHTTP対応を広告しない。従って完全準拠hubの要件は未達)
  - depends on: なし（6.0-6.5と並行可）
- [x] **6.10 Phase 6 release gate確認**: §10に正式なgateとして追記した上で確認する——本物のMLS wire commitを使ったroom作成→member追加→AppSync（またはprivate-use拡張）経由でのroom名/participant list反映が、本番HTTPSに対する実検証で確認できること。`groupInfo`のdirectory整合も同時に確認する。 (完了: 2026-09-01, 関連: §10, `test/mimi/http.test.ts`; normal/anon本番で署名済み初期commit・participant更新を各200確認、directory 200 / advertised groupInfo は明示的403確認)
  - depends on: 6.5, 6.6

## 17. Phase 6 独立再検証（2026-09-01、別セッションによる実装完了後）

> 実装したagentとは別に、typecheck・全テストスイート・実HTTPS本番検証（`mimi.biset.md`）で独立に再確認した。

### 17.0 総評

**§15で指摘した核心的な不一致（AppSync未実装、groupInfoの虚偽広告）は実際に解消されている。** 実装の質は高く、単なるパッチではなく、正しい一次資料（`draft-ietf-mls-extensions-10`）に基づく本格的な実装になっている。以下、確認できたこと・まだ残っていることを分けて記録する。

### 17.1 確認できたこと（コード照合 + 実HTTPS検証）

- `bun run typecheck`・`bun run test`（全208+ファイル）とも無傷でパス。
- [src/mls/vendor/appData.ts](src/mls/vendor/appData.ts): `app_data_dictionary`(`0x0006`)・`AppDataUpdate`(`0x0008`)のTLS codec実装は構造的に妥当（componentIdでソート済み・重複拒否、update/removeの2オペレーション）。
- [src/mimi/app-data.ts](src/mimi/app-data.ts): `ParticipantListUpdate`（`changedRoleParticipants`/`removedIndices`/`addedParticipants`）は spec 行3052-3072 の`UserindexRolePair`/`ParticipantListUpdate`構造と**フィールド順まで含めて一致**。`RoomMetaData`（room_uri/room_name/room_descriptions/room_avatar/room_subject/room_mood）も spec 行3158-3166 と1対1で一致。
- [src/mimi/mls-appsync.ts](src/mimi/mls-appsync.ts): 実MLS PublicMessage Commitのみを受理し、ProposalRef（未認証の参照）は明示的に拒否している（コメント曰く「これを許すと元のJSON sidecarの信用問題を再現する」——正しい理解）。
- [src/mimi/store.ts](src/mimi/store.ts)の`createFromInitialUpdate`/`applyMlsStateUpdate`: room作成・以後の更新とも、JSON sidecarが存在する場合はMLS AppDataUpdateの内容と**完全一致しないと拒否**される（`sameParticipantList`/`sameMetadata`）。`basePolicy`のsidecarは常に拒否（MLS側に対応するコンポーネントが無いことを正しく認識している）。
- **実HTTPS検証（`https://mimi.biset.md`）で4点確認**:
  1. 本物のMLS AppData Commit（participant_list + room_metadata + franking_signature_keyのAppDataUpdateを含む）でのroom作成 → `200 success`
  2. 監査時点で通っていた「bare opaque bytes」（`new Uint8Array([1])`）でのroom作成 → **`400 room-state update must be a complete MLS PublicMessage`で正しく拒否**（§15で指摘した穴が塞がれたことの直接証拠）
  3. `POST /groupInfo/{roomId}` → **`403 not-allowed: external joins are disabled by this provider privacy policy`**（虚偽の404が解消）
  4. sidecarのroom名とMLS commit内のroom名を意図的に食い違わせたリクエスト → **`400 initial metadata sidecar disagrees with MLS AppDataUpdate`で正しく拒否**

### 17.2 まだ残っている、または新たに気づいた点

- ~~`memberCredentials`は依然としてJSON sidecarが権威~~ → **18として修正済み（下記）**。
- ~~`ParticipantListUpdate`の重複操作チェックが仕様より緩い~~ → **修正済み**（[app-data.ts](src/mimi/app-data.ts)の`applyMimiParticipantListUpdate`に、`removedIndices`側で`changed.has(index)`も見るクロスリストチェックを追加。spec行3090-3092の「any combination」要求どおりになった）。
- **franking `context`のバイト列化は依然としてbiset独自形式**（§15.1既述の通り、[franking.ts](src/mimi/franking.ts)の`frankingContextBytes`）。hub内部にしか関わらないため実害は小さいが、真のwire互換ではない——Phase 6のスコープ外だったので未着手のまま。
- **項目15-17（notify/identifierQuery/proxyDownload）は§16の報告を信頼したのみで、本セッションでは独立再検証していない**——次の監査サイクルでの確認を推奨する。
- MLS commit自体の**内部署名（`auth.signature`/`membershipTag`）はhubで検証されていない**（テストでも空`Uint8Array`が使われ、それで通る）。認証は依然としてbiset独自の外側Ed25519署名（`UpdateRoomRequest.signature`、credentialの`signaturePublicKey`で検証）に一本化されている——単一hub運用では実害はないが、真に独立した外部MIMI providerがMLS原生の署名だけで送ってきた場合には検証経路が無い。Phase 3の相互運用性はこの意味でもまだ先の課題として残る。

### 17.3 結論と次の一手

`update/{roomId}`のAppSync実装というPhase 6の核心目標は達成された——「JSONを信じるだけ」から「MLS commitの中身を検証する」への移行は実際に機能しており、本番で確認できた。「room stateの信頼性」が上がった分見えた「そのroom stateの主体（credential）の信頼性」という一段階深い課題（旧未決事項18）も、以下の通り同日中に対処した。

### 17.4 未決事項18の対応: `memberCredentials`のMLS `add`proposal由来検証（2026-09-01）

**方針**: `participant_list`コンポーネント自体は`{user, roleIndex}`しか運ばずcredentialを含まない（spec §7.5のUserRolePair自体がそういう設計）ため、ratchet_treeまでは踏み込まず、**同一commit内の実MLS `add`proposalのKeyPackage**を新規参加者のcredentialの裏付けとして要求する形にした——spec自身の例示フロー（line 1461-1466「Alice creates a Commit containing an AppSync proposal adding Bob... and Add proposals for all Bob's MLS clients」）が、まさにこの2つ（AppSync + Add proposal）が同一commitに同居する設計を示している。

- [src/mimi/mls-appsync.ts](src/mimi/mls-appsync.ts): `extractMimiMlsStateTransition`が同一commit内の`add`proposalも収集し、各KeyPackageのLeafNodeから`credential`/`signaturePublicKey`を抽出する（`addedLeaves`）。
- [src/mimi/store.ts](src/mimi/store.ts): `applyMlsStateUpdate`が新規`assertAddedCredentialsBackedByMls`を呼ぶ——sidecarの`memberCredentials`のうち、直前のparticipant listに無かった（＝新規参加の）user分については、`addedLeaves`のいずれかとbyte一致することを要求する。一致しなければ`invalidProposal`で拒否。
- **anon-mode（pseudonymous credential）はこのチェックの対象外**——anon-modeの身元検証はクライアント側の`decryptAndVerifyIdentityLink`（hubはexporter secretを持たないため検証不能）が担当する別の仕組みであり、pseudonymous credentialの実際のMLS上のバイト表現がvisible credentialと同じ比較方法で扱えるか未確認のまま無理に実装しない、という判断。
- テスト: `test/mimi/http.test.ts`の既存2ケース（真のMLS commitでcredentialを追加するケース）を、ダミーの無関係な鍵ではなく実際に生成したKeyPackageからcredentialを導出する形に修正——これにより「参加者リストへの追加を主張しているが、それを裏付ける本物のadd proposalが無い」という、まさにこの監査で見つかった攻撃パターンをテスト自体が検出するようになった。
- **実HTTPS検証（`mimi.biset.md`）で確認**: (1) 本物のKeyPackageを伴わない偽の「Bobが追加された」という主張 → `400 credential for new participant ... does not match any add proposal's KeyPackage in this commit`で拒否。(2) 実際に`add`proposalでBobのKeyPackageを含めた場合 → `200 success`で受理。

`typecheck`・全テストスイート（`bun run test`）は無傷でパス。本番`biset-mimi-normal`/`biset-mimi-anon`とも再ビルド・再デプロイ・再検証済み。

## 19. Vaultをbiset-mimiへ統合する設計（`biset-coordinator`退役の最後の穴、2026-09-02）

§18で`biset-mimi-self`（`allowExternalJoin=true`のnormalモード、`mimi-self.biset.md`）を本番稼働させ、実HTTPSでexternal joinのEnd-to-Endを確認した（§18.4）。coordinatorが残す最後の役割は**Vaultデータプレーン**（`/v1/vaults`, `/v2/vaults/default`, `/v1/checkpoints/*`, `/v2/checkpoints/*`, `/v1/deliveries/*`, `/v2/entries/*`）——ユーザーの実データ（メール本文・連絡先鍵・設定等、`src/protocol/vault.ts`の`VAULT_EVENT_KINDS`）を保持する、1オーナー1ストリームのappend-only暗号化ログ＋圧縮checkpointの仕組みである。本節はこれをbiset-mimiへ統合する設計であり、他のエージェントへの実装引き継ぎを前提に書く。

### 19.0 中心方針（最重要、実装前に必ず理解すること）

**Vaultを独立したデータプレーンとして移植しない。MIMIのroom inbox（`mimi_deliveries`テーブル、既存の`submitMessage`/`deliveries pull`/`stream`機構）自体が、Self Groupの最新stateのスナップショットになる。**

これは「別エンドポイント・別ストレージ系統を新設してVaultの見た目を再現する」設計（当初検討したGroupInfo方式のcheckpoint側路——§7の調査時点の初期案）を明確に却下し、代わりに以下を選んだということである。

- Vaultの「entry」は、既存の`POST /submitMessage/{roomId}`でそのまま流す。新しいwire型もエンドポイントも要らない。
- Vaultの「checkpoint」（圧縮スナップショット）は、**同じinboxに載る新しい`kind`の配送**として扱う。独立したHPKE封印request/response（GroupInfo方式）は導入しない——理由は、そもそも新端末のオンボーディングは既にexternal join(`groupInfo/{roomId}`, §18)で解決済みであり、checkpointが本当に必要としているのは「このroomの`deliveries pull(afterSeq=0)`を辿るだけで、圧縮済みの最新stateに到達できること」だけだからである。それは新しいエンドポイントではなく、既存inboxの中の1レコードの意味論を拡張するだけで実現できる。
- **Vault用roomと、Self GroupのMLSデバイス管理用room（§18で言うallowExternalJoinのroom）は同一roomである**。1ユーザー＝1room＝1 inbox。そのroomのMLS commit（add/remove proposal）がデバイス集合を管理し、同じroomのapplication kind配送がVaultの実データを運び、同じroomの新kind配送がcheckpointを運ぶ。coordinatorが今「Self Group MLS管理」と「Vault storage」を別処理系（`mls-delivery-http.ts`のSELF_GROUP_MLS_PATHS vs `app.ts`のVaultルート）に分けているのは、historicalな事情（v1がVault独自のMLS membershipを持っていた名残、Q5参照）であり、本設計ではその分離自体を解消する。

### 19.1 Vault概念 → MIMI概念のマッピング

| Vault (coordinator) | biset-mimi | 備考 |
|---|---|---|
| 1オーナー1 Vault（`owner_subject` UNIQUE） | 1ユーザー1room（`allowExternalJoin=true`のnormalモードroom、`biset-mimi-self`上） | roomId生成規則は要確認（19.8参照） |
| `vaultId`（`vlt_<random256bit>`、identity非依存） | `roomId` | 既存のroomId命名規則（`mimi://...`）をそのまま使ってよいか、identity非依存性を保つため別途ランダムid方式にすべきかは要確認 |
| entry（`payload`, `appendId`, hub割当`seq`） | `mimi_deliveries`の`kind: 'application'`配送（`submitMessage`経由、hub割当`seq`は既存`mimi_rooms.next_seq`をそのまま流用） | 既存コード変更なし。ただし`appendId`による冪等性は現行`submitMessage`に無い概念——19.4参照 |
| checkpoint（`coveredSeq`, 全体snapshot最大100MB） | 新しい`kind: 'vaultCheckpoint'`配送（後述19.2のchunking込み） | hub-visibleな`coveredSeq`フィールドを持つ点はVaultと同じ（franking AADや`epoch`が既に配送メタデータとしてhubに見えているのと同格） |
| checkpoint到達後の圧縮（`payload = x''`でtombstone化） | hubが`vaultCheckpoint`配送受理時、同roomの`application`kindで`seq <= coveredSeq`の`payload`列を空にする | `src/coordinator/store.ts:136`（v2）・`:315-318`（v1）の圧縮ロジックをほぼそのまま移植する。冪等性・単調増加制約（`coveredSeq`は後退不可、同値再送は先着優先）も含めて踏襲する |
| `/v2/entries/pull`（cursor=`seq`） | 既存`POST /v1/mimi/deliveries/pull`・`GET /v1/mimi/deliveries/stream` | 変更不要。新端末や長期オフライン端末の追いつきも、既存の`afterSeq`ベースのpull/SSEでそのまま賄える |
| v1 legacyのACK・per-recipient snapshot | 廃止 | v2で既に廃止済みの概念であり、本設計でも復活させない |
| Vault独自のMLS device management（`vault_members`等、v1 legacy） | 廃止、Self Group room自体のMLS commit（add/remove）に一本化 | §19.0で述べた統合そのもの |

### 19.2 サイズ制約とchunking方針

現行`MAX_BODY_BYTES = 1024 * 1024`（[http.ts:47](src/mimi/http.ts:47)、全POSTエンドポイント共通のHTTPボディ上限）に対し、Vault entryは最大25MB、checkpointは最大100MB——3〜4桁違う。

**推奨: 上限緩和ではなくchunkingを選ぶ。** 理由:
- MIMIプロトコル全体の「メッセージは小さい」という設計哲学（1MiB上限は`submitMessage`だけでなく全エンドポイント共通の意図的な制約）を、Vault専用に例外を空けて崩したくない。
- 単一HTTPリクエストで100MBを受ける実装は、メモリ・タイムアウト・リトライ設計の負担が大きい。既存のper-room `seq`ベースのpullは、そもそも複数の小さな配送を順序保証つきで運ぶ仕組みなので、chunkingと相性が良い。
- hub側の変更が最小で済む——新しいHTTPボディ上限の分岐を増やさず、新しい`kind`の意味論を1つ足すだけでよい。

具体設計（案、19.8で最終確認要）: Vaultの1エントリ・1checkpointを複数の`application`kind配送（既存submitMessageそのまま、既存1MiB上限内に収まるチャンク）に分割して連続送信する。checkpointの場合、実データのchunk群を送った後（または前）に、小さな`vaultCheckpointManifest`的なkindの配送を1通だけ送る——これがhubに見える唯一の新規メタデータで、`coveredSeq`・チャンク数・全体ハッシュ程度を持つ。hubはこのmanifest受理をトリガーに`coveredSeq`以下のapplication payloadを圧縮する。クライアント側はpull時にmanifestを見つけたら、それに紐づくchunk群を結合して復元する。

### 19.3 メタデータ平文漏洩の是正（AskUserQuestionで「直す」を選択済み）

現行Vaultの既知ギャップ（`ARC-coordinator.md`§11.3, Q7で確認済み）: entry payload内部のJSON構造（`VaultDeliveryPackV1`）で、event種別（`"message.add"`等の文字列）・`targetIds`・timestampが平文——coordinatorはこれをパースしないが、生バイトを見れば読める。

本設計での解消: Vault entryの中身（`VaultDeliveryPackV1`相当）は丸ごと**MLS `PrivateMessage`として暗号化**されて`appMessage`に入る（既存の`submitMessage`の`appMessage`は既にそういう扱い——[franking調査Q5]参照、hubは`appMessage`を一切パースしない完全opaqueなバイト列として扱う）。hubから見える範囲は既存のsubmitMessage経路が元々晒しているものだけ——sender credential、roomId、timestamp、32byte `frankingTag`、`epoch`、ciphersuite、そして`kind`文字列（`"application"`または新設の`"vaultCheckpoint"`系）。`VaultDeliveryPackV1`内部のevent種別やtargetIdsはMLS暗号化層の内側に完全に入るため、hubには一切見えなくなる——構造的な解消。

残る検討点: checkpointの`coveredSeq`自体はhubに見える必要がある（圧縮判断に使うため）。これはVault自身の`coveredSeq`も元々coordinatorに見えていた情報と同格であり、後退ではない。

### 19.4 新規実装が必要な箇所

- [src/mimi/protocol-types.ts](src/mimi/protocol-types.ts): `MimiDeliveryEntry.kind`（現行`'commit' | 'proposal' | 'welcome' | 'application'`）に`'vaultCheckpoint'`等を追加。checkpoint manifest配送用のフィールド（`coveredSeq`, chunk情報）を持つ型を追加。
- [src/mimi/store.ts](src/mimi/store.ts): `submitMessage`（[store.ts:245-257](src/mimi/store.ts:245)）に相当する新しいcheckpoint受理経路を追加し、受理時に`mimi_deliveries`の`application`kind・`seq <= coveredSeq`の`payload`列を空にする圧縮処理を実装する。[src/coordinator/store.ts:136](src/coordinator/store.ts:136)（v2）の`coveredSeq`検証（後退不可・単調性・同値再送の冪等性）をそのまま移植する。
- [src/mimi/wire.ts](src/mimi/wire.ts): 上記の新しいrequest/response・delivery entryのencode/decode追加。
- **entryの冪等性（`appendId`相当）**: 現行`submitMessage`にこの概念が無い。クライアント再送時に同じ内容が重複`seq`で積まれてよいのか（既存のVaultは`appendId`+`payloadHash`一致なら同じ`seq`を返す設計）、それとも冪等性はクライアント側のoutbox管理（`main.ts`の既存ローカルoutbox、変更対象からいったん除外）に完全に任せてよいのか——**要確認、19.8参照**。
- `biset-mimi-self`デプロイ自体（`MimiDeploymentOptions`）に新しいフラグは不要という理解——`allowExternalJoin=true`の既存normalモードのままでよい。

### 19.5 クライアント側の移植対象

現行:
- [src/vault/coordinator-transport.ts](src/vault/coordinator-transport.ts)（fetchラッパー、scope別bearer token）
- [src/vault/coordinator-sync.ts](src/vault/coordinator-sync.ts)（`synchronizeCoordinatorStream`, `flushCoordinatorStreamOutbox`）
- [src/vault/coordinator-checkpoint.ts](src/vault/coordinator-checkpoint.ts)（checkpointの暗号化/復号）
- [src/vault/coordinator-lifecycle.ts](src/vault/coordinator-lifecycle.ts)（Vault作成、v1 legacy専用）
- [src/main.ts:1859-1921](src/main.ts:1859)の`synchronizeStreamOnce`（pull checkpoint → Self Group追いつき → outbox flush → pull entries → 必要ならcheckpoint再構築）

これらを、biset-mimiの`MimiClientTransport`（既存、`submitMessage`/`deliveries pull`/`stream`を持つ）を使う新しいモジュール（例: `src/vault/mimi-vault-sync.ts`）へ置き換える。`synchronizeStreamOnce`の構造自体（checkpoint起点で追いつき、outboxをflushし、以後をpullし、caught-upならcheckpoint再構築）は本設計でもほぼそのまま使える——「checkpointをpullする」の実体が「`deliveries pull(afterSeq=0)`した結果から直近の`vaultCheckpoint`manifestを見つける」に変わるだけで、専用エンドポイントが1つ減る分むしろ単純化する。

認証は、Vault独自のbearer token scope（`vault.create|vault.group.install|vault.append|vault.pull|vault.ack`）から、biset-mimiの既存認証（credential + Ed25519署名、room参加者チェック）へ一本化する。

### 19.6 既存ユーザーの移行・coordinator退役の順序

1. 本節の設計を実装、`biset-mimi-self`に対して新規ロジックをテスト・実HTTPS検証（§18.4と同じ手法）。
2. **既存Vaultデータの移行は不要——削除してよい**（2026-09-02、ユーザーの明示指示）。現行coordinatorに保存済みのVaultデータは全てテストデータであり、実データは存在しない（§18で述べた既存の標準許可「リスクはない。実データも存在しない」と同じ前提）。よって移行スクリプトは作らない。coordinator退役時にVaultテーブル（`vault_streams`, `vault_stream_checkpoints`, v1 legacy分含む）ごと単純に破棄する。
3. 全員の切り替えが終わったら、coordinatorのVaultルート・関連テーブルを削除し、coordinatorプロセス自体を停止・退役する。

### 19.7 作業ワークシート（§13/§16と同じ規約：着手前`[ ]`→`[~] (agent: ..., 開始: ...)`、完了時`[x] (完了: ..., 関連ファイル)`）

- [x] **19.a 設計確認（最優先、他タスクをブロックする）**: 19.8の未確定事項（roomId命名規則、chunking方式の最終確認、`appendId`冪等性の置き場所）を決定し、本節に追記する。 (完了: 2026-09-02, 関連: §19.8; random room URI・manifest+chunk・hub側冪等性を確定)
  - depends on: なし
- [x] **19.b `MimiDeliveryEntry.kind`拡張とcheckpoint圧縮ロジック**: protocol-types.ts / store.ts / wire.tsへの実装（19.4）。 (完了: 2026-09-02, 関連: `src/mimi/{protocol-types,wire,authorizer,http,store}.ts`, `test/mimi/store.test.ts`; 署名済みmanifest、単調coveredSeq、同値再送、applicationだけの圧縮を実装)
  - depends on: 19.a
- [x] **19.c chunking実装**: 大きいentry/checkpointの分割送信・受信側再構成（19.2）。クライアント側（19.5の新モジュール）とhub側双方。 (完了: 2026-09-02, 関連: `src/vault/mimi-vault-chunks.ts`, `src/mls/mimi-client-transport.ts`, `src/mimi/store.ts`, `test/vault-mimi-chunks.test.ts`; 500KiB chunk、全体hash、順次送信・manifest後送信、hub側manifest/圧縮を実装)
  - depends on: 19.a
- [x] **19.d メタデータ平文漏洩の是正確認**: 実際にVault entryの中身がMLS暗号化層の内側に入り、hubから`VaultDeliveryPackV1`内部のフィールドが一切見えないことをテスト・実HTTPS検証で確認する（19.3）。 (完了: 2026-09-02, 関連: `test/mimi/store.test.ts`, `scripts/verify-mimi-vault-live.ts`; Self実HTTPSで暗号文entry・chunk・manifest圧縮まで確認)
  - depends on: 19.b
- [x] **19.e クライアント側移植**: `src/vault/mimi-vault-sync.ts`（新規）実装、`main.ts`の`synchronizeStreamOnce`呼び出し元をcoordinator-transportからこちらへ切り替え（19.5）。 (完了: 2026-09-02, 関連: `src/{main.ts,mls/mimi-vault-{room,session}.ts,vault/mimi-vault-sync.ts}`; durable MLS retry・MIMI inbox checkpoint復元/圧縮・Self endpoint切替)
  - depends on: 19.b, 19.c
- [x] **19.f テスト・実HTTPS検証**: `bun run typecheck`・`bun run test`、`biset-mimi-self`に対する実HTTPS End-to-End（entry送受信、checkpoint圧縮、chunk結合、新端末onboarding後のVault復元）。 (完了: 2026-09-02, 関連: `scripts/verify-mimi-vault-{live,onboarding-live}.ts`, `test/{vault-mimi-sync,mls/mimi-vault-room}.test.ts`, commits `8c6a949`, `221dc55`, `36600cb`; 実HTTPSで外部join→元端末受信→post-join checkpoint復元まで確認、全typecheck/testと公開app配信確認)
  - depends on: 19.b, 19.c, 19.e
- [x] **19.h coordinator退役** (完了: 2026-09-02, agent: Codex開始→本セッションで検証・仕上げ): 本番v1で確認——`biset-coordinator.service`のsystemd unitファイルは削除済み（`systemctl is-enabled`が`not-found`）、プロセスは`inactive`。バイナリは削除でなく`/opt/biset/bin/biset-coordinator.bak-*`として複数世代バックアップ保持（ロールバック用、意図的）。SQLite DBは本番の生きたパスには存在せず、`/var/backups/`・`/root/biset/state-backup-*/`配下のバックアップにのみ残存（意図的な退避、削除ではない）。Caddyの`coordinator.biset.md`ブロックはバックアップ（`Caddyfile.bak-coordinator-retire-20260902-101815`）を取った上で削除済み。
  - **本セッションで見つけて直した穴**：`coordinator.biset.md`ブロック削除後、同ドメインが`*.biset.md`ワイルドカードへ意図せずfall throughし、無関係なanchor/core側のper-identityハンドラが200を返す状態になっていた（デバッグ時に紛らわしい・将来の事故の元）。明示的に`coordinator.biset.md { respond ... 410 }`ブロックを追加し、`caddy validate`→`caddy reload`で本番反映、実際に410が返ることを確認した。
  - `client-side`（`src/main.ts`, `config.example.json`, `deploy.sh`）は既にCodexの`7b0bc35`でcoordinator依存を除去済み（`mimiSelfBaseUrl`設定時はcoordinator関連のboot処理を完全にスキップする後方互換ゲート付き）。
  - 実HTTPS疎通確認：`mimi-self.biset.md`・`mimi.biset.md`・`t.biset.md`（app）・`biset.md`（anchor）、いずれも200。
  - §5.4b（Self Group operational gate）はこの退役より後にチェックが付いた——本文書が定めた順序とは前後したが、ユーザーの明示的な独立許可に基づく判断（5.4bの完了注記を参照）。
  - depends on: 19.f

### 19.8 実装前に確認・決定すべき未確定事項

- **roomId命名規則（決定）**: `mimi://mimi-self.biset.md/r/vault-<base64url(random 32 bytes)>` とする。provider URI はMIMI room IDに必要だが、suffixは256-bit乱数のみでDID・domain・mail addressを含まない。provider移転時は既存room IDを不変のopaque IDとしてtransport設定から到達させ、identityのdomain変更でroomを再生成しない。新端末用にはこのopaque URIだけを署名済み`routing.json`の`mimiVaultRoom`へ置き、設定済みHTTPS providerと一致するURIだけを受理する。Vault内容・鍵・checkpointはこの公開ポインタに含めない。
- **chunking方式（決定）**: 上限緩和はしない。raw payloadは500KiB以下に分割する（MLS PrivateMessageとJSON/base64 framing後も共有1MiB HTTP上限内に収めるため。700KiBは実HTTPSで超過を確認）。transfer ID・ordinal・count・全体SHA-256を持つクライアント内のopaque envelopeを既存`submitMessage`で順に配送する。checkpointでは全chunkの後に、`coveredSeq`・transfer ID・count・hashだけを持つ署名済み`vaultCheckpoint` manifestを送る。hubはmanifestを認証・単調性検査して圧縮するが、暗号文chunkの内容を読まない。
- **entryの冪等性（決定）**: client outboxだけには委ねない。`SubmitMessageRequest`へランダムなopaque `deliveryId`を追加し、hubは`(roomId, sender client, deliveryId)`をpayload SHA-256とhub seqに一意に永続化する。同じID・同じhashは元の受理結果を返し、同じID・異なるhashは競合として拒否する。これは応答喪失後の再送で二重Vault eventを作らないためであり、Vault v2の`appendId`契約を保つ。
- **1MiB上限のchunkサイズ（決定）**: raw payloadは1 chunkあたり最大`500 * 1024` bytesとする。実HTTPSで700KiBがMLS暗号化・JSON/base64 framing後に共有1MiB HTTP上限を越えることを確認したため、十分な余白を確保した。25MB entryは最大52、100MB checkpointは最大205 chunkとなる。同期実装は逐次送信・逐次再構成し、全chunkを同時にメモリへ載せない。

## 18. `biset-coordinator`置き換えに向けて: `self`モード廃止と`allowExternalJoin`（2026-09-01）

§14で示したビジョン（Self Group = 本人1人のMIMI room）を実際に進めるにあたり、いくつか設計判断をやり直した。

### 18.1 決定: `self`という独立モードは廃止する

以前実装した`MimiDeploymentMode = 'normal' | 'anon' | 'self'`の`self`は、**デプロイ起動時に固定された単一の所有者(`selfOwnerUser`)しか使えない**という設計だった——これは「ユーザー1人につき専用プロセスを1つ立てる」ことを意味し、実際のユーザー数でスケールしない（5.4が"spike"止まりだった理由）。

正しい理解は「**third-partyグループとの可用性分離はプロセスレベルの話であって、コードレベルの話ではない**」ということ。`self`用の特別なコード（`credentialAllowed`の所有者チェック、`selfUpdateOwned`、federation route拒否）を全て削除し、`MimiDeploymentMode`は`'normal' | 'anon'`の2つだけにした。Self Group/Vault用のデプロイは、**third-party用と全く同じ`normal`モードのコード**を、別プロセス・別ポート・別DBとして立てるだけになる——コードは完全に1つ、`git diff`で差分ゼロ。

### 18.2 唯一残った実際の差: external join

coordinatorの設計（`PLAN_biset-coordinator.md`）は、root keyで復元した新端末が**他の端末が1台もオンラインでなくても**自分のSelf Groupに入れることを前提にしている。これはexternal join（`GroupInfo`取得→external commit）でしか実現できない。third-partyのgroup chatではexternal joinを許すとGroupInfoのratchet treeが実credentialを漏らすため意図的に403にしていた（Phase 6, 6.6）が、Self Groupでは「漏らす相手」がそもそも存在しない（部屋の所有者は１人だけ）。

これを新しい`mode`にせず、**`MimiDeploymentOptions.allowExternalJoin: boolean`という1つの設定フラグ**にした（デフォルト`false`、third-party用デプロイはこのまま）。Self/Vault用デプロイだけ`true`にする。

### 18.3 `POST /groupInfo/{roomId}`を実装した（spec §5.6準拠）

これまで「常に403」だった未実装のエンドポイントを、実際にspec §5.6の`GroupInfoRequest`/`GroupInfoResponse`のセマンティクスで実装した。

- [src/mimi/protocol-types.ts](src/mimi/protocol-types.ts): `GroupInfoRequest`/`GroupInfoResponse`/`GroupInfoCode`を追加。
- [src/mimi/authorizer.ts](src/mimi/authorizer.ts): `groupInfoRequestSigningBytes`/`groupInfoResponseSigningBytes`、`authorizeGroupInfoRequest`（署名検証のみ——参加者チェックはhttp.ts側、新しいdeviceのcredentialは初見が前提のため）、`userIsRoomParticipant`（**exact credential一致ではなくuser URI一致**——新端末は今まさに初めて見るcredentialを持っているのが前提）。
- [src/mimi/group-info.ts](src/mimi/group-info.ts)（新規）: `sealGroupInfoResponse`。room保存済みの`groupInfo`/`ratchetTree`（opaqueバイト列、既存の`HandshakeBundle.groupInfo`/`ratchetTree`フィールド経由で既に保存されていたが、今まで配信経路が無かった）を、requesterの`groupInfoPublicKey`へ`encryptWithLabel`（vendor engineの既存HPKE実装、`"GroupInfo and ratchet_tree encryption"`ラベル）でHPKE封印し、**roomのfranking鍵（Ed25519）をhub_senderとして再利用**して署名する——新しい鍵体系を増やさず、既存のfranking_signature_keyという「hubの識別子」をそのまま流用した。
- pending proposalsは追跡していないため常に空リスト——ドキュメント化済みの意図的な簡略化（spec自体は追跡を要求するが、初回の新端末onboardingという主要ユースケースでは実害が薄い）。
- [src/mimi/wire.ts](src/mimi/wire.ts): 対応するJSON+base64urlのencode/decode一式、および封印前のGroupInfoRatchetTreeTBE相当を`encodeGroupInfoRatchetTreeBundle`としてbiset独自JSON形式で実装（spec本文のTLS Presentation Language形式ではない、§3の既存方針通り）。
- テスト（`test/mimi/http.test.ts`）: 実際にHPKE鍵ペアを生成し、既存参加者と同じuser URIを持つ「新端末」がGroupInfoを取得・復号でき、無関係な第三者は`notAuthorized`、存在しないroomは`noSuchRoom`になることをEnd-to-Endで確認。

`typecheck`・全テストスイート無傷でパス。

### 18.4 本番デプロイ・実HTTPS検証完了（2026-09-01）

v1に3つ目のプロセス`biset-mimi-self`を追加した——`biset-mimi-normal`/`biset-mimi-anon`と全く同じバイナリ、`MIMI_MODE=normal`・`MIMI_ALLOW_EXTERNAL_JOIN=true`・独立DB(`/var/lib/biset-mimi-self/mimi-self.sqlite`)・独立ポート(8796)だけが違う。

- `/etc/biset/mimi-self.env`、`/etc/systemd/system/biset-mimi-self.service`を新規作成、`systemctl enable --now`。
- Caddyに`mimi-self.biset.md`ブロックを追加（`mimi.biset.md`/`mimi-anon.biset.md`と同じ`tls { alpn http/1.1 }`パターン）、`caddy validate`→`caddy reload`。
- 既存の`biset-mimi-normal`/`biset-mimi-anon`もこのフェーズの変更を含む最新バイナリへ再デプロイ・再起動し、`mimi.biset.md`の`groupInfo`が引き続き`403 not-allowed`を返すこと（挙動不変）を確認。
- `https://mimi-self.biset.md`に対し実際にHTTPS越しでEnd-to-Endを実行——room作成（`franking-agent` GET→鍵取得→commitに埋め込み→`/update`）、所有者の新端末が`/groupInfo`でGroupInfo+ratchet_treeを取得・HPKE復号・hub署名検証まで成功、無関係な第三者は`notAuthorized`、存在しないroomは`noSuchRoom`を確認。ローカルテスト(`:memory:`)と完全に同じ結果が実配線でも再現。

残る最大の穴は§Pending（Vault data plane: `/v1/vaults`, `/v2/entries/*`, `/v2/checkpoints/*`）——`biset-coordinator`にはこれらの相当機能があるが`biset-mimi`には未設計。これが片付くまで`biset-coordinator`は退役できない。

## 20. Federation outbound dispatchの配線（2026-09-02）

Phase 3（§13/§10.1）で「independent hub/follower間でmTLS-bound `/notify`を通したhub commitがfollowerのlocal deliveryへ到達すること」は確認済みだったが、それは**手動で`/notify`をPOSTしてpeer pushをシミュレートしたテスト**（`federation-gate.test.ts`）——「ローカルのroom更新/message送信が受理されるたびに、hubが自発的にリモート参加者のいるproviderへfanoutする」という**トリガー自体**は未配線のままだった（`MimiFanoutDispatcher.send`はコードにあるがどこからも呼ばれていなかった）。本節はこの配線と、その過程で見つかった別の穴を記録する。

### 20.1 実装したもの

- [src/mimi/mimi-uri.ts](src/mimi/mimi-uri.ts)（新規）: `mimiUriProviderDomain(uri)`——`mimi://domain/u/...`形式のURI（spec行344-352）からprovider domainを取り出す。`WHATWG URL`パーサは非specialスキームでも`//`付きなら authority を正しく解釈することを確認済み（`mimi://a.example/u/alice`→`hostname: 'a.example'`）。
- [src/mimi/provider-directory-client.ts](src/mimi/provider-directory-client.ts)（新規）: `resolveMimiProviderBaseUrl(domain)`——`https://{domain}/.well-known/mimi-protocol-directory`を取得し、`notify`フィールドのoriginを返す。identity domainと実際のhub originが一致すると仮定せず、自分自身が配るのと同じdirectory機構で相手にも問い合わせる設計。
- [src/mimi/http.ts](src/mimi/http.ts): `MimiFederationOptions`に`outbound?: { dispatcher: MimiFanoutDispatcher; resolveProviderBaseUrl?(domain): Promise<string> }`を追加（未設定なら今まで通りoutboundなし）。`dispatchFanout(...)`——`/update`・`/submitMessage`が受理された直後、roomの**現在の**participant listのうちローカルでない（`federation.providerDomain`と一致しない）domainを集め、それぞれへ`MimiFanoutDispatcher.send`する。**fire-and-forget**——ローカルのレスポンスは待たせず、相手が不通でもローカルの受理は失敗しない（ログのみ）。Welcomeは`HandshakeBundle.welcome`がbare `Welcome`構造体（ローカル配送と同じ形）のため、`decodeWelcome`→`encodeMlsMessage({wireformat:'mls_welcome',...})`で完全なMLSMessageへ包み直してから送る（`fanout.ts`の`validate()`が完全なMLSMessageを要求するため）。
- [test/mimi/federation-dispatch.test.ts](test/mimi/federation-dispatch.test.ts)（新規）: 本物のMLS commit（`add` proposal + AppSync）でhub上にroomを作り、`mimi://follower.example/u/bob`という別providerのユーザーを追加するcommitを`/update`で送るだけで（`MimiFanoutDispatcher.send`を一切手動で呼ばずに）followerのstoreへcommit・welcome・その後のapplication messageが自動的に届くことを確認。

`bun run typecheck`（全7 tsconfig）・`bun run test test/mimi`（38 files）・`bun run build:mimi`、いずれも無傷。

### 20.2 テスト中に見つかった別の穴: followerは未知のroomのfanoutを拒否する

`store.ts`の`acceptProviderFanout`（[store.ts:226](src/mimi/store.ts:226)）は、**そのroomが自分のstoreに既に存在する場合しか受理しない**（`if (!room) return 'noSuchRoom'`）——受信したcommitからroomを新規作成するブートストラップ機構が無い。実際に`federation-dispatch.test.ts`のroom作成commitをfollowerへfanoutしたところ、事前にfollower側でroomを（テストの都合で`store.submitUpdate`を直接呼んで）作っていなければ`404 noSuchRoom`で拒否されることを確認した。

これは§20.1で直した「outbound dispatchのトリガー」とは別の、もう一段深い穴——「Aliceが初めてBobを（別providerの）新しいroomへ招待する」という、まさにこのPLAN文書冒頭で例に出した新規送信フローが、outbound dispatchが直っても依然として完結しない。理由：Bobのprovider（follower）は、Bobが実際に参加する前提のroomをまだ一度も知らない状態でfanoutを受け取ることになるが、現在の実装はそれを拒否する。

**部分的に解決した（2026-09-02、同日中）**: `store.ts`に`createFromProviderFanout`を追加し、`acceptProviderFanout`が未知のroomIdへのfanoutを、その**commitがroom作成に自己完結している場合に限り**新規room作成として受理できるようにした（[store.ts:225](src/mimi/store.ts:225)、[http.ts:157](src/mimi/http.ts:157)の`bootstrapTransitionFromFanout`）。「自己完結」とは、genesis commit自体に`add`（Bobを含む）・`participant_list`・`room_metadata`・`franking_signature_key`のAppDataUpdateが全て乗っている場合——`test/mimi/federation-dispatch.test.ts`の新規テストで、Bobを初期メンバーに含むgenesis commitを`hub`の`/update`へ送るだけで（手動seeding無しに）`follower`側へroomが自動作成されることを確認した。

**まだ解決していない部分**（スコープ外として明記）：
1. **後からメンバーが追加されるケース**（roomが既に存在する状態で、後続のcommitで初めてBobが追加される——本セクション冒頭で最初に見つかった元のテストケースがまさにこれ）は、まだ動かない。理由：後続の「メンバー追加」commitは通常`room_metadata`/`franking_signature_key`を再送しない（変更が無いので送る必要が無い——実際`test/mimi/http.test.ts`の`add`テストでもこの2つは送られていない）。したがってbootstrapに必要な情報がその1つのcommitだけでは揃わない。これを解決するには、followerがhome providerへ「このroomの現在のstateをくれ」と問い合わせる**新しいprovider間エンドポイント**が要る——現状存在しない、未設計。
2. **`memberCredentials`が空のまま作られる**（[store.ts:225-243](src/mimi/store.ts:225)のdocコメントに理由を明記）——MLS credentialのエンコーディングはMIMI上で実装依存であり、fanoutされた`add` proposalの生バイトだけから「このleafはどのローカル参加者のものか」を汎用的に特定する信頼できる方法が無い。結果、`credentialMatchesRoom`（`authorizer.ts`）による完全一致要求のため、**bootstrapされたroomでも、followerのローカル参加者（Bob）はまだ`deliveries pull`/`submitMessage`を呼べない**——room自体は作られるが、Bob自身がそこへ参加してくる経路（Welcomeを処理した後、自分の credential を home hub 側の記録と一致させる自己登録の仕組み）がまだ無い。これは新しいwireプロトコル面の設計判断であり、次のセッションで着手前に方針を確認する。

加えて、biset自身の`/update`にある「franking_signature_key credentialは自分自身のHTTPS originと一致しなければならない」というチェック（[http.ts](src/mimi/http.ts)、`/update`ハンドラ内）は「呼び出し元が自分がそのroomのホームhubだ」という前提に立っており、followerとして他providerのroomを鏡映しにする操作には引き続き**そのまま使えない**——ただしこれは`/update`（ローカルクライアント向け）の話であり、今回追加した`/notify`経由のbootstrap（`createFromProviderFanout`）はこのチェックを最初から経由しない別経路なので、この制約と衝突しない。

### 20.3 本番投入にまだ必要なもの（未着手、20.1のコードとは別スコープ）

- biset-mimiの各ドメイン用TLSクライアント証明書（Caddyが既に持つLet's Encryptサーバー証明書を、outbound用クライアント証明書として流用できる可能性が高い——ACME証明書は通常EKUをserverAuthに制限しないため。要確認）。
- Caddy側で`/notify`等federation専用routeへのクライアント証明書要求・検証（`client_auth { mode request }`——`require`ではなく`request`。通常のクライアント（ブラウザ）はクライアント証明書を持たないため、site全体を`require`にすると壊れる）、検証済みpeerの識別情報をBunプロセスへヘッダ経由で転送する設定。**Caddyが公開CAに対するクライアント証明書検証を素直にサポートするかは未検証**——ここは実装前に要調査。
- 本番用`authenticatePeer`実装（Caddyが転送するヘッダを読む）、`index.ts`への`federation`オプションの配線（現状`index.ts`は`federation`を一切渡していない——本番は federation 機能全体がOFF）。
- 検証：biset自身が別ドメインの2台目インスタンスを立てて、実際のmTLSハンドシェイク〜dispatch〜受信までを実配線で確認する（本物の外部MIMIプロバイダは現状世に存在しないため）。

## 21. hubの認証モデルを本物のMLS PublicMessage署名検証へ（2026-09-02、spec §9/§7.4に基づく）

§20.2で見つかった2つの未解決点（後からのメンバー追加のbootstrap、`memberCredentials`の出所）は、どちらもbiset独自の回避策（新しいprovider間state-sync endpoint、新しいcredential自己登録endpoint）を発明しないと解けないように見えていた。だが`mimi-protocol-06.md`を読み直すと、specは既に答えを持っていた。

### 21.1 spec本文が示す、本来あるべき認証モデル

- **§9 Security Considerations**：「room actionのpolicyを強制するhubに対し、actorは自分の身元を、MLSのPublicMessage署名形式＋MLSが提示するidentity credentialを使って認証する」。
- **§7.4 Authenticating proposals**：hub・followerサーバー自身のproposal発行権限は、group自体が持つRFC 9420標準の`external_senders`拡張（証明書リスト）で管理される。「followerのユーザーが参加者になったら、そのfollowerの証明書を`external_senders`へ追加する（普通のMIMI commitとして）」——新しいendpointではなく、既存のcommitフローの一部。

つまり、hubが参加者を認可する本来の方法は、**biset独自の外側Ed25519署名＋`memberCredentials`サイドカーの厳密byte一致**ではなく、**PublicMessageの内部署名を、その時点のratchet tree上の該当leafの署名鍵と照合して検証する**こと。これが本来動けば、§20.2の2つの穴は副産物として消える——sidecar自体が要らなくなるので、federationでも自然に機能する。

これは新しい発見ではなく、§17.2で既に記録していた既知のgap（「MLS commit自体の内部署名はhubで検証されていない...単一hub運用では実害はないが、真に独立した外部MIMI providerがMLS原生の署名だけで送ってきた場合には検証経路が無い」）と同じ根——今回の2つの行き詰まりは、その省略の副作用だったとわかった。

### 21.2 実装したもの：`src/mls/vendor/publicGroupState.ts`（新規）

hubは実際のMLS groupのmemberではない（秘密鍵を一切持たない）。RFC 9420のDelivery Service設計は、まさにこの「メンバーではない観測者が、tree構造・署名鍵といった**公開情報だけ**を追跡する」モデルを前提にしている。vendored MLSライブラリ（`src/mls/vendor/`）は、この公開部分を扱う関数を既にほぼ全て持っていた（`validateRatchetTree`・`applyUpdatePath`・`nextEpochContext`・`findSignaturePublicKey`・`verifyFramedContentSignature`）——ただしどれも`ClientState`（秘密鍵込みの型）に紐づく形で使われていた。

新規`PublicGroupState`型（`{groupContext, ratchetTree, confirmationTag, unappliedProposals}`）と、以下の関数を実装：

- `initialPublicGroupState(ratchetTree, groupContext, authService, cs)` — genesis状態の初期化（`validateRatchetTree`で構造検証）。
- `verifyPublicMessageSignature(state, message, wireformat, cs)` — PublicMessageの内部署名を、tree上の該当leafの鍵（またはexternal_senders拡張の鍵）と照合するだけの独立した検証（commit適用とは別に、application/proposalメッセージ単体にも使える）。
- `applyPublicCommit(state, message, authService, cs)` — 署名検証→`applyProposals`（既存の唯一の実装を、秘密鍵フィールドがダミーの`placeholderClientState`経由で再利用——ダミー値が読まれるのは`external_init`分岐が計算する`externalInitSecret`だけで、その値自体は捨てる）→`applyUpdatePath`で公開tree効果を適用→`nextEpochContext`でepoch/tree hash/transcript hashを進める。

**意図的にできないこと（省略ではなく、MLSの設計上不可能）**：confirmation tag・membership tagの検証は、epoch secret（実メンバーしか持たない）に依存するため、非メンバーのhubには原理的に不可能。hubが検証できるのは「誰が送ったか（署名）」と「tree構造の整合性（parent hash・tree hash）」まで——epoch secret自体の内部整合性は実メンバー側の責任、というのがRFC 9420のDelivery Serviceモデルそのもの。

### 21.3 実地検証

`test/mls-vendor-public-group-state.test.ts`：実際に2人（Alice作成→Bob追加）のMLS groupを組み、本物のclient側`ClientState`が計算する`ratchetTree`/`groupContext`/`confirmationTag`と、このtrackerが同じcommitバイト列だけから独立に計算した結果を突き合わせ、**完全一致**することを確認した。署名を改ざんしたcommitは`verifyPublicMessageSignature`が`false`を返し、`applyPublicCommit`が例外を投げることも確認済み。`bun run typecheck`（全構成）・`bun run test`（全体）とも無傷。

### 21.4 解決：genesisのconfirmationTagはGroupInfoが運ぶ（新しいプロトコル不要）

「genesisのconfirmationTagをhubがどう知るか」——新しいwireフィールドを発明する前に思い出すべきだった。**RFC 9420のGroupInfo構造（`GroupInfoTBS.confirmationTag`）が、まさにこの値を運ぶために存在する**。GroupContext・（`ratchet_tree`拡張経由の）ratchet tree・confirmationTagが1つの構造にまとまり、group内の実メンバー（`signer`、tree自身から鍵を引ける leaf index）の署名で保護されている。

biset-mimiの`HandshakeBundle.groupInfo`（`protocol-types.ts`）は**既存の、これまでオプションだったwireフィールド**——biset自身のクライアントコードが`groupInfoForExternalJoin`（`src/mls/group.ts`）で`encodeGroupInfo`（bare構造体、Welcomeと同じ規約で非MLSMessage-wrap）としてこれまでも生成していた。今回新しくやったのは、hub側でこれを**デコードして使う**ことだけ——新しいプロトコル面は一切追加していない。

新規[src/mimi/mls-group-info-bootstrap.ts](src/mimi/mls-group-info-bootstrap.ts)：`bootstrapPublicGroupStateFromGroupInfo(groupInfoBytes, authService, cs)`——GroupInfoをdecode→`ratchet_tree`拡張からtreeを取り出す→`signer`のleaf鍵をそのtree自身から引く→`verifyGroupInfoSignature`で自己完結的に署名検証→検証済みの`PublicGroupState`を返す。`test/mimi/mls-group-info-bootstrap.test.ts`で、実clientの`ClientState`と完全一致することを確認済み（改ざんされた署名は正しく拒否）。

### 21.5 配線した：store.ts/http.tsへの統合

trackerとGroupInfo bootstrapを、実際にbiset-mimiの認証経路へつないだ。

- **永続化**：`mimi_mls_public_state`テーブル（room_id, group_context, ratchet_tree, confirmation_tag）と`store.mlsPublicState/saveMlsPublicState/clearMlsPublicState`アクセサ（store.ts）。`Database.transaction`は同期でなければならないため、この非同期な暗号検証は`submitUpdate`のトランザクションの**外側**で行う——`http.ts`の`trackMlsPublicState`が、`dispatchFanout`と同じ「acceptが返った後にfire-and-forgetで走る」形を踏襲する。
- **room作成時**：`bundle.groupInfo`が提供されていれば`bootstrapPublicGroupStateFromGroupInfo`でtracking開始（無ければ従来通りtrackingなしのまま、後方互換）。
- **以後のcommit**：trackingされているroomなら`applyPublicCommit`で追随。**fail-open**——検証・適用が何らかの理由で失敗したら、そのroomのtrackingを単に止める（`clearMlsPublicState`）だけで、commit自体のaccept/rejectには一切影響しない。この機構は既存のsidecar照合に「足す」だけの追加チェックなので、trackingが失敗しても既存の動作を後退させることは構造上あり得ない。
- **`credentialMatchesRoom`（authorizer.ts）の拡張**：既存のsidecar厳密一致に加えて、**tracking済みroomなら、claimされた`(credential, signaturePublicKey)`ペアが現在のtree上の実leafと一致するか**もOR条件で見る——sidecarに無くても、tree上に実在すれば認可される。pseudonymous credentialialは対象外のまま（既存の§17.4の判断を継承——匿名モードの身元検証はクライアント側の別機構が担当）。

### 21.6 実地検証：federationの穴が実際に閉じたことを確認

[test/mimi/mls-tree-authorization.test.ts](test/mimi/mls-tree-authorization.test.ts)——本物のMLS commitでBobを追加するが、`/update`リクエストに`stateUpdate`（sidecar）を一切含めない、という条件で：

1. `deployment.store.room(roomId)?.memberCredentials`にBobのエントリが**存在しないこと**を確認（sidecarには本当に何も無い）。
2. Bobが自分の実leaf鍵で署名した`deliveries/pull`が**成功**し、実際にcommitが返る。
3. Bobが実leaf鍵で署名した`submitMessage`も**成功**する。
4. 無関係な鍵で「Bobだ」と名乗るstrangerは**403で拒否**される。

これで§20.2で見つかった2つの穴のうち「memberCredentialsの出所」は解消。「後からのメンバー追加のbootstrap」（既存roomが別providerへ初めてfanoutされる際、genesis以外のcommitだけではroom_metadata/franking_signature_keyが揃わない問題）も、GroupInfoが任意のepochで発行できる以上、federation dispatch側がGroupInfoを添えて送れば同様に解決できる見込み——ただし、そのための実際の配線（fanout batchへのGroupInfo同梱、§20.3のmTLS/Caddy配線と合わせて）はまだ次のステップ。

`bun run typecheck`（全7構成）・`bun run test`（mimi/MLS vendor関連44テスト）・`bun run build:mimi`、すべて無傷。
