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

クライアント側の振り分け（相手がbiset内部かどうか、anon/normalどちらを使うか、を自動選択する仕組み）は別文書で扱う（本文書はサーバー実装のみ）。

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
- クライアント側のtransport振り分けUI/UX → 前回までの議論で合意した「相手のcapabilityで自動選択」の実装は別文書。

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

## 11. 未決事項

1. **room policy（役割/権限体系）の具体設計** — `draft-ietf-mimi-room-policy`の内容を別途調査してから確定する。今は`room-policy.ts`にフックだけ用意する。
2. **他社MIMI実装の実際のwire形式** — JSON採用を決めたが、実際に相互接続するprovider次第でアダプタが要る可能性がある。Phase 3で確認する。
3. **anon modeの再暗号化コストの実測** — §7.3。大規模room未対応の可能性を許容するか、別の緩和策（例: 変更があったメンバーの差分だけ再暗号化）を検討するかは実装しながら判断する。
4. **frankingのhub_key漏洩時の対応** — spec自身のtrust modelの限界であり、biset固有の対応策があるかは要検討。
5. **`biset-mls-ds`の廃盤条件・移行手順（新規、2026-09-01）** — 「`biset-mimi`（anon-mode）が今の`biset-mls-ds`と同等以上のidentity-blindness保証を満たす」ことをどう検証・宣言するか（§10 release gateの拡張が必要）。既存`biset-mls-ds`上の稼働中roomをどう移行するか（`GroupLocalId`→`PseudonymousCredential`の変換は非自明——両者は暗号的に無関係な仕組みであり、単純な変換式は無い可能性が高い。roomを作り直す形の移行になるかもしれない）。
6. **`biset-coordinator`（Self Group DS）統合の是非・設計（新規、2026-09-01）** — §0/§14で方向性のみ記録。「room=本人1人・複数device」という統合は魅力的だが、[PLAN_biset-mls-ds.md §2](PLAN_biset-mls-ds.md)がcoordinatorとmls-dsを分離した可用性上の理由（third-partyトラフィックがVault同期の可用性を脅かすリスク）が、この統合でも同様に問題になる。normal/anonに加えて**3つ目のプロセス（self-group専用）**が要るのか、それとも別の分離策があるのか、Phase 3完了後に別途設計する。

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
- [ ] **2.2 identity-link再暗号化**: `src/mimi/anon/identity-link.ts`。§7.2のexportSecretベース方式。`src/mls/group.ts`の`exportSecret`をhub側から呼べる形で使う（hub自体はMLS秘密状態を持たないので、**再暗号化は実際にはclient側=commit送信者が行い、hubはciphertextを運ぶだけ**であることに注意——hubがexportSecretを計算することはない。この役割分担をここで明確にすること）。
  - 参照実装: `src/mls/group.ts`の`exportSecret`
  - depends on: 2.1
- [ ] **2.3 PseudonymousCredential型・wire**: `src/mimi/protocol-types.ts`/`wire.ts`に追加。
  - depends on: 2.1
- [ ] **2.4 authorizer.ts拡張**: `mode === 'anon'`のインスタンスでは`PseudonymousCredential`以外のroom作成/commitを拒否する（実credentialが誤ってanon-modeインスタンスに混入することを防ぐ、構造的なガード）。normal-modeのインスタンスでは今まで通り。
  - depends on: 2.3
- [ ] **2.5 テスト**: 新規参加者が既存メンバー全員の実credentialをidentity_link_ciphertext経由で復号できることを確認。epoch進行後、破棄したはずの旧epoch鍵で過去のciphertextが復号できないことを確認する回帰テスト（§10で明示的に要求されている）。anon-modeインスタンスへ実credentialでのroom作成を試みて拒否されることも確認する（2.4のガード）。
  - depends on: 2.2, 2.4
- [ ] **2.6 デプロイ設定**: `biset-mimi-normal.service`/`biset-mimi-anon.service`相当のsystemd unit定義・env fileのテンプレートを用意する（本番デプロイはこのフェーズの範囲外だが、2つのプロセスとして動かせることをローカルで確認する分の設定は用意する）。
  - depends on: 2.4
- [ ] **2.7 Phase 2 release gate確認**（§10）。
  - depends on: 2.5, 2.6

### Phase 3: 実フェデレーション

- [ ] **3.0 前提調査**: `draft-ietf-mimi-room-policy`の内容を取得・確認する（§11未決事項1）。この結果次第で3.5（room-policy.ts）の設計が変わるため、3.5より先に必ず行う。
  - depends on: 2.7
- [ ] **3.1 provider-transport.ts**: mTLS + From/Hostヘッダによるprovider間認証（spec §4.1）。
  - depends on: 2.7
- [ ] **3.2 directory.ts**: `GET /.well-known/mimi-protocol-directory`（spec行1023）。
  - depends on: 3.1
- [ ] **3.3 同意/存在確認系エンドポイント**: `requestConsent`/`updateConsent`/`identifierQuery`（spec行2219, 2220, 2346）。
  - depends on: 3.1
- [ ] **3.4 fanout**: `POST /notify/{roomId}`（spec行1924）。0.6で設定済みの`idleTimeout`が効いてくる箇所。
  - depends on: 3.1
- [ ] **3.5 room-policy.ts**: role/permission体系の実装。
  - depends on: 3.0
- [ ] **3.6 reportAbuse/proxyDownload**: 残り2エンドポイント（spec行2568, 2713）。
  - depends on: 3.1
- [ ] **3.7 Phase 3 release gate確認**（§10、最低1つの外部または自前2台構成でのhub/follower間room共有）。
  - depends on: 3.2, 3.3, 3.4, 3.5, 3.6

### Phase 4: クライアント統合

- [ ] **4.1 mimi-client-transport.ts**: `src/mls/mimi-client-transport.ts`。
  - 参照実装: `src/mls-ds/client-transport.ts`
  - depends on: 3.7
- [ ] **4.2 normal/anon振り分けロジック**: 別文書（相手のcapability discoveryに基づく自動選択、このセッションの前半で合意した設計）と接続する。この文書には設計を書かず、別文書へのリンクをここに追加する。
  - depends on: 4.1

### Phase 5: 将来統合（現時点では着手しない）

§14の通り、`biset-mls-ds`の廃盤と`biset-coordinator`統合は方向性のみ確定していて具体設計がまだない。**このフェーズのタスクは意図的にまだ列挙しない**——§11未決事項5・6の設計が終わってから、この節にタスクを追記する。今この節を見たagentは、ここに着手するのではなく§11未決事項5・6の調査・設計提案をまず行うこと。

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
