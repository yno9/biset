# DID Discussion

biset の識別子層(did:dht)の解決の仕組み、それを支える経済的合理性、そして「DIDベースのメッセージング」導入の検討経緯をまとめたディスカッションログ。設計そのものの仕様は [`DID.md`](DID.md)、実装済みの現状は [`ARC.md`](ARC.md#identity-layer-did) を参照。ここは「なぜその形になったか」の議論の記録。

---

## 1. did:dht はどう解決されるか

`did:dht:<suffix>` の `<suffix>` 部分は、Ed25519公開鍵をz-base-32エンコードしたものそのもの。解決は以下の手順:

1. suffixをz-base-32デコードしてEd25519公開鍵を得る
2. その鍵をキーとして、BitTorrent **Mainline DHT** 上の **BEP44 mutable item** を検索する
3. 返ってくるペイロードは `署名(64B) + seq番号(8B, big-endian uint64) + DNSパケット本体` という構造
4. DNSパケットの各TXTレコード(`_k0._did.`が鍵、`_s0._did.`/`_s1._did.`がserviceなど)をdid:dhtのProperty Mapping規則に従って読み替えると、DID Documentが復元できる

**特徴と裏付けた事実:**
- 署名は発行者の秘密鍵によるものなので、**特定のリレー/Gatewayを信頼する必要がない**(クライアント側で検証できる)。実運用のPkarr公開relay(`relay.pkarr.org`)に対して実際に `curl` → バイナリ取得 → 手動デコードを行い、この構造を確認済み。
- BEP44の仕様上、レコードは再アナウンスなしで**約2時間**でDHTから消える(TTL)。ただし、biset自身のpkarr gateway(`go-jmapserver/pkarr/gateway.go`)は取得・登録した全レコードを無期限にキャッシュ・再Publishしていた(修正前)。この挙動は「生きてるアカウントは高可用」という利点と、「消したはずのアカウントがずっと再公開され続ける」という欠点の両面を持つ(`Gateway.Forget`で対処、詳細はARC.mdの該当箇所)。
- 中央集権的なGatewayサーバー(例: TBDが運用していたテスト用`diddht.tbddev.org`)はあくまで**便利なキャッシュ層**であり、DHT本体の代替ではない。実際、TBD/Block社は2024年11月にWeb5構想自体を縮小・撤退し、このGatewayも消滅した。しかしDHT本体・Pkarr relay(`relay.pkarr.org`など)はそれとは独立に生き残っている。

---

## 2. なぜ did:dht なのか(経済的合理性)

Mainline DHTを選ぶ最大の理由は経済的なもの: **プロトコルレベルのインセンティブ層(トークン、マイナー、バリデータ)が一切不要**で、biset側もそれを必要としない。

- **共同生産(joint production)**: BitTorrentクライアントは「DHTを維持するため」ではなく、「自分が欲しいファイルのpeerを見つけるため」に動いていて、DHTノードとしての稼働はその**副産物**にすぎない(牛を育てて牛肉と皮を同時に得る構造と同じ)。
- **正の外部性への意図的なフリーライド**: 世界中の約1000万台のBitTorrentノードは、did:dht/Pkarrのトラフィックを運んでいることを知らず、対価も受け取っていない。biset(や他のPkarrベースのシステム)はこの外部性にタダ乗りしている。
- これがブロックチェーンと根本的に違う点: ブロックチェーンは「グローバルな二重支払い防止の合意」という高コストな問題を解くために報酬設計が要るが、did:dhtのレコードは**署名による自己認証**(グローバル合意不要)+ **自然消滅(TTL)**(ストレージの外部性なし)で成立しているため、そもそも経済的インセンティブで攻撃コストを吊り上げる必要がない。
- 弱点の裏返し: 誰も「維持するため」に動いてないので**SLAが存在しない**。企業が運営する便利Gateway層(TBDの例)はいつ消えてもおかしくないが、DHT本体はどの一社の資金繰りにも依存しないぶん、はるかに頑健。

(この節の詳細版は [`ARC.md`](ARC.md) の `## Why did:dht?` セクションに英語で記載済み。)

---

## 3. DIDベースのメッセージングプロトコルの選択肢

biset に「DIDを使ったメッセージング」を足す場合の主な候補を調査した:

| プロトコル | 識別子との関係 | 強み | 弱み |
|---|---|---|---|
| **DIDComm Messaging v2**(DIF標準) | DID Documentの`service`(`DIDCommMessaging`型)で相手を発見。トランスポート非依存(HTTP/メール/QR/オフライン) | biset既存の「DID Documentのserviceで相手を発見する」設計・「1 relay = 1 protocol」設計と親和性が高い。Mediator(中継)概念もrelay構造に近い | 一般消費者向けチャットとしての実運用例がまだ少ない(主にSSI/資格情報交換文脈) |
| **XMTP** | ウォレット/任意のDID/ネットワーク識別子と紐付け可能 | グループ暗号にMLSを採用 — bisetがAP向けE2EEで既に選んだMLSと設計思想が近く、参考実装として有用 | Web3/ウォレット文化寄りで、bisetのメール的ユースケースとはやや毛色が違う |
| **Nostr DM(NIP-04/NIP-17)** | biset は既に `seed.ts` でNIP-06経由のNostr鍵を派生済み | 追加の鍵管理なしで着手できる可能性があり実装コストが一番低い | npubとdid:dhtの対応を明示的に結ぶ仕組みが別途必要 |
| **AT Protocol(Bluesky) chat** | did:plc/did:webを使うが、DM自体は`chat.bsky`という独自API寄り | 汎用プロトコルとしての独立性が薄く、did:dhtとの相性で得るものが少ない | — |

**結論**: biset自身の設計(did:dhtのservice解決 + relay=protocolブリッジ + AP向けに既にMLSを選定済み)を素直に伸ばすなら、**DIDComm**が本命候補、**Nostr NIP-17**が最も低コストな代替、**XMTP**はMLS実装の参考として横目に見る、という位置づけ。

---

## 4. DIDCommの将来性

**追い風:**
- 2026年5月、DIFは新規メンバーLeadpoint Systemsと組み、DIDComm実装のデータベース化に着手 — DIF自身が「実装は把握してる以上に広く使われているはずだが、可視化が追いついていない」と認めている段階。
- EUの「Digital Product Passport(循環経済規制)」ランドスケープ文書でDIDComm2が標準候補として明記されるなど、**規制の絡む企業間データ交換**の文脈で採用圧力が高まりつつある(元々Hyperledger AriesのVerifiable Credential交換から出てきた経緯とも合致)。
- 「AIエージェント間の検証可能な通信基盤」としてDIDCommを再文脈化する議論も出てきている。DIF新エグゼクティブディレクターもAgentic AI領域を重点分野に挙げている。

**逆風:**
- 一般消費者向けチャットとしての実運用例はまだ少数(DIF自身が挙げる例もEntidad/Unmioのデモ程度)。Signal/Matrix/DeltaChatのような広い実運用には届いていない。
- SSI業界全体が抱える「DID方式間の相互運用性の欠如」という慢性課題を引きずっている(次節)。
- TBD/Block社のWeb5撤退(2024年11月)は did:dht 方式そのものの否定ではないが、「大企業がDID関連投資を引き上げる」前例として業界心理への逆風になっている。

**総括**: DIDCommは「エンタープライズ/資格情報交換/規制対応インフラ」としてはじわじわ本命化しつつあるが、「メッセージングアプリの土台」としてはまだニッチな実証実験の域。biset のように実際に人が使ってるネットワーク(DeltaChat/chatmail、ActivityPub)との相互運用を最優先する設計とは、全面採用ではなく**部分的な補助チャンネル**としての導入が現実的。

---

## 5. 「DID方式間の相互運用性の欠如」の実態 — did:dhtはdid:plc/did:webと話せないのか

結論: **プロトコル仕様としては方式非依存**だが、実務では2段階の壁がある。

1. **DIDComm実装側の解決コード(ドライバ)のカバレッジ問題**: DIDComm実装(didcomm-rs、Aries系など)は「DID → DID Document」変換をUniversal Resolver的なプラグイン機構に投げるが、そのドライバは方式ごとに個別実装が必要。主要ライブラリが標準サポートしてるのは`did:peer`/`did:key`/`did:web`/`did:ion`あたりに偏っており、**did:dhtやdid:plc用のドライバは未整備なことが多い** — プロトコルは話せるはずなのに、手元のライブラリにコードがないので動かせない、という実装カバレッジの問題。
2. **相手が実際にDIDCommを喋っているかは別問題**: did:plcは基本的にAT Protocol専用の識別子で、そのDID Documentの`service`には`AtprotoPersonalDataServer`のようなAT Protocol専用エントリしか入っておらず、**`DIDCommMessaging` serviceを公開しているdid:plcユーザーはほぼいない**。解決はできてもエコシステムとして繋がる相手がいない。

→ biset的には、①はdid:dht用のresolverを書けば解決できる(次節参照)。②はdid:plc/did:webとの相互運用を狙うなら相手側の対応待ちになるため、**まずはbisetユーザー間(did:dht同士)での利用**が現実的な最初のスコープ。

---

## 6. 実装案: did:dht上でDIDCommを話す(biset向け)

biset ユーザー間の会話を、AP(ActivityPub)経由よりも軽量なチャンネルでやりたい、というモチベーションに対する具体案。

**既に流用できるもの:**
- `src/did/resolver.ts`(DHT resolve/publish) — DIDCommライブラリが要求する `resolve(did) → DID Document` という薄いインターフェースにラップするだけで足りるはず。ゼロから書く必要はない。

**新規に必要なもの:**

1. **鍵交換用のX25519鍵の追加。** biset のdid:dht root鍵は署名用のEd25519だが、DIDComm v2の暗号化(JWE、ECDH-ES/1PU)はX25519を要求する。`seed.ts`が既にSLIP-0010で複数のサブ鍵パス(Nostr用、PGP用)を派生させているのと同じパターンで、DIDComm用のX25519鍵を一本追加するのが自然。
2. **DID Documentへの`DIDCommMessaging` service追加。** 既存の`_s0`(mail)、`_s1`(AP)と同じ並びで`_s2._did.`のような新しいserviceレコードを足し、エンドポイントURIと上記X25519鍵(recipientKeys)を載せる。
3. **受信用の新規relay(`jmapdidcomm`)。** 「1 relay = 1 protocol」という既存パターンに沿って、DIDCommメッセージを受けるHTTPエンドポイントを持つ新relayを立てる。既存のjmapsmtp/jmapapのコード構造を型として流用可能。

**位置づけ:** AP経由(フェディバース連合、フルの`service`解決+MLS)よりも軽量な、biset同士専用のダイレクトチャンネルとして。段階的に、まずbisetユーザー間(did:dht⇔did:dht)に閉じて検証し、他方式(did:web等)との相互運用は後回しでよい。

---

## 未決事項 / 次に決めるべきこと

- DIDComm本採用 vs Nostr NIP-17による低コスト代替、どちらを先に検証するか
- `jmapdidcomm` relayのメッセージ永続化モデル(mail/APのJMAP Emailモデルにどこまで寄せるか、それとも別モデルにするか)
- X25519鍵のローテーション方針(root鍵はrotation-less設計だが、DIDComm用サブ鍵も同様の無期限運用でよいか)
