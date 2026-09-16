# did:webvh と Tor / DIDComm Mediator による分散型・非対称通信アーキテクチャ 技術メモ

## 1. 概要 (Overview)

本ドキュメントは、以下の2つのコアコンポーネントを中心とした分散型・プライバシー保護コミュニケーションシステムの設計・技術議論をまとめたものである。

1. **`did:webvh` の `updatekey` からの Tor v3 `.onion` アドレス暗号的導出**
   - 1つの鍵ペア（Ed25519）から DID 管理権限（Update Key）、改ざん防止検証用の SCID、および Tor ネットワーク上のアクセスエンドポイント（`.onion`）を統一的に導出する手法。
2. **DIDComm Mediator による HTTP / Tor `.onion` トランスポート・ブリッジング**
   - 異なるネットワーク環境（Tor匿名領域のAliceと、クリアネットHTTPS領域のBob）の間を、E2E暗号化を維持したまま中継・仲介するレジリエントなメッセージング構造。

---

## 2. `did:webvh` の `updatekey` から Tor v3 `.onion` アドレスの導出

### 2.1 暗号鍵と表現形式の関係

`did:webvh` のジェネシスエントリ（`did.jsonl`）に記録される `updateKeys` は、DID の更新署名を検証するための公開鍵（通常 Ed25519）である。

* **`updateKey` (Multibase/Multicodec 形式)**:
  - 構造: `[Multicodec Header (Ed25519 pub: 0xed01)] + [Raw Public Key (32 bytes)]`
  - エンコード: Base58btc (`z6M...`)
  - 実質的には `did:key:z6M...` の公開鍵データそのものを指す。
* **Tor v3 `.onion` アドレス**:
  - 構造: `[Raw Public Key (32 bytes)] + [Checksum (2 bytes)] + [Version (1 byte: 0x03)]`
  - エンコード: Base32 (小文字, 56文字) + `.onion`

どちらも**ベースとなる生データは「32バイトの Ed25519 公開鍵」**であるため、単一の Ed25519 鍵ペアから相互に変換・導出が可能である。

### 2.2 導出アルゴリズム (Ed25519 $ightarrow$ `.onion`)

1. **生鍵データの抽出演算**:
   Multibase形式の `updateKey` （例: `z6M...`）から Base58btc デコードを行い、先頭の Multicodec プレフィックス（2バイト: `0xed01`）を取り除いて 32バイトの Raw Ed25519 Public Key ($K_{pub}$) を抽出する。
2. **Tor v3 チェックサム算出**:
   $$	ext{Checksum} = 	ext{SHA3-256}(".onion\ checksum" \parallel K_{pub} \parallel \mathtt{0x03})[0..2]$$
3. **アドレス組み立て**:
   $$	ext{Address} = 	ext{Base32 Encode}(K_{pub} \parallel 	ext{Checksum} \parallel \mathtt{0x03}) + ".onion"$$

### 2.3 `did:webvh` 識別子への統合

導出した `.onion` アドレスを `did:webvh` の位置識別子（Domain）に組み込むことで、**Self-Certifying（完全自己証明型）DID** を構成できる。

* **DID 形式**:
  `did:webvh:<SCID>:<onion-address>.onion`
* **性質**:
  - **SCID**: 初期エントリ（`updateKeys` 等含む）のハッシュ値から算出。
  - **Domain**: `updatekey` から直接算出した `.onion` アドレス。
  - **結果**: 識別子名、配信サーバーのIPアドレス（Tor Onion）、およびDIDの更新所有権がすべて同一の暗号鍵に束ねられた、検閲耐性の高い識別子となる。

### 2.4 セキュリティ・プライバシー上のトレードオフ

* **アイデンティティの紐付け（Linkability）**:
  Web上の DID アイデンティティと Tor 隠しサービスが同一人物運営であることが暗号的に証明される。意図的な証明には有用だが、Tor 側の完全な匿名性を保ちたい場合にはアンチパターンとなる。
* **鍵の再利用（Key Reuse）のリスク**:
  万が一、Tor サーバー側で秘密鍵が漏洩した場合、DID のルート管理権限も同時に喪失する。ドメイン分離の原則からは、本来プロトコルごとに別の鍵を生成し、証明書等で関連付けを行う方が望ましい。

---

## 3. Pure Client-side (JS/Wasm) での Tor (.onion) 解決

ブラウザ（Chrome/Firefox等）は標準で raw TCP ソケットを扱えないため、JavaScript 内から直接 `.onion` へ接続することはできない。Pure Client-side でこれを解決するための技術スタックは以下の通り。

```
[ Browser Web Worker (Wasm Arti) ]
       │ WebSockets (wss://)
       ▼
[ WebSocket Bridge / Pluggable Transport ]
       │ Raw TCP (Tor Protocol)
       ▼
[ Tor Network (Guard -> Middle -> HSDir / RP) ] ──> [ Target .onion ]
```

### 3.1 技術コンポーネント

* **Arti (Rust / WebAssembly)**:
  Tor 公式の Rust 実装である `arti` を `wasm32-unknown-unknown` 用にコンパイルし、ブラウザ内で Onion 巡回・サーキット構築・暗号化処理を実行する。
* **WebSocket Bridge**:
  ブラウザの WebSocket 通信を受け取り、Tor ネットワークの raw TCP へ中継するトランスポート層。暗号化セルをそのまま透過させるため、ブリッジ自体が通信内容や最終宛先を解読することはできない。

### 3.2 ブラウザ内での実行フローと最適化

1. **Web Worker 運用**:
   AES-CTR や Ed25519 等の大量の暗号演算による UI スレッドのフリーズを防ぐため、Wasm Arti インスタンスは必ず Web Worker 内で動かす。
2. **キャッシュ機構 (IndexedDB)**:
   初回起動時の Directory Consensus 取得（数MB）およびサーキット確立には 5〜15秒を要する。コンセンサス情報や暗号状態を `IndexedDB` に永続化し、2回目以降の bootstrap 時間を大幅に短縮する。

---

## 4. DIDComm Mediator による HTTP / Tor `.onion` トランスポート・ブリッジ

`did:webvh` や Tor を使う Alice（Tor利用）と、一般的な HTTPS サーバーを使う Bob（クリアネット利用）の間でメッセージを送受信するため、**DIDComm Mediator（メディエーター）** がトランスポート変換ハブとして機能する。

### 4.1 通信アーキテクチャ概要

* **DIDComm のレイヤー分離**:
  DIDComm は「アプリケーションデータ」「E2E暗号化パケット（JWE / Envelope）」「転送プロトコル（HTTP/Tor/WebSocket）」が完全に独立している。
* **Mediator の役割**:
  最外層の `Forward` メッセージ（ルーター宛てヘッダー）のみを復号・解読し、インナーペイロード（E2E暗号化された本文）には触れずに別プロトコルへ転送（または蓄積）する。

```
+-------------------+             +--------------------+             +-------------------+
|    Alice (Tor)    | <== Tor ==> | DIDComm Mediator   | <== HTTP ==>|    Bob (HTTPS)    |
| .onion / Wasm-Arti|             | (onion + https URL)|             |   Clearnet Host   |
+-------------------+             +--------------------+             +-------------------+
```

### 4.2 双方向メッセージング・シーケンス

#### A. Bob (HTTPS) $ightarrow$ Alice (Tor) の送信
1. **宛先参照**: Bob は Alice の DID ドキュメントから、エンドポイントとして Mediator の `https://` URL を取得。
2. **Forward 送信**: Bob は Alice 宛に E2E 暗号化したメッセージを生成し、Mediator 宛の `Forward` メッセージで包んで Mediator の `https://` エンドポイントへ POST。
3. **Store (Inbound)**: Mediator は `Forward` を解読し、「Alice 宛」であることを確認して内部のメッセージキュー（Inbox）に保管。
4. **Pickup (Tor)**: Alice は Tor 経由で Mediator の `.onion` エンドポイントへ接続し、DIDComm **Pickup Protocol** を用いてメッセージを安全にプル（取得）する。

#### B. Alice (Tor) $ightarrow$ Bob (HTTPS) の送信
1. **Forward 依頼**: Alice は Bob 宛に E2E 暗号化したメッセージを作成し、Mediator 宛の `Forward` メッセージで包む。Tor 経由で Mediator の `.onion` エンドポイントへ送信。
2. **Relay (HTTPS)**: Mediator は `Forward` メッセージから Bob の HTTPS エンドポイントを特定し、標準的な HTTP POST で転送。
3. **Direct Delivery**: Bob は自身の HTTPS サーバーで直接メッセージを受信。

### 4.3 プライバシーおよびセキュリティ保証

1. **完全 E2EE (End-to-End Encryption)**:
   Mediator は鍵を持っていないため、Alice ⇔ Bob 間の通信本文（インナーペイロード）を盗聴・改ざんすることは不可能。
2. **メタデータ（IP/ネットワーク領域）の隠蔽**:
   Bob 側から見えるIPアドレスやドメインは Mediator のもののみであり、Alice が Tor ネットワーク上に潜伏している事実や Alice のリアル IP は完全に保護される。
3. **ストア・アンド・フォワード (Store-and-Forward)**:
   Tor クライアント（Alice）がモバイル環境等で一時的にオフラインになっても、Mediator がメッセージを保持するため、非同期メッセージングが問題なく機能する。

---

## 5. まとめと構成図

本アーキテクチャにより、**「自己同一性の暗号的証明（`did:webvh`）」**、**「ネットワーク匿名性（Tor `.onion`）」**、および**「標準ネットワークとの相互運用性（DIDComm Mediator）」** を高度に融合させたWebベースメッセージング基盤が成立する。

```
[ Alice: Web App / Wasm-Arti ]
  │  DID: did:webvh:<SCID>:<onion-address>.onion
  │  Key: updateKey (Ed25519) <--- 暗号的同一 ---> Tor Address (.onion)
  │
  │ (Tor WebSocket / WSS)
  ▼
[ DIDComm Mediator Node ]
  ├── Onion Endpoint : http://[mediator-onion].onion/didcomm
  └── HTTPS Endpoint : https://mediator.example.com/didcomm
  │
  │ (Clearnet HTTP POST)
  ▼
[ Bob: Clearnet Host ]
  │  DID: did:web:example.com:bob
  └── Endpoint : https://example.com/bob/didcomm
```
