# W5: checkpoint の KEK を MLS group 由来に載せ替える

対象リポジトリ: `~/biset`（TypeScript / Bun / ブラウザSPA）

## 背景と決定

MIMI Self Vault の checkpoint は、暗号化に使う KEK を `masterSeed` から導出していた。
native login の廃止（2026-09-05）で `masterSeed` が存在しなくなり、**checkpoint の作成・復元が停止している**。

代替として3案を検討し、**ユーザーが (b) を選択した**（2026-09-05）:

| | 方式 | 代償 |
|---|---|---|
| (a) | did.md が identity 共通 secret を capability で提供 | did.md 側の仕様と実装が必要 |
| **(b)** | **checkpoint KEK を MLS group に wrap（SegmentKey と同じ方式）** | **新デバイス追加時に既存デバイスが1台オンラインである必要**。全デバイス喪失＝復旧不可 |
| (c) | checkpoint を諦める | hub の delivery ログが無限に伸びる |

> **不採用になった案について**: 一度 `src/wallet/did-md-oauth.ts` の `vaultSecret` を使う案が挙がったが、
> あれは `crypto.getRandomValues` で**端末登録ごとに生成される端末ローカルの乱数**であり、
> identity 共通ではない。別デバイスからは復元できないので使えない。同じ誤りを繰り返さないこと。

## 現状の構造（調査済み）

`src/vault/vault-checkpoint.ts`（101行）は既に**二層構造**になっている:

- ランダムな `dataKey` が snapshot 本体を AES-GCM で暗号化する
- `kek` が `dataKey` を包む（`wrappedDataKey`）
- envelope は `{ version, wrapNonce, wrappedDataKey, dataNonce, ciphertext, ciphertextHash, plaintextLength }`

**したがって変更は「包む鍵を差し替える」だけで済む。** 本体の暗号化層には触らない。

現在 v1（退役 Coordinator 用、`coordinatorUrl` を KEK に混ぜる）と v2（`masterSeed` 由来）が読める。
v1/v2 の**書き込み経路はもう存在しない**（呼び出し元が native login と一緒に消えた）。

## 設計（v3 envelope）

### 包む鍵は VEK にする

`SegmentKey` の wrap と同じ鍵を使う。`src/mls/vault-epoch.ts` の
`MlsVaultEpochKeyResolver.deriveVaultEpochKey(identityId, selfGroupId, epoch)` が VEK を返す。

v3 envelope は、どの VEK で開けるかを示すため `selfGroupId` と `epoch` を持つ:

```
{
  version: 3,
  selfGroupId, epoch,            // この VEK で wrappedDataKey を開く
  wrapNonce, wrappedDataKey,     // dataKey を VEK(selfGroupId, epoch) で包んだもの
  dataNonce, ciphertext, ciphertextHash, plaintextLength
}
```

AAD には既存 v2 と同様 `vaultId` と `coveredSeq` を含め、さらに `selfGroupId` と `epoch` も含めること
（epoch のすり替えを検知するため）。ラベルは `biset/vault-checkpoint/aad/v3` のように**必ず v3 で分離**する。

### ⚠️ 最重要の制約: VEK は現行 epoch でしか導出できない

`deriveVaultEpochKey` は **`selfGroupId`/`epoch` が現行と一致しなければ例外を投げる**
（`vault-epoch.ts` の該当箇所を必ず読むこと）。これは意図的な設計で、MLS の forward secrecy とも整合する。

したがって:

- **epoch N で作った checkpoint は、epoch が N+1 に進んだ時点で誰も開けなくなる**（作った本人も含む）
- 新デバイスが参加すると epoch は必ず進む。つまり**参加直後の新デバイスは、既存の checkpoint を開けない**

これは (b) を選んだ以上避けられない性質であり、**バグではない**。解決は次項。

### 再ラップではなく「作り直し」で解決する

古い VEK を再導出する道は無い（forward secrecy）。しかし checkpoint は
**Vault 全体をローカルに持つデバイスならいつでも作り直せる**。既存デバイスが新 epoch で作り直せばよい。

`src/main.ts` には既に checkpoint を定期的に作り直すゲートがある。現在の条件はおおむね
「最新 checkpoint manifest を見ていない」かつ「今回の同期に gaps が無い」である。

**このゲートに「既存 checkpoint の epoch が現行 epoch と違うなら作り直す」を追加すること。**
そうしないと、新デバイスが参加して epoch が進んでも、古い checkpoint が存在する限り作り直されず、
新デバイスは永久に復元できない。

### 開けない checkpoint は落ちずに skip する

新デバイスが古い epoch の checkpoint を引いたとき、**例外で同期ループを止めてはいけない**。
`src/vault/mimi-vault-sync.ts` には既に `gaps`（`MimiVaultSyncGap`）という構造化された報告機構があり、
`applyCheckpoints` は checkpoint restore の失敗を skip-and-log で扱う。**その経路に合流させること。**
新しい `kind` を足すのが適切なら足してよい（例: `checkpoint-epoch-unavailable`）。

## やること

1. `vault-checkpoint.ts` に v3 を実装する
   - `createVaultCheckpoint(vek, snapshot, { vaultId, coveredSeq, selfGroupId, epoch })`
   - `openVaultCheckpoint(vek, payload, { vaultId, coveredSeq })` — envelope の `selfGroupId`/`epoch` を検証
   - **v1/v2 の読み取り経路は削除してよい**（書き手が存在せず、`masterSeed` も無いので開けない）。
     削除する場合はコミットメッセージで理由を述べること
   - `Coordinator` を含む古い関数名（`createPortableCoordinatorCheckpoint` など）はこの機会に改名してよい。
     中身は MIMI Self Vault のものであり、Coordinator は撤去済みのサブシステムである
2. wallet 経路（`src/main.ts` の `configureWalletAccountIfPresent` 内）に checkpoint の作成と復元を配線する
   - VEK は既存の crypto boundary から取れる（`buildWalletVaultCryptoBoundary` が返す resolver 系を確認すること）
   - 作成ゲートに epoch 不一致条件を追加（上記）
3. 復元失敗を `gaps` に載せる（上記）
4. **回帰テストを書く**

## 必須のテスト

**それぞれ「実装前に落ちること」を確認するまでが1件の作業。**

1. epoch N で作った checkpoint が、同じ epoch の VEK で開けること
2. **epoch N で作った checkpoint が、epoch N+1 の VEK では開けないこと**（forward secrecy の確認）
3. AAD 不一致（`vaultId` / `coveredSeq` / `selfGroupId` / `epoch` のいずれかを改竄）で開かないこと
4. 開けない checkpoint が**例外ではなく `gaps` として報告される**こと（同期ループが止まらないこと）
5. 既存 checkpoint の epoch が現行と違うとき、作成ゲートが作り直しを許可すること

判定は具体的に行うこと。`toThrow(TypeError)` のような緩い判定は、実装前でも通ってしまう例が実際にあった。

## 絶対ルール

- **本体の暗号化層（`dataKey` による snapshot の AES-GCM）には触らない。** 変更は KEK 層だけ。
- envelope のバージョンとラベルを必ず分離する（`/v3`）。既存ラベルを使い回さない。
- 既存テストを1本も消さない・弱めない。
- 「ついでの」リファクタは禁止。気づいたことは報告に書く。
- **`vaultSecret` を使わない**（冒頭の理由）。
- 迷ったら勝手に決めず、止まって報告する。

## 触ってよいファイル

`src/vault/vault-checkpoint.ts`、`src/vault/mimi-vault-sync.ts`、`src/main.ts`、
`src/mls/vault-epoch.ts`（読むのは自由、変更は必要最小限）、`test/` 配下の新規テスト。
これら以外の変更が必要になったら、変更せずに止まって報告すること。

## 検証（すべて必須）

```
bun run typecheck
bun run test           # 全通過
bun run build          # `bun build` 単体は不可。必ず `bun run build`
node --check dist/app.js
bun run reachability --quiet
```

`bun run reachability` の `reached by nothing` から `src/vault/vault-checkpoint.ts` が**消えるはず**
（配線されて本番から到達可能になるため）。消えなければ配線漏れ。

## git

- 自分が変更したファイルだけを `git add`。`dist/` は stage しない。
- コミットは `git commit <paths> -F <messagefile>` の形（pathspec 付き）。
- コミットメッセージ末尾に `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` を付ける。

## 報告

- v3 envelope の最終的な形
- v1/v2 を削除したか、した/しなかった理由
- 作成ゲートの epoch 条件をどう書いたか
- 各テストが「実装前に落ちること」をどう確認したか
- `reachability` の before / after
- 気づいたが手を出さなかった問題

## 参考

- `PLAN-simplify.md` §3.6 — native login 廃止の経緯と決定事項
- `ARC.md` §6・§9 — Self Vault MLS group と VEK、配送モデル
- `src/vault/crypto.ts` — SegmentKey を VEK で包む既存の実装。今回の手本
