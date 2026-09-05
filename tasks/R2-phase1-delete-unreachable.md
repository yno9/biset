# R2 (Phase 1): 到達不能コードの削除

対象リポジトリ: `~/biset`（TypeScript / Bun / ブラウザSPA）

**先に `tasks/R1-src-restructure-design.md` を読むこと。** そこに構成変更全体の設計と、
ユーザーが下した決定がある。この作業はその Phase 1 にあたる。

## この作業の位置づけ

`src/` の構成を作り直す（Phase 2）前に、**本番から到達不能なコードを先に消す**。
2,720行を移動してから消すのは二度手間であり、移動の diff に紛れて「消すべきだったもの」が見えなくなる。

**Phase 2（ディレクトリ移動）には着手しないこと。** この作業は削除だけである。

## 前提

- 作業ツリーが clean であること（`git status --porcelain` が空）
- 他のエージェントが動いていないこと（`git log --oneline -5` で確認）

未コミットの変更がある場合は**着手せずに報告すること**。

## 削除するもの（ユーザー決定済み）

### A. mail 一式（削除決定）

```
src/mail/enable-openpgp.ts          63
src/mail/ingress-projector.ts      107
src/mail/ingress-workflow.ts        50
src/mail/openpgp-credential.ts      72
src/mail/openpgp-message.ts         64
src/mail/rfc3156.ts                149
src/mail/rfc5322-builder.ts         56
src/vault/openpgp-credential-reader.ts   39
src/vault/openpgp-credential-sink.ts     24
src/vault/mail-submission-transport.ts   34
```

`src/mail/` はディレクトリごと消える見込み。**残るファイルがあれば報告すること**
（`message-view.ts` `body-text.ts` `rfc5322-headers.ts` `mail-message.ts` などは
到達可能かもしれない。**必ず確認してから消すこと**）。

> 復元の出発点は `tasks/W3-wallet-mail-design-proposal.md` に残る。実装は did.md 側の
> mediator が必要で、このリポジトリ内では動かせない。

**`src/ui/` が `mail` を4箇所 import している**（実測）。UI 側の参照も一緒に外すこと。
UI から機能が消える場合、**markup は残して inert にするのがこのリポジトリの慣習**
（`ui/account/config-page.ts` のヘッダに明記されている）。勝手に markup を削除しないこと。

### B. peer restore / archive import（削除決定）

```
src/vault/restore-workflow.ts           184
src/vault/recovery-archive-file.ts       27
src/vault/recovery-archive-import.ts     33
src/shared/protocol/restore-control-wire.ts  101
```

`src/vault/restore-transfer*.ts` も同系統だが到達可能性リストに出ていない。
**参照を辿って、restore 経路として一体で消せるかを確認すること。**

> ⚠️ **`src/vault/recovery-archive.ts` と `recovery-archive-export.ts` と
> `recovery-archive-rewrap.ts` は消さないこと。** checkpoint が
> `createRecoveryArchiveSnapshot` を使っており、W5 で配線されて生きている。
> 名前が似ているだけで別物である。

### C. 撤去済みサブシステムの残骸

```
src/vault/delivery-outbox.ts        65   （旧 core の HTTP delivery）
src/vault/delivery-sync.ts          74   （同上）
src/vault/ingress-sync.ts           72   （同上）
src/didcomm/webvh-routing-pointer.ts 64  （削除された enableDidComm 由来）
src/vault/didcomm-credential-reader.ts 42（同上）
src/vault/didcomm-credential-sink.ts   25（同上）
src/local-jmap/accounts.ts          69   （リモート JMAP アカウント。配線されたことがない）
src/local-jmap/remote.ts           125   （同上）
src/ui/account/modal.ts             30   （identity-modals 削除で孤立した汎用ヘルパ）
```

## 削除しないもの

| ファイル | 理由 |
|---|---|
| `identity/webvh/create-genesis.ts` `migrate.ts` | **残す側のコードのテスト3件**が、実物の did:webvh log を組み立てる唯一の手段として使っている。消すと resolver のカバレッジごと消える |
| `identity/web/identifier.ts` `mirror.ts` | 上の `create-genesis.ts` 経由でのみ到達する did:web mirror。連鎖的に残る |
| `mimi/anon/identity-link.ts` `anon/pseudonym.ts` `room-policy.ts` | **normal/anon の区別を残すというユーザー決定**（R1 §5） |
| `mls/vendor/crypto/kdf.ts` `signature.ts` | RFC 9420 の vendored fork。upstream diff を保つため触らない |
| `shared/protocol/test-vectors.ts` | テストベクタの定義。テスト専用で正常 |
| `vault/recovery-archive.ts` `-export.ts` `-rewrap.ts` | checkpoint が使用中（上記） |

## 判断を保留し、報告してほしいもの

次の3つは削除候補に見えるが、**勝手に消さずに分類だけ報告すること**。

```
src/mls/keypackage-store.ts        142   MLS KeyPackage プール。現行 Self Vault は external join を使うので不要だが、将来機能の下ごしらえの可能性
src/mls/mimi-client-routing.ts      83   MIMI deployment の選択。normal/anon を残す決定と関係するかもしれない
src/mls/mimi-room-migration.ts     109   anon room への移行機構。同上
src/vault/didcomm-device-key-reader.ts 33  旧 revokeDevice（seed 経路）が唯一の読み手だった
src/vault/didcomm-device-key-sink.ts   26  同上
```

後ろ2つは seed 経路と一緒に呼び出し元が消えている可能性が高いが、
**wallet 経路のデバイス削除（`removeMimiVaultDevice`）が使っていないか必ず確認すること。**

## 進め方

1. **削除の前に `grep -rn` で参照を全部洗う**（`src/` `test/` `scripts/` すべて）。
   想定外の参照が見つかったら、消さずに報告すること。
2. A → B → C の順に、**カテゴリごとにコミットを分ける**。
3. 1カテゴリ消すごとに `bun run typecheck` と `bun run test` を回す。
4. 削除対象を検証していたテストは一緒に消す。**消したテストは報告に列挙すること。**
   削除対象と無関係なテストは消さない。

## 絶対ルール

- **「残す」リストのものを巻き添えにしない。**
- 型が通らなくなった箇所を、動かないダミー実装で埋めない。消せないなら消さずに報告する。
- 「ついでの」リファクタ・改名・バグ修正は禁止。気づいたことは報告に書く。
- **Phase 2（ディレクトリ移動）には着手しない。**
- 迷ったら勝手に決めず、その項目を飛ばして報告する。

## 検証（各カテゴリごと + 最後に全部）

```
bun run typecheck
bun run test           # 全通過。落ちたら隠さず出力ごと報告
bun run build          # `bun build` 単体は不可。必ず `bun run build`
node --check dist/app.js
bun run knip           # exit 1 が正常
bun run reachability --quiet
bun run build:didcomm-mediator && bun run build:mail-plugin && bun run build:mimi
```

`bun run reachability` は本番エントリからの到達可能性を見る独自チェック
（knip はテストが import したファイルを "used" と見なすのでこの層を捕まえられない）。
着手前の値は **170/291 reachable、tests-only 32、nothing 6**。
削除後、**tests-only と nothing が大きく減るはず**。前後の数値と、
**新たにそこへ落ちたファイル**を報告すること（それは「消し残した部品」である）。

## git

- 自分が変更・削除したファイルだけを `git add` / `git rm`。`git add -A` は使わない。
- **`dist/` は stage しない。**
- コミットは `git commit <paths> -F <messagefile>` の形（pathspec 付き）。
- カテゴリごとにコミットを分ける。
- コミットメッセージ末尾に `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` を付ける。

## 報告

1. カテゴリ別の削除ファイル数・行数
2. **消さなかったもの**とその理由（想定外の参照があった等）
3. 判断保留リスト5件の分類結果
4. 消したテストの一覧
5. `knip` / `reachability` の before / after と、新たに孤立したファイル
6. 検証コマンドの結果
7. 気づいたが手を出さなかった問題

## 参考

- `tasks/R1-src-restructure-design.md` — 構成変更全体の設計と決定事項
- `PLAN-simplify.md` — これまでの簡素化の経緯
