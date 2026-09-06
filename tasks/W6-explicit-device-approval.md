# W6: 新端末追加に既存端末の明示承認を要求する ＋ 強制リセット

Status: **設計文書**。実装の承認は未取得。
作成: 2026-09-06（ユーザー決定に基づく）

## 決定事項

> 新端末の追加時、明示的に従来端末の approve を求めることにしよう。approve がなければ、
> そもそも端末を追加できない。ただ、なにかのきっかけで従来端末にアクセスできなくなると詰むので、
> 強制リセット機能もあわせて追加する。その場合、新端末が唯一の有効端末としてフレッシュスタートする。

## 背景

現在、新端末は did.md Wallet 認証（DID control の証明）だけで Self Vault MLS group に
**自己承認で参加できる**（`joinMimiVaultRoom` → `joinGroupExternally`、external commit）。
既存端末は一切関与しない。

これは「DID を制御している」ことの証明だけで端末が増える設計であり、
Wallet の OAuth フローが何らかの形で悪用された場合、**既存端末の誰も気づかないまま**
新しい端末が Self Vault に参加できてしまう。

## 設計: 通常の参加は既存端末の Add を要求する

MLS には2つの参加方式がある。現在使っているのは前者:

| 方式 | 誰が動くか | 既存メンバーの関与 |
|---|---|---|
| External Commit（現状） | 新端末が自分で参加コミットを作る | **無し**（GroupInfo と did:webvh 証明があれば成立） |
| **Add Proposal + Commit（変更後）** | **既存メンバーが** 新端末の KeyPackage を使って参加コミットを作る | **必須** |

### フロー

1. 新端末は did.md Wallet 認証を終える（現状と同じ）。この時点では **room に参加しない**
2. 新端末は自分の MLS KeyPackage を生成し（`keypackage-store.ts` の `generateOwnKeyPackage`、既存）、
   MIMI hub へ公開する（`POST /keyPackage` 相当のエンドポイント——**正確なルート名は要検証**、下記）
3. 新端末は UI に「既存端末での承認待ち」を表示し、参加が成立するまで待つ
4. 既存端末は、通常の Self Vault 同期ラウンド（SSE watch でトリガーされる、`main.ts` 既存の仕組み）の中で、
   **自分の identity 宛に未消費の KeyPackage が無いか**を確認する（`GET /keyMaterial/{targetUser}`、既存エンドポイント）。
   まだ room member になっていない KeyPackage を見つけたら、それを「承認待ちの参加要求」として UI に出す
   （端末の fingerprint / JKT を表示し、Approve / Deny）
5. 利用者が Approve すると、既存端末は `addMembers(state, [keyPackage])`（`group.ts`、既存）で
   Add proposal + commit を作り、通常の commit submission 経路（`POST /update/{roomId}`、
   `removeMimiVaultDevice` が Remove で使っているのと同じ経路）で送信する
6. 新端末は Welcome を受け取り、参加が成立する

### 実装前に検証が必要な項目（推測で埋めない）

- **KeyPackage 公開の正確なエンドポイント名**（`src/server/mimi/http.ts` と `src/protocol/mimi/wire.ts` を読むこと）
- **まだ member でない端末が、自分宛の Welcome が届いたことをどう知るか。**
  既存の SSE watch（`watchMimiVaultDeliveries`）は room member 向けの認可（`requester` に visible credential が要る）を
  前提にしている可能性が高く、**参加前の端末は同じ経路を使えない**。
  KeyPackage を公開した端末が Welcome の到着をポーリングする、別の軽量な口が要るかもしれない
- Deny した場合の KeyPackage の扱い（放置すると再利用されうる。明示的に破棄する経路が要る）

## 設計: 強制リセット（既存端末に一切アクセスできない場合）

既存端末が全滅した場合の**唯一の脱出口**。上記の承認フローを迂回し、
did.md Wallet の DID control 証明だけで完結させる——ここは意図的に**現状と同じ信頼レベル**に戻す。

### フロー

1. 新端末は既存 room への参加を試みず、`createMimiVaultRoom`（**既存の関数、そのまま流用可能**——
   現在は「初回の identity 作成時」に使われているものと同じ処理）で、
   **新しい Self Vault room を、自分を唯一の member として作成する**
2. 新しい room の URI で `routing.json` の `mimiVaultRoom` ポインタを**上書き**する
   （did.md Wallet が認可する通常の routing.json 更新と同じ権限レベル）
3. 旧 room の内容（＝旧 Vault の全履歴）は**破棄される**。新端末は空の Vault からフレッシュスタートする

### 波及: 取り残された旧端末をどう扱うか

強制リセット後、もし旧端末のどれかが後からオンラインに戻ってきたら、
自分の room ID が routing.json の指す room と食い違っていることに気づく必要がある。

**現状のコードは boot 時に routing.json を読んで一度 room に join したら、以後ポインタの変化を
再チェックしない可能性が高い**（要確認）。この検知が無いと、取り残された端末は
**自分だけの古い room に書き込み続け、他の誰にも届かないまま気づかない**という
静かな split-brain が起きる。

→ 同期ラウンドで routing.json の `mimiVaultRoom` ポインタを都度確認し、
自分の room ID と食い違っていたら「この端末のデータは他の場所で行われたリセットにより
無効になりました」と明示的に UI に出す経路が要る。**これは強制リセット機能の一部として実装すること**
（無いと強制リセットが新しい形の事故を生む）。

### UI 上の要件

- 強制リセットは**破壊的で不可逆**（他のすべての端末が履歴にアクセスできなくなる）。
  「他の端末に本当にアクセスできないか」を強く確認する文言を要求すること
- 通常の「新端末を追加する」導線とは明確に分離し、誤操作を防ぐこと

## この2つの関係

| | 認可の根拠 | 既存端末の関与 |
|---|---|---|
| 通常の参加 | DID control（Wallet）**＋既存端末の承認** | 必須 |
| 強制リセット | DID control（Wallet）のみ | **意図的に無し**（これが脱出口の存在意義） |

強制リセットの信頼レベルは現状の「通常参加」と同じ（DID control のみ）。
**格下げではなく、稀な破壊的操作として隔離しただけ**である。

## 実装順序の提案

1. **既存端末の routing.json ポインタ再チェック**（強制リセットの前提。無いと split-brain の検知ができない）
2. **通常参加の Add-based 化**（KeyPackage 公開 → 承認 UI → `addMembers`）。ここは protocol 詳細の検証が先
3. **強制リセット機能**（`createMimiVaultRoom` の流用 + routing.json 上書き + 破壊的確認 UI）

1 は 2・3 のどちらにも安全上必要なので最初にやる。2 と 3 は独立して進められる。

## 触れるファイル（見込み）

- `src/client/mimi/vault-room.ts` — `joinMimiVaultRoom` の分岐、強制リセット用の新関数
- `src/client/mls/group.ts` — 変更不要見込み（`addMembers` 既存）。要確認
- `src/client/app/main.ts` — 承認 UI のトリガー、routing.json ポインタ再チェックの配線
- `src/client/app/ui/account/*` — 承認プロンプト、強制リセットの導線と確認 UI
- `src/server/mimi/http.ts` / `src/protocol/mimi/wire.ts` — KeyPackage 公開エンドポイントの確認（変更不要かもしれない）

## 参考

- `ARC.md` §9.4 — checkpoint の epoch 制約と、既存端末経由の自動復旧の仕組み（この機能とは別レイヤー）
- `ARC.md` §5 — 現行の enrollment フロー（did.md Wallet OAuth）
