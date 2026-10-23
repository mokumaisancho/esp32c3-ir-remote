# ROM-003 解決可能性調査・依存関係・実施順（2026-10-24）

対象: [ROM-003研究 Issue #5](https://github.com/mokumaisancho/esp32c3-ir-remote/issues/5) / [実装Epic #6](https://github.com/mokumaisancho/esp32c3-ir-remote/issues/6) / ESP32-C3 ROM rev0, rev101, rev3。

**結論：未知APIを「探す」前に、未知関数の真の開始位置をROM機械語だけから再発見できる、正解漏洩のない再現可能な評価を完成させる。** 最遠距離探索に新たな重みを付ける作業は保留。

## 0. 過去の実測と今回の追加検証を明確に区分

### 既存ROM-003結果（2026-10-23）
- ELFの `STT_FUNC` で構築した関数間グラフ：1,968 / 2,100 / 2,040ノード、直接辺1,147 / 1,206 / 1,165。
- 直接関数間辺を持たないノード：1,222 / 1,277 / 1,278（全体の約60%）。
- 上位100件・固定ラベル隠蔽（各rev 124正例）合計：near_known 51、reverse 50、dual-root 45、degree 44、random 28、farthest 1。
- 5分割感度合計（3rev×5ランキング、正例延べ1,846件）：near 308、reverse 276、dual 261、degree 239、random 123、farthest 16。
- **これらは「名前」を隠しただけ。入口アドレスと関数範囲は既知で、真の未知関数発見率ではない。** ROM世代間には共通コードがあるため、3つを独立実験と見なさない。
- [既存CI](https://github.com/mokumaisancho/esp32c3-ir-remote/actions/runs/39960263500) / [旧正本](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/state/ROM003_DISTANCE_POC_20261023.json)。

### E0について本ターンに実施した実証
- 新規 [`rom_boundary_source_seal.py`](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/rom_boundary_source_seal.py)：SHA-256固定の公式ROM tar → `ELF`内の実行可能セクション（`SHT_PROGBITS`・`SHF_EXECINSTR`）の生バイト、アドレス、ROMエントリのみを探索入力へ出力。関数名・個別関数開始/サイズは独立した評価用JSONへ出力。
- [GitHub CI・11/11 PASS](https://github.com/mokumaisancho/esp32c3-ir-remote/actions/runs/39985074956)。実際のELFの `.strtab` の関数名を1文字変更しても、探索入力JSON全体は不変、評価側JSONは変化するという負例テストも通過。
- 3revの探索用実行可能バイト列：363,582 / 367,052 / 365,968バイト。独立した評価側に保持する関数シンボル記録：1,986 / 2,118 / 2,058件。**重複した別名が各rev 18件**あり、独立した開始・サイズ組は1,968 / 2,100 / 2,040件とCIで一致した。E2では別名を二重に正解計上しない。
- CI artifacts：candidate bytes `12515240963`、evaluator-only oracle `12515560388`、ログ/マニフェスト `12514747073`。**これは論理的な入力の分離であり、完全なアクセス制御の証明ではない。** ROMはまだ再逆アセンブルしていないので新入口発見数は未測定。

## 1. なぜ残課題が解決しにくいのか

| 根本の不足 | 過去コードでの具体的な問題 | 先に満たすべき前提 |
|---|---|---|
| 評価の正解混入 | `rom_fast_graph.make_symbol_index` が関数の開始/終了位置を使い、`rom_gap_branch_seeds` と `rom_p0a_indirect_roots.build_gaps` もシンボル境界を使う | バイトだけの探索入力と評価側オラクルの分離（E0）。既存のsymbol gapを「ブラインド未知領域」に流用禁止 |
| 実行可能領域≠コード | RV32Cでは16bit/32bit命令とデータが混在し得る。正しい命令に見えるだけでは関数でない | 根拠付き入口→再帰的復号→符号付き/typedなCODE/DATA/UNKNOWN（E1） |
| 入口と基本ブロックを混同 | 直接分岐の飛び先は一般にbasic blockであり独立関数でない。tailcall・例外や非標準復帰を誤解しやすい | call-link/入口種別/戻りの根拠（E1/E3） |
| 欠損した間接辺 | 既存グラフの約60%が孤立。間接分岐やテーブルジャンプは一部のみ復元 | `AUIPC/JALR`、RV32Cデータフロー、読み込み元からの証拠をもつ辺だけ昇格（E3） |
| 正解そのものが不確実 | 既存のGhidra/ELF範囲不一致は9件。名前付き関数でも埋め込みtrap、非標準の復帰を含む | 独立オラクルの信頼度・除外理由を設定し、複数ツールの合意を真理と誤認しない（E2） |
| 世代差・重複 | リビジョン間でコード継承、アドレス移動、関数名の別名がある | 同一コードのグループ分割と正規化署名（E3） |
| 「未知＝新規API」という飛躍 | 152件の名前ベース候補は公開先行資料で説明可能。実機の動作を観測していない | 入口発見→ABI→公開先行例→実機機能という4段階の独立判定（E4） |

## 2. 小課題への分割・依存関係・完了条件

```
固定ROMアーカイブ
   |
   +-- E0 探索用生バイト / 評価オラクル分離 [P0: 静的入力生成PASS]
         |
         +-- E1 根拠付きRV32ICコード開始点・基本ブロック復元 [P0]
         |      |
         |      +-- E3 間接制御フローの厳格復元 [P1]
         |      |
         +-- E2 関数境界そのものを隠した厳格評価 [P0]
                |
                +-- E3 世代間重複/署名正規化
                       |
                       +-- E4 探索順位の再検証・新規性判断 [P1]
```

| ID / Issue | 達成目標（AC） | まだ足りないもの | 実現可能性 | 停止/分岐条件 |
|---|---|---|---|---|
| [E0 #7](https://github.com/mokumaisancho/esp32c3-ir-remote/issues/7) | 候補器へ関数名/入口情報を渡さない。実ELFシンボル名変異で探索入力不変 | 実装した隔離は論理的。候補実行をオラクル無し別環境に置く強化は後続 | **高：基本機能CI実証済み** | 漏洩検出は最優先で修正。E1へ進んでよい |
| [E1 #8](https://github.com/mokumaisancho/esp32c3-ir-remote/issues/8) | RV32IC 16/32-bitからPC付き根拠でコード候補抽出。基本ブロックと関数入口を分離 | シンボルを参照しない再帰走査、コード/データの識別、停止/未知理由 | **中〜高：既存復号関数は利用可能、入口精度未実証** | 基本ブロック誤昇格・逆アセンブル解釈不能を必ず報告 |
| [E2 #9](https://github.com/mokumaisancho/esp32c3-ir-remote/issues/9) | 正しい関数開始PCをブラインド再発見。正例・確認済み負例・未判定を混ぜない | 入口の層別サンプル、独立オラクル品質判定、候補器との厳格分離 | **中：ELFオラクル候補はあるが全てを真値と見なせない** | 独立した負例と漏洩防止が揃わなければ率を公表しない |
| [E3 #10](https://github.com/mokumaisancho/esp32c3-ir-remote/issues/10) | 間接辺は命令/定数伝播の証拠で昇格。各世代を正規化して重複検出 | 読み取り専用テーブル/レジスタのdef-use、join/tailcall処理、アドレス補正 | **中〜低：解けない間接制御は残る** | 比較試験で改善しなければ追究を停止しUNKNOWN維持 |
| [E4 #11](https://github.com/mokumaisancho/esp32c3-ir-remote/issues/11) | 境界発見→実際の呼出し可能性→文献上の新規性を別々に判定 | E2本物の比較結果、先行研究照合、最終段階の実機検証 | **ツール評価は高、新しいシリコンAPIの実証は低/未確定** | 既存手法に改善がなければ距離ランキングは不採用。API新規性は実証できなければ0件 |

実装順はE0→E1→E2で固定。E3に着手するのは、E2が証拠不足の箇所を実測で特定してから。エラーを潰さず無期限に続けることを禁止する。

## 3. 実用OSS／論文の対応表（直接利用と研究上の参考を区別）

| 先行研究・OSS | 今回解決する論点 | 適合性・採用判断 |
|---|---|---|
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | 独立したRV32IMC復号、関数境界・逆コンパイルの異論を調べる | **高：既存リポですでに採用実績あり。** ただし[12.0のRISCV32 ELF言語自動認識問題](https://github.com/NationalSecurityAgency/ghidra/issues/8873)に注意し、明示的なISA指定＋version pinを使用。Ghidra出力＝絶対正解とはしない |
| [Capstone](https://github.com/capstone-engine/capstone) | RV32IMC機械語・RVCの16/32bit再帰復号 | **高：現行コードで5.0.6を使用済み。** [6.xで`CS_MODE_RISCVC`の名称が変更](https://github.com/capstone-engine/capstone/issues/2977)。新規POCでは5.0.6に固定 |
| [angr CFGFast](https://api.angr.io/en/latest/analyses/cfg.html) | 関数境界探索、再帰的CFG、間接ジャンプ解決、FakeRet | **アルゴリズム設計に有効だが直接組込みは保留。** [現行PyVEXのlibvex対応ISA](https://api.angr.io/projects/pyvex/en/latest/_modules/pyvex/lifting/libvex.html)にはRISCV64がありRISCV32がない。RV32C対応実証が先 |
| [DDisasm](https://github.com/GrammaTech/ddisasm) / [Datalog Disassembly (USENIX 2020)](https://www.grammatech.com/publication/datalog-disassembly/) | 競合するコード/データ推論を証拠事実として統合し、アドホック判断を減らす | **方式は援用可能、実装の直接再利用は不可に近い。** README記載の対応ISAにRISC-Vがない。PoC初期段階で依存しない |
| [BYTEWEIGHT (USENIX 2014)](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-bao.pdf) | 名前・呼出し元がなくても機械語パターンから関数開始位置候補を作る | **代替研究として中。** 学習済み重みのRISC-V移植と別訓練データが前提。決定論的機械語解析を優先 |
| [DeepDi (USENIX 2022)](https://www.usenix.org/conference/usenixsecurity22/presentation/yu-sheng) | 命令間の関係を使う分類、関数入口復元 | **研究参考。** 元論文の結果がESP32-C3 RV32Cでそのまま再現する根拠なし。NNの導入は採用済み閾値を破る改善がある場合のみ |
| [Ground Truth for Binary Disassembly is Not Easy (USENIX 2022)](https://www.usenix.org/conference/usenixsecurity22/presentation/pang-chengbin) | 正解データの完全性/精度の欠陥とデータ漏洩 | **E0/E2の必須参考。** ELF単独の開始PCが常に正しいと見なさず根拠を区分 |
| [REFuSe-Bench (NeurIPS 2024)](https://papers.nips.cc/paper_files/paper/2024/hash/2663c994c84a79b338bca613fe1ae223-Abstract-Datasets_and_Benchmarks_Track.html) | 単純な生バイト基準法を比較対象に置く重要性 | **E2の評価設計に採用。** ただし論文は機能類似性が主題であり、このROMの未知入口復元の性能を保証しない |
| [Rizin](https://github.com/rizinorg/rizin) | CLI中心の別実装との結果比較 | **選択的。** 当該版でROM ELFのRV32Cと入口推定が動作するかスモークテストを先に実行。重い基盤統合はしない |

## 4. 失敗しないための実験計画（これから実施するAC）

1. **E0入力契約**：公式ROM tar SHAを照合した生バイトだけを探索側へ渡す。別の評価プロセスがSTT_FUNCを参照して合否判定。既存`rom_fast_graph`の正本ノードを新しい候補器へ渡したら失敗扱い。論理上の分離を越える敵対的分離は未達と明示。
2. **E1最小解析**：ELF `e_entry`（現在検証済みの`0x40000000`）から出発し、生バイトでJAL/分岐/RVCからの再帰的エッジを作る。分岐命令が存在しても別関数とは見なさず、`LINKED_CALL_TARGET`、`BASIC_BLOCK_TARGET`、`INDIRECT_UNKNOWN`を分離する。
3. **E2ブラインド評価**：入力に個別関数PC/サイズが混入していないことをチェック。既存正例は直接呼出・リーフ・割り込み・間接関数等に層別。9件のELF/Ghidra境界不一致は真値不確定群として別管理。人手で作った実行可能領域内のRISC-V命令に見えるデータは負例とし、ROM内未判定データは勝手に負例に数えない。
4. **ベースライン**：byte-only halfword scan、rooted recursive CFG、次数、near-known、reverse。ブラインドPCの完全一致と1件を検証するまでの探索候補数（cost@k）を計測する。多始点「最遠距離」は既に負例なので補助比較のみ。
5. **E2→E3移行ゲート**：真正の入口再発見が確認でき、かつ判定できる負例も含む評価で新方式が**最大の既存ベースラインを同等の検査予算・偽陽性水準で上回る**場合にのみ詳細化する。事前の目標値として、ブラインド検証でrecall@100の**5ポイント以上の改善**かつ確認済み負例で偽陽性増加なしを設ける（現在は未達/未測定。後から閾値を修正して結果を再評価しない）。
6. **E4実機と公開新規性**：ELF未知入口、意味が未知、公開未収載、呼出し可能、ハードウェアの新機能はそれぞれ別の判定。後三者は機械語だけでは保証しない。

## 5. 何がまだ足りず、いつ方向転換するか

| 外的依存・不足 | 補う最低限の成果 | 解決できない場合 |
|---|---|---|
| 入口候補生成器がまだない | E1の生バイト直接分岐・基本ブロック復元の最小コード | 候補なしを成功扱いせず到達不能理由と予算を出して終了 |
| 一致するELF開始位置も真値として怪しい例 | Ghidra差異9件、trap/mret/特殊復帰を別の検証群に分ける | その群をclean evaluationから除外し信頼度を表示 |
| 本当の負例が不足 | 合成の`.text`内データ＋別セクション根拠の明らかな非コード、可能なら独立手動サンプル | 自称precision/FPRを出さず確認済み負例あたりの誤検出のみ報告 |
| 欠落した間接ジャンプ | 命令・レジスタ書込履歴・ベースレジスタ・読み取り元テーブルの照合証拠 | 保守的なUNKNOWN。推測だけでグラフに辺を足さない |
| 同一バイトコードの世代重複 | 関数正規化SHAや命令CFG署名のクラスタを学習/評価群で分割 | 独立汎化の実証は不可と記録 |
| 実機での安全な確認 | revision-matched実機＋読取主体の観測可能なプローブ | ROM構造解析だけ完了。新しいハードウェア機能の発見宣言は禁止 |

### 成功を阻害しない停止条件
- E1で十分な真正候補が出ない場合、距離重みの探索を継続せず、入口root・ベクタと間接経路の不足に戻る。
- E2で正解漏洩が見つかればスコアは無効。データ分離を修正し、独立した新しい固定holdoutで再評価。
- E2で単純な生バイト手法に勝てなければ複雑なNN・グラフ最適化の実装を止める。
- E4で独立した新規性確認ができなければ、**新規API発見数0**のまま研究課題だけを保存。

**実施済みと未実施の境界：** E0の生バイト/評価オラクル分離のみ現段階でCI実証済み。E1〜E4、実機による未知機能の実証は未実施。作業日数や有効性の確率を、証拠がない段階で確定値として主張しない。
