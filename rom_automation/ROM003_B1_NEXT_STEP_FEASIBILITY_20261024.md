# ROM-003 / B1 次工程の実現可能性ゲート — 2026-10-24

原課題: 公開情報に記載のない、**実際に呼び出せるESP32-C3 ROM機能の独立実証**。次工程: 252個の関数範囲外候補への生バイト上の「呼出し」260本を再評価し、32bit命令の途中に見える11本を除く249本の未分類参照から、**独立した入口/CFG到達経路の有無**を判定する。

## 結論と確度
- **未知機能の発見を保証する手段はない**。未知の到達経路がゼロでも、グラフ欠落、未モデル化割込み/間接呼び出し、単なるデータのどれか特定できないことがある。
- **固定スコープのPOCを完了し、GO/NO-GOを記録する工程は構成できる**。ただしRV32Cの実測によるPoCの妥当性はまだ未検証。
- **既存研究を十分見たという旧判断は不適切だった**。少なくとも2026年のAmace（Superset CFG + pre-disassembly backward analysis）が直接関連していることが今回新たに確認された。

## 追加した最重要研究・公開実装

1. **Nguyen et al., Analyzing Bytes: Pre-Disassembly Static Binary Analysis (PLDI 2026)**, https://doi.org/10.1145/3808292 — すべての可能な命令位置を事前に保持するsuperset CFG、逆方向のstack depthとcallee-saved register保存解析で正しい命令開始を絞り込む。全offsetについてO(n)の解析を目標とする。**最遠距離探索より今回の擬似C.JAL混入/未知入口検査に直接一致。** 公開コード https://github.com/nhuhuan/amace 。コード実験はx86系・x86_64 CPU・16GB RAM・100GB storage前提、**RV32Cに直接適用可能とは未実証**。全面Docker環境をMacに導入しない。
2. **Wijayadi et al., Evaluating Disassembly Errors With Only Binaries (AsiaCCS 2025 / TraceBin)**, https://arxiv.org/abs/2506.20109 — ソース無しのバイナリを実行トレースで検査。静的CFGで到達が不明でも、実際のPC観測が独立した証拠になる。ただし実行していない経路の不存在は示さない。ARM/x86など他ISAの結果をRV32へ転用しない。
3. **Tsang et al., FFXE: Dynamic Control Flow Graph Recovery for Embedded Firmware Binaries (USENIX 2024)**, https://www.usenix.org/conference/usenixsecurity24/presentation/tsang — volatile/コールバックに依存する間接分岐を選択的な強制実行で解析。静的失敗の後の条件付き代案。即時採用せず、ESP32-C3のMMIOモデル・ROMリビジョンの準備と安全性が必須。
4. **Pang et al., Ground Truth for Binary Disassembly is Not Easy (USENIX 2022)**, https://www.usenix.org/conference/usenixsecurity22/presentation/pang-chengbin — ELF関数名/サイズだけを完全な独立真値として誤解してはいけない。今までのE0/E2の評価・実機分離を継続。
5. **RISC-V C extension official spec**, https://docs.riscv.org/reference/isa/v20260120/unpriv/c-st-ext.html — IALIGN=16で、16/32ビット命令が半語境界に混在。既知関数の通常の線形復号が32ビットとした位置での疑似C.JALは標準経路のcall根拠ではないが、別入口からの重複実行を**論理的に排除したわけではない**。

## 確実性を上げる単一の最小POC（未実装）

**B1-POC目的:** 249の未分類「呼出し元」参照に対し、**命令解釈の整合性と既知入口からの到達可能性のうち証拠のあるものだけ**を識別し、改良アルゴリズムを採用するか決める。真の未知API数の正確な推定は目的に含めない。

1. **対象固定:** 既存の3ROM SHA、249の参照(source PC+raw bytes+target PC)、11の32-bit途中にある疑似C.JAL、既知CALL/RETの独立コントロールを固定。rev違いは混ぜない。生バイトonly候補解析は、関数開始oracleから完全分離。
2. **既存実装を優先:** `rom_boundary_byte_frontier.py`、`rom_p0a_cfg_defuse.py`、既存のROM-001直接分岐・間接分岐成果物、Capstone==5.0.6を再利用。命令境界と前方CFG証拠だけでは評価不能な対象に絞る。
3. **Amaceの概念だけ局所移植:** ROM全実行セクションを半語ごとに仮復号し、可能な前駆/後継を保持したsuperset-CFGを作る。RV32C SP保存、呼出し/ret、callee-saved register状態の**保守的**逆方向分析を行い、249 source PCsを **REACHABLE_WITH_WITNESS / CONTRADICTED_STANDARD_DECODE / UNKNOWN** に分類。UNKNOWNを不在の証拠と誤認しない。最遠距離スコアの調整禁止。
4. **同じ資源のベースライン:** 既存rooted DFS、単純なraw-halfword scan、既存strict-JALR CFG。既知callの再発見と11疑似call排除をnegative/controlとして含める。現物の「正例の真の未知API」は未確認なので未知API precisionは算出しない。
5. **STOP/GO:** 実ROM SHA・入力隔離・テストが通らなければERROR/FAILED。新規独立証拠が確認でき、かつ単純ベースラインより効果的なら根拠付き候補だけ次のprior-art審査へ。再現できる証拠が増えなければ**静的手法はNO-GO**とし、それ以上249箇所を繰り返し総当たりしない。実機/エミュレータによるPC証拠へ移行するか、原課題をBLOCKEDのまま閉じる。

### 必要なAC
- AC-B1-1: 同じ249入力と元の11 negを固定し、全レコードに一意のID・rev・PC・raw・証拠由来を付与。アドレスだけでは別機能の証明にならない。
- AC-B1-2: 11個の疑似callに独立実行根拠無しでPROVENを付けない。復号で別の解釈を許すときはUNKNOWN。
- AC-B1-3: 既知のコール正例を正解漏洩なく保持し、原CFG/baselineとの recall・検査コストを保存。正解の関数境界を候補構築に使用しない。
- AC-B1-4: 全249に証拠付き決定/UNKNOWNの理由を残す。UNREACHABLEを「ROMに存在しない」に読み替えない。
- AC-B1-5: GitHub Actions CIと別ジョブ評価に、原始バイト照合、命令変異テスト、result JSON SHA、真偽証拠を記録。閾値を結果後に変更しない。

## 未充足前提とリスク

- **形式上の問題:** 249は「参照・見かけの呼出し元」の数であり、249個の新機能・ユニーク関数ではない。世代の複製を除外する。
- **構造上の問題:** 現行`rooted_walk`はELF `e_entry`だけを始点とし、割り込み・ROM exported call・未解決JALR/CSRなどを部分的に残す。グラフの非到達＝現実の非到達ではない。
- **解釈上の問題:** 既存22bit/16bit解釈の誤用を避け、RVC IALIGN=16、通常の命令列の途中への任意飛び込みは機械語の別経路による実証が必要。
- **計算量上の問題:** O(n)はAmace側の特定抽象解析の性質。移植したPython実装やRV32C対応がO(n)になる保証は無い。高コスト実験の前に小規模実データを検査。
- **学術的な結論:** 「正確性優先で質問・調査・検証回数を最小化する」という目的の下で、249件をひとつずつ手で調べる・x86向けDocker環境をそのまま全導入する・Ghidraで全範囲を再分析することは、当面採用しない。

**本ファイルは調査・工程判断であり、Amace-RV32C移植や新たな到達先を検証済みと主張しない。原課題のSTATUSはBLOCKED、確認済みの新ROM APIは0件のまま。**
