# ESP32-C3 ROM 自動調査ワークフロー

対象原課題: `ESP32C3-ROM-001`。動作基盤はGitHub Actionsであり、MacやChatGPTの一時サンドボックスを常時稼働させる必要はありません。

## トリガー

- `workflow_dispatch`：GitHub Actions画面から手動起動
- `push`：`rom_automation/*.py`・審査JSON・ワークフロー変更
- `workflow_run`：既存「ESP32-C3 ROM 88 candidate Ghidra review」が成功すると起動。GitHubの当該runからGhidra成果物を取得し、そのSHA-256を照合

## 実行順序

1. ROM・Ghidraの以前の成果物をSHA-256付きで取得。更新Ghidraの場合はGitHubが報告する当該artifactのdigestと照合。
2. 88候補の識別子と、3 revisionにおけるROM機械語、関数アドレス、Ghidra逆コンパイルを全件照合。
3. `rom_automation/output/state.json` に88件のタスクと判定状態を生成。
4. 追加の意味検証が必要な優先8件を選び、全機械命令・Ghidra擬似C・実験条件をJSON資料として出力。
5. **88件すべての意味判定が独立審査済み**で、審査JSONのSHA-256が別途承認・固定された場合に限り次のジョブを実行し、88候補以外のROM関数を棚卸し。

意味判断はLLMによる自動分類に依存しません。名前の存在やCIの成功から新規機能を自動認定しません。新しい証拠がない場合、同じバッチを無制限に再試行せず `WAITING_FOR_INDEPENDENT_PROOF` を返します。

実機上の因果実験は、このワークフローからは自動実行しません。ESP32-C3のrev101か他revかを実測で確認した安全な検証環境・認可が必要です。

## 検証実績

- [最終CI実行（5件のゲート試験PASS）](https://github.com/mokumaisancho/esp32c3-ir-remote/actions/runs/39259636313)
- [JSON状態、優先8件の全命令・擬似C、全量ログ](https://github.com/mokumaisancho/esp32c3-ir-remote/actions/runs/39259636313/artifacts/12190040693)
- 実行結果：名前・機械語証拠照合88/88。意味検証未了88/88。後続探索は正しくスキップ。
- `workflow_run` での新規Ghidra成果物の取り込みはコード実装済みだが、**イベント起動の実機CI試験は未実施**。

GitHub Actions成果物にはリポジトリの保持期限（本ワークフローでは90日）があります。実証された長期判断は別途既存の非公開正本リポジトリに記録してください。
