"""Independent fail-closed triage tests; never approve silicon behavior."""
import json
import os
import pathlib
import unittest
from decision_gate import evaluate
from semantic_frontier import analyze_rows, build, modeled_names
G = pathlib.Path(os.environ["ROM_GHIDRA_ZIP"])
M = pathlib.Path(os.environ["ROM_MACHINE_ZIP"])
REVIEW = pathlib.Path(__file__).with_name("reviewed_semantics.json")

class SemanticFrontierTests(unittest.TestCase):
    def test_return_is_not_external_indirect_transfer(self):
        rows = [
            {"mnemonic":"lw","operands":"a0, 0(a5)"},
            {"mnemonic":"c.jr","operands":"ra"},
        ]
        c = analyze_rows(rows)
        self.assertEqual(c["returns"], 1)
        self.assertEqual(c.get("nonreturn_indirect_transfers",0), 0)

    def test_dynamic_indirect_is_distinct_from_return(self):
        rows = [
            {"mnemonic":"c.jalr","operands":"a5"},
            {"mnemonic":"beq","operands":"a0, zero, 0x4000"},
            {"mnemonic":"c.jr","operands":"ra"},
        ]
        c = analyze_rows(rows)
        self.assertEqual(c["returns"], 1)
        self.assertEqual(c["nonreturn_indirect_transfers"], 1)
        self.assertEqual(c["conditional_branches"],1)

    def test_static_effect_union_source_not_invented(self):
        leaf, exact = modeled_names()
        self.assertEqual((len(leaf),len(exact),len(leaf|exact)), (25,19,32))

    def test_actual_original_88_no_new_discovery_or_silicon_claim(self):
        state = evaluate(G, M, REVIEW)
        result = build(M, state)
        self.assertEqual(result["awaiting_bounded_effect"], 56)
        self.assertEqual(len(result["items"]), 56)
        self.assertEqual(len(set(x["name"] for x in result["items"])),56)
        self.assertEqual(result["silicon_experiments_run"],0)
        self.assertEqual(result["independent_review_approved"],0)
        self.assertTrue(all(x["novel_api_proven"] is False for x in result["items"]))
        self.assertEqual(result, build(M, state))

    def test_tampered_identity_fail_closed(self):
        state = evaluate(G, M, REVIEW)
        state["candidate_count"] = 89
        with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED:CANONICAL_88"):
            build(M,state)
if __name__ == "__main__":
    unittest.main()
