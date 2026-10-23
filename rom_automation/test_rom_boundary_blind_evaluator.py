#!/usr/bin/env python3
"""ROM-003 E2: evaluator negative controls; real 3-rev scorer runs in its own CI job."""
import copy,json,os,pathlib,unittest
from rom_boundary_blind_evaluator import score,evaluate,REVS

def mock_data():
 c={};g={}
 for rev in REVS:
  g[rev]={"schema":"ROM003_SEALED_SYMBOL_ORACLE_V1","revision":rev,
    "symbol_function_records":[{"entry_pc":hex(0x40000000+4*i),"size_bytes":4,"name":f"f{i}"} for i in range(1002)]+
      [{"entry_pc":hex(0x40000000),"size_bytes":4,"name":"renamed_alias"}]}
  c[rev]={"schema":"ROM003_E1_BYTE_ONLY_CANDIDATES_V1","revision":rev,
     "true_function_boundary_verified":False,"novel_usable_API_verified":False,
     "rooted_entry_candidates":["0x40000000"],
     "ranked_raw_link_baseline":["0x40000000","0x40000008","0x40001ffe"],
     "ranked_possible_entries":["0x40000000","0x40000008","0x40001ffe"],
     "unresolved":[],"instructions_rooted":10,"rooted_call_count":1,
     "unrooted_halfword_candidate_count":3}
 return c,g

class SealedOracleTest(unittest.TestCase):
 def test_exact_entry_and_unjudged_are_separate(self):
  result=score(["0x40000000","0x40000002","0x40000004"],{0x40000000,0x40000004})
  self.assertEqual(result["correct_labeled_entries_any_rank"],2)
  self.assertEqual(result["unjudged_other_candidate_addresses"],1)
  self.assertIsNone(result["false_positive_rate_verified"])
 def test_wrong_interior_basic_block_does_not_match(self):
  result=score(["0x40000002"],{0x40000000})
  self.assertEqual(result["hit_at_100"],0)
 def test_alias_deduplicated_three_rev(self):
  c,g=mock_data();out=evaluate(c,g)
  self.assertEqual(out["positive_entry_count_across_revisions"],1002*3)
  for r in out["revisions"]:
   self.assertEqual(r["duplicate_alias_records"],1)
   self.assertEqual(r["scores"]["rooted_calls"]["hit_at_10"],1)
 def test_injected_symbol_oracle_field_fails(self):
  c,g=mock_data();c[REVS[1]]["symbol_function_records"]=[{"entry_pc":"0x40000000"}]
  with self.assertRaisesRegex(ValueError,"GOLDEN_SYMBOL_RECORD_LEAK_IN_CANDIDATE"):
   evaluate(c,g)
 def test_false_novelty_proof_fails(self):
  c,g=mock_data();c[REVS[0]]["novel_usable_API_verified"]=True
  with self.assertRaisesRegex(ValueError,"FALSE_DISCOVERY_CERTIFICATION"):
   evaluate(c,g)
 def test_wrong_revision_fails(self):
  c,g=mock_data();g[REVS[1]]["revision"]=REVS[0]
  with self.assertRaisesRegex(ValueError,"REVISION_OR_SCHEMA_MISMATCH"):
   evaluate(c,g)
 def test_rooted_missing_from_candidates_fails(self):
  c,g=mock_data();c[REVS[1]]["rooted_entry_candidates"]=["0x4000dd00"]
  with self.assertRaisesRegex(ValueError,"ROOTED_CANDIDATE_LOST_WITHOUT_REASON"):
   evaluate(c,g)
 def test_empty_oracle_fails(self):
  c,g=mock_data();g[REVS[0]]["symbol_function_records"]=[]
  with self.assertRaisesRegex(ValueError,"INSUFFICIENT_GOLDEN_BOUNDARIES"):
   evaluate(c,g)
 def test_duplicate_candidate_is_not_multiple_hits(self):
  result=score(["0x40000000","0x40000000","0x40000000"],{0x40000000})
  self.assertEqual(result["hit_at_10"],1)
  self.assertEqual(result["ranked_candidates"],1)
 def test_invalid_pc_raises(self):
  with self.assertRaisesRegex(ValueError,"CANDIDATE_PC_FORMAT"):
   score(["MALICIOUS_NAME"],{0x40000000})
 def test_real_candidate_and_oracle_artifacts(self):
  cdir=os.environ.get("ROM003_E2_CANDIDATE_DIR")
  gdir=os.environ.get("ROM003_E2_ORACLE_DIR")
  if not cdir or not gdir:self.skipTest("Not in real CI scorer job")
  c={r:json.loads((pathlib.Path(cdir)/(r+".json")).read_text()) for r in REVS}
  g={r:json.loads((pathlib.Path(gdir)/(r+".json")).read_text()) for r in REVS}
  out=evaluate(c,g)
  self.assertEqual(len(out["revisions"]),3)
  self.assertEqual(out["actual_new_usable_ROM_APIs"],0)
  self.assertTrue(all(row["duplicate_alias_records"]==18 for row in out["revisions"]))
if __name__=="__main__":unittest.main()
