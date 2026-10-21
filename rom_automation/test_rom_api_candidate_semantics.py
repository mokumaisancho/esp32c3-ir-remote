#!/usr/bin/env python3
import copy,json,os,unittest
from rom_api_candidate_semantics import audit,execute,formula
class ROMApiSemantics(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  location=os.environ.get("ROM_DOSSIER_JSON")
  if not location:raise unittest.SkipTest("ROM_DOSSIER_JSON only exists in the dedicated full-machine dossier job")
  with open(location,encoding="utf-8") as h:cls.pinned=json.load(h)
 def test_all_pinned_isa_paths_match_independent_formula(self):
  r=audit(self.pinned)
  self.assertEqual(r["test_count"],10576)
  self.assertEqual(r["visited_instruction_count"],16)
  self.assertFalse(r["mismatches"])
  self.assertFalse(r["global_novelty_proven"])
 def test_wrong_candidate_hash_fails_closed(self):
  c=copy.deepcopy(self.pinned)
  c["new_api_candidates"]["rom2_temp_to_power1"]["function_sha256"]="0"*64
  with self.assertRaisesRegex(ValueError,"MACHINE_PROVENANCE_DRIFT"):audit(c)
 def test_branch_target_mutation_cannot_pass(self):
  c=copy.deepcopy(self.pinned)
  for ins in c["new_api_candidates"]["rom2_temp_to_power1"]["instructions"]:
   if ins["pc"]=="0x4003ea04":ins["operands"]="a2, 1"
  with self.assertRaisesRegex(ValueError,"INSTRUCTION_OR_OPERAND_TAMPER"):audit(c)
 def test_changed_quotient_is_refuted_by_differential_suite(self):
  c=copy.deepcopy(self.pinned)
  for ins in c["new_api_candidates"]["rom2_temp_to_power1"]["instructions"]:
   if ins["pc"]=="0x4003ea12":ins["operands"]="a1, 7"
  raw=c["new_api_candidates"]["rom2_temp_to_power1"]["instructions"]
  got,_=execute(raw,-10,0,1)
  self.assertNotEqual(got,formula(-10,0,1))
  with self.assertRaisesRegex(ValueError,"INSTRUCTION_OR_OPERAND_TAMPER"):audit(c)
 def test_signed_wrapping_and_branch_boundary(self):
  self.assertEqual(formula(32768,0,0),0)
  self.assertEqual(formula(0,0,0),0)
  self.assertEqual(formula(5,0,1),1)
  self.assertEqual(formula(5,0,0),0)
if __name__=="__main__":unittest.main()
