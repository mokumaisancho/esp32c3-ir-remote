"""Pinned full-body AGC POC reproducibility and fail-closed boundaries."""
import os,pathlib,unittest
from agc_rom_effects import NAMES,REVS,vector,independent_register_equations,evaluate
M=pathlib.Path(os.environ["ROM_MACHINE_ZIP"])
G=pathlib.Path(os.environ["ROM_GHIDRA_ZIP"])
class RomAGCEffectTests(unittest.TestCase):
 def test_all_revision_effects_and_negative_controls(self):
  result=evaluate(M,G)
  self.assertEqual(result["name"],NAMES[0])
  self.assertEqual(result["vectors"],300)
  self.assertEqual(result["negative_operand_mutations"],3)
  self.assertEqual(len(result["revisions"]),3)
  self.assertFalse(result["physical_silicon_verified"])
  self.assertFalse(result["independent_review_approved"])
  self.assertFalse(result["novel_api_verified"])
  self.assertEqual([result["revisions"][r]["ordered_machine_store_count"] for r in REVS],[26,7,6])
 def test_revision_specific_agc_parameters(self):
  mem,a0,a1=vector(4)
  outcomes=[independent_register_equations(rev,mem,a0,a1) for rev in REVS]
  self.assertNotEqual(outcomes[0][0x6001c13c],outcomes[1][0x6001c13c])
  self.assertEqual(outcomes[0][0x6001c064],0x3032030)
  self.assertEqual(outcomes[2][0x6001c134],mem[0x6001c134])
 def test_input_a1_changes_agc_field(self):
  mem,a0,_=vector(5)
  out0=independent_register_equations(REVS[2],mem,a0,0)
  out1=independent_register_equations(REVS[2],mem,a0,1)
  self.assertNotEqual(out0[0x6001c0a4],out1[0x6001c0a4])
if __name__=="__main__":unittest.main()
