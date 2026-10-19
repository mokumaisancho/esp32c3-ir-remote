"""ROM-001 SPI init: Ghidra AST safety and raw-ROM net-effect tests."""
import os,pathlib,unittest
from spi_slave_rom_effects import evaluate,ghidra_net_effect,initial_memory
from decision_gate import REVS
M=pathlib.Path(os.environ["ROM_MACHINE_ZIP"])
G=pathlib.Path(os.environ["ROM_GHIDRA_ZIP"])
class RomSPIInitTests(unittest.TestCase):
 def test_original_3_revisions(self):
  result=evaluate(M,G)
  self.assertEqual(result["vectors"],90)
  self.assertEqual(result["negative_operand_mutations"],3)
  self.assertEqual(len(result["revisions"]),3)
  self.assertTrue(result["revision_code_identical"])
  self.assertFalse(result["silicon_verified"])
  self.assertFalse(result["intermediate_writes_independently_certified"])
  self.assertFalse(result["independent_semantic_review_approved"])
  for r in REVS:
   self.assertEqual(result["revisions"][r]["machine_stores"],47)
   self.assertEqual(result["revisions"][r]["ghidra_C_assignments"],43)
 def test_unsafe_ast_refused(self):
  snippet="\n".join(["_DAT_ram_6003f0e0 = __import__('os');"]*43)
  with self.assertRaisesRegex(RuntimeError,"UNSUPPORTED_GHIDRA_C_AST"):
   ghidra_net_effect(snippet,initial_memory(1))
 def test_incomplete_pseudocode_refused(self):
  with self.assertRaisesRegex(RuntimeError,"GHIDRA_ASSIGNMENT_COUNT_NOT_43"):
   ghidra_net_effect("_DAT_ram_6003f0e0 = 0;",initial_memory(1))
if __name__=="__main__":unittest.main()
