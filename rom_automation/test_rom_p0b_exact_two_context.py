"""Pinned dual MMIO read machine signature and counterexample tests."""
import unittest
from rom_p0b_exact_two_context import check_machine,CASES,derive_lui_pc
class MMIOExactTwoTests(unittest.TestCase):
 def test_source_pc_derived_from_exact_lui_access_signature(self):
  self.assertEqual(derive_lui_pc("0x4003ba76","b766006083a7461c","LUI_ACCESS"),0x4003ba72)
  self.assertEqual(derive_lui_pc("0x40045474","37470360832707c0","LUI_ACCESS"),0x40045470)
 def test_corrupted_lui_signature_length_rejected(self):
  with self.assertRaisesRegex(RuntimeError,"SOURCE_PATTERN_BYTE_COUNT_MISMATCH"):
   derive_lui_pc("0x4003ba76","b7660060","LUI_ACCESS")
  with self.assertRaisesRegex(RuntimeError,"SOURCE_PATTERN_BYTE_COUNT_MISMATCH"):
   derive_lui_pc("0x4003ba76","b766006083a7461c","LUI_ADDI_ACCESS")
 def test_bytes_equal_exact_are_accepted(self):
  check_machine(bytes.fromhex("b766006083a7461c"),"b766006083a7461c")
  check_machine(bytes.fromhex("37470360832707c0"),"37470360832707c0")
 def test_single_instruction_mutation_fails_closed(self):
  with self.assertRaisesRegex(RuntimeError,"PINNED_ROM_MACHINE_BYTE_MISMATCH"):
   check_machine(bytes.fromhex("b766006083a7461d"),"b766006083a7461c")
 def test_missing_first_lui_fails(self):
  with self.assertRaisesRegex(RuntimeError,"PINNED_ROM_MACHINE_BYTE_MISMATCH"):
   check_machine(bytes.fromhex("83a7461c"),"b766006083a7461c")
 def test_target_callsites_distinct_revisions_and_access(self):
  self.assertEqual(len(CASES),2)
  self.assertEqual(len({c["rev"] for c in CASES}),2)
  self.assertEqual({x["address"] for x in CASES},{"0x600061c4","0x60033c00"})
if __name__=="__main__":unittest.main()
