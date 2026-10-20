"""Pinned dual MMIO read machine signature and counterexample tests."""
import unittest
from rom_p0b_exact_two_context import check_machine,CASES
class MMIOExactTwoTests(unittest.TestCase):
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
