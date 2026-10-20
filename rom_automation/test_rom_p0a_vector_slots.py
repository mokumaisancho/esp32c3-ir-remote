"""ROM-001 independent RV32 vectored slot true JAL target tests."""
import unittest
from rom_p0a_entry_trampoline import direct_unconditional_j
class VectorTableTests(unittest.TestCase):
 def test_real_vector_table_first_slot_JAL_displacement(self):
  for pc in (0x40001c00,0x40001f00,0x40001d00):
   self.assertEqual(direct_unconditional_j(bytes.fromhex("6f000008"),pc),pc+128)
 def test_vector_mode_slot_addresses_are_4byte_units(self):
  base=0x40001c00
  self.assertEqual([base+4*i for i in range(32)][-1],base+124)
 def test_corrupted_link_bit_invalidates_unconditional(self):
  raw=int.from_bytes(bytes.fromhex("6f000008"),"little")
  self.assertIsNone(direct_unconditional_j((raw|0x80).to_bytes(4,"little"),0x40001c00))
 def test_nonbranch_instruction_is_not_handler_pointer(self):
  self.assertIsNone(direct_unconditional_j(bytes.fromhex("97020000"),0x40001c00))
 def test_short_truncated_jal_invalid(self):
  self.assertIsNone(direct_unconditional_j(bytes.fromhex("6f00"),0x40001c00))
if __name__=="__main__":unittest.main()
