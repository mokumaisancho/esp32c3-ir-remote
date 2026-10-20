"""P0-A independent bit encoded unconditional JAL/C.J roots."""
import unittest
from rom_p0a_entry_trampoline import direct_unconditional_j
class ELFRootTests(unittest.TestCase):
 def test_elf_entry_real_rev0_raw_j(self):
  self.assertEqual(direct_unconditional_j(bytes.fromhex("6f101059"),0x40000000),0x40001d90)
 def test_elf_entry_real_rev101_raw_j(self):
  self.assertEqual(direct_unconditional_j(bytes.fromhex("6f200009"),0x40000000),0x40002090)
 def test_elf_entry_real_rev3_raw_j(self):
  self.assertEqual(direct_unconditional_j(bytes.fromhex("6f101069"),0x40000000),0x40001e90)
 def test_mutated_link_register_is_not_unconditional_j(self):
  w=int.from_bytes(bytes.fromhex("6f101059"),"little")
  self.assertIsNone(direct_unconditional_j((w|(1<<7)).to_bytes(4,"little"),0x40000000))
 def test_mutated_opcode_is_not_j(self):
  w=int.from_bytes(bytes.fromhex("6f101059"),"little")
  self.assertIsNone(direct_unconditional_j(((w&~127)|0x13).to_bytes(4,"little"),0x40000000))
 def test_jalr_indirect_not_treated_as_direct(self):
  self.assertIsNone(direct_unconditional_j(bytes.fromhex("67800000"),0x40000000))
if __name__=="__main__":unittest.main()
