"""P0-A independent bit encoded unconditional JAL/C.J roots."""
import unittest
from rom_p0a_entry_trampoline import direct_unconditional_j,enumerate_bounded_gap_cfg
class ELFRootTests(unittest.TestCase):
 def test_small_boot_root_cfg_reaches_real_instructions_and_stops_on_ret(self):
  base=0x40000000
  code=bytes.fromhex("6f00400001458280") # JAL +4, C.LI, C.JR RA
  sec={"sh_addr":base,"sh_size":len(code),"data":code}
  class FakeSection:
   def __getitem__(self,k):return sec[k]
   def data(self):return sec["data"]
  r=enumerate_bounded_gap_cfg(b"",None,[FakeSection()],[(base,base+len(code))],[],[base])
  self.assertGreaterEqual(r["visited_gap_instructions"],2)
  self.assertFalse(r["hit_node_limit"])
  self.assertGreaterEqual(r["unresolved_terminators_count"],1)
 def test_symbol_boundary_stops_boot_root_cfg(self):
  base=0x40000000;raw=bytes.fromhex("6f00400001458280")
  class Sect:
   def __getitem__(self,k):return {"sh_addr":base,"sh_size":len(raw)}[k]
   def data(self):return raw
  r=enumerate_bounded_gap_cfg(b"",None,[Sect()],[(base,base+4)],[(base+4,base+8)],[base])
  self.assertEqual(r["visited_gap_instructions"],1)
  self.assertIn(hex(base+4),r["named_function_target_boundaries"])
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
