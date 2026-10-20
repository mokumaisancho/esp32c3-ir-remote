"""Fail-closed machine-byte JALR local CFG register origin tests."""
import types,unittest
from rom_p0a_cfg_defuse import infer_register_value,predecessors

def ins(pc,value,mnemonic="addi"):
 return types.SimpleNamespace(address=pc,size=4,bytes=value.to_bytes(4,"little"),mnemonic=mnemonic)

def code(base):
 # LUI x5, 0x40000000; ADDI x5,+0x180; ADDI x8,x8,+1; JALR x1,0(x5)
 return [ins(base,0x400002b7,"lui"),ins(base+4,0x18028293),
         ins(base+8,0x00140413),ins(base+12,0x000280e7,"jalr")]

class CFGTests(unittest.TestCase):
 def test_nonadjacent_register_source_passes(self):
  seq=code(0x40001000)
  r=infer_register_value(seq,3,5)
  self.assertEqual(r["value"],0x40000180)
  self.assertEqual(len(r["witnesses"]),2)
 def test_unrelated_register_unchanged(self):
  seq=code(0x40001000)
  self.assertNotIn("value",infer_register_value(seq,3,6))
 def test_unknown_load_blocks(self):
  seq=code(0x40001000)
  seq[2]=ins(0x40001008,0x00002283,"lw")
  self.assertEqual(infer_register_value(seq,3,5)["unresolved"],"LOAD_OR_UNMODELED_REG_WRITE")
 def test_cfg_join_blocks(self):
  # BEQ x0,x0,+8 to skip the middle instruction, causing two predecessors to JALR.
  seq=code(0x40001000)
  seq[1]=ins(0x40001004,0x00000463,"beq")
  self.assertEqual(infer_register_value(seq,3,5)["unresolved"],"CFG_JOIN_OR_NO_PREDECESSOR")
 def test_call_clobber_blocks(self):
  seq=code(0x40001000)
  seq[2]=ins(0x40001008,0x000000ef,"jal")
  self.assertEqual(infer_register_value(seq,3,5)["unresolved"],"CALL_RETURN_BARRIER")
 def test_unknown_opcode_blocks(self):
  seq=code(0x40001000)
  seq[2]=ins(0x40001008,0x0000000b,"unknown")
  self.assertNotIn("value",infer_register_value(seq,3,5))
if __name__=="__main__":unittest.main()
