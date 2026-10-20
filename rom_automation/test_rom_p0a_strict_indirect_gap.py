"""Unit tests for soundness of conservative static JALR gap target checks."""
import types,unittest
from rom_strict_indirect import candidate_call
def mk(pc,w):
 return types.SimpleNamespace(address=pc,size=4,bytes=w.to_bytes(4,"little"),mnemonic="")
class GapTests(unittest.TestCase):
 def test_positive_and_mutated_register(self):
  pc=0x40001000
  seq=[mk(pc,0x400002b7),mk(pc+4,0x18028293),mk(pc+8,0x000280e7)]
  r=candidate_call(seq,2,None,{0x40000180:["GAP"]})
  self.assertIsNotNone(r)
  self.assertEqual(r["resolved_callee"],"0x40000180")
  self.assertFalse(r["dynamic_execution_proven"])
  self.assertIsNone(candidate_call(seq,2,None,{0x40000182:["NEIGHBOR"]}))
  seq[2]=mk(pc+8,0x000300e7)
  self.assertIsNone(candidate_call(seq,2,None,{0x40000180:["GAP"]}))
 def test_noncontiguous_provenance_rejected(self):
  pc=0x40001000
  seq=[mk(pc,0x400002b7),mk(pc+8,0x18028293),mk(pc+12,0x000280e7)]
  self.assertIsNone(candidate_call(seq,2,None,{0x40000180:["GAP"]}))
if __name__=="__main__":unittest.main()
