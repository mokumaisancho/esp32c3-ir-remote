"""ROM-001 P0-A checks with independent encoded RV32IMC signed branch fixtures."""
import unittest
from rom_gap_branch_seeds import branch_target,select_nonoverlapping

def b_enc(off,funct3=0):
 u=off&0x1fff
 return (0x63|(funct3<<12)|(((u>>11)&1)<<7)
  |(((u>>1)&15)<<8)|(((u>>5)&63)<<25)|(((u>>12)&1)<<31)).to_bytes(4,"little")

def cb_enc(off,funct3=6):
 u=off&0x1ff
 w=1|(funct3<<13)|(((u>>8)&1)<<12)|(((u>>3)&3)<<10)|(((u>>6)&3)<<5)|(((u>>1)&3)<<3)|(((u>>5)&1)<<2)
 return w.to_bytes(2,"little")

class GapSeedTests(unittest.TestCase):
 def test_rv32_branch_forward_backward(self):
  for off in (2,4,16,254,-2,-8,-256):
   target=branch_target(b_enc(off),0x40012000)
   self.assertEqual(target,(0x40012000+off,"B_RV32",False))
 def test_rvc_branch_forward_backward(self):
  for off in (2,4,8,16,32,254,-2,-16,-256):
   target=branch_target(cb_enc(off),0x40012000)
   self.assertEqual(target,(0x40012000+off,"CB_RVC",False))
 def test_unsupported_riscv_branch_funct3_rejected(self):
  self.assertIsNone(branch_target(b_enc(4,2),0x40012000))
  self.assertIsNone(branch_target(b_enc(4,3),0x40012000))
 def test_opcode_mutation_never_creates_false_branch(self):
  raw=bytearray(b_enc(32));raw[0]=(raw[0]&0x80)|0x13
  self.assertIsNone(branch_target(bytes(raw),0x40012000))
 def test_paper_weighted_interval_dp_not_greedy(self):
  v=[{"start":0,"stop":10,"weight":11,"anchor_id":"a"},
   {"start":0,"stop":5,"weight":7,"anchor_id":"b"},
   {"start":5,"stop":10,"weight":7,"anchor_id":"c"}]
  r=select_nonoverlapping(v)
  self.assertEqual([x["anchor_id"] for x in r],["b","c"])
  self.assertEqual(sum(x["weight"] for x in r),14)
 def test_mutant_overlap_is_not_double_counted(self):
  v=[{"start":100,"stop":105,"weight":5,"anchor_id":"x"},
     {"start":104,"stop":110,"weight":100,"anchor_id":"y"}]
  self.assertEqual([x["anchor_id"] for x in select_nonoverlapping(v)],["y"])
 def test_zero_candidate_allowed(self):
  self.assertEqual(select_nonoverlapping([]),[])
if __name__=="__main__":unittest.main()
