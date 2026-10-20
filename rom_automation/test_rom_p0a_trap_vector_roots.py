"""ROM-001 pure byte-level CSR write and adjacent vector-value counterexamples."""
import unittest
from rom_p0a_trap_vector_roots import csr_vector_write,resolve_adjacent_value

def enc_csr(csr,funct3,rs1,rd=0):
 w=(csr<<20)|(rs1<<15)|(funct3<<12)|(rd<<7)|0x73
 return w.to_bytes(4,"little")
def enc_lui(reg,upper):
 return (upper|(reg<<7)|0x37).to_bytes(4,"little")
def enc_auipc(reg,upper):
 return (upper|(reg<<7)|0x17).to_bytes(4,"little")
def enc_addi(reg,rs,imm):
 return (((imm&0xfff)<<20)|(rs<<15)|(reg<<7)|0x13).to_bytes(4,"little")

class TrapRootsTests(unittest.TestCase):
 def test_mtvec_true_csrrw(self):
  a=csr_vector_write(enc_csr(0x305,1,5))
  self.assertEqual(a["name"],"mtvec")
  self.assertEqual(a["writer_value_register"],5)
  self.assertTrue(a["is_overwrite"])
 def test_mtvec_zero_src_CSRRS_read_only(self):
  self.assertIsNone(csr_vector_write(enc_csr(0x305,2,0)))
  self.assertIsNone(csr_vector_write(enc_csr(0x305,3,0)))
  self.assertIsNone(csr_vector_write(enc_csr(0x305,6,0)))
 def test_write_zero_src_csrrw_is_actual_write(self):
  a=csr_vector_write(enc_csr(0x305,1,0))
  self.assertEqual(resolve_adjacent_value([],0x40001000,a["writer_value_register"])["value"],0)
 def test_other_CSR_not_triggered(self):
  self.assertIsNone(csr_vector_write(enc_csr(0x300,1,5)))
  self.assertIsNone(csr_vector_write(enc_csr(0x341,1,5)))
 def test_adjacent_LUI_ADDI_to_mtvec(self):
  pc=0x40001000
  hist=[(pc,enc_lui(5,0x40012000)),(pc+4,enc_addi(5,5,0x124))]
  found=resolve_adjacent_value(hist,pc+8,5)
  self.assertEqual(found["value"],0x40012124)
  self.assertEqual(found["kind"],"ADJACENT_LUI_ADDI")
 def test_wrong_register_does_not_leak_value(self):
  pc=0x40001000
  hist=[(pc,enc_lui(6,0x40012000)),(pc+4,enc_addi(5,5,0x124))]
  self.assertIsNone(resolve_adjacent_value(hist,pc+8,5))
 def test_interrupt_counterexample_nonadjacent_pair_unknown(self):
  pc=0x40001000
  hist=[(pc,enc_lui(5,0x40012000)),(pc+8,enc_addi(5,5,4))]
  self.assertIsNone(resolve_adjacent_value(hist,pc+12,5))
 def test_pc_relative_AUIPC_ADDI_with_sign_extension(self):
  pc=0x40001000
  hist=[(pc,enc_auipc(7,0x1000)),(pc+4,enc_addi(7,7,-12))]
  self.assertEqual(resolve_adjacent_value(hist,pc+8,7)["value"],0x40001ff4)
 def test_mutated_opcode_not_read_as_vector_write(self):
  old=int.from_bytes(enc_csr(0x305,1,5),"little")
  self.assertIsNone(csr_vector_write(((old&~0x7f)|0x13).to_bytes(4,"little")))
 def test_CSR_imm_write_no_register(self):
  v=csr_vector_write(enc_csr(0x307,5,19))
  self.assertEqual(v["name"],"mtvt")
  self.assertEqual(v["immediate_value"],19)
  self.assertIsNone(v["writer_value_register"])
if __name__=="__main__":unittest.main()
