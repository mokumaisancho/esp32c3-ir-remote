"""RV32C exact-bit register-effect negative and independent Capstone checks."""
import types,unittest
from rom_rvc_register_effects import rvc_effect
from rom_p0a_cfg_defuse import infer_register_value

def raw(v):return v.to_bytes(2,"little")
def inst(pc,v,n=2):
 b=v.to_bytes(n,"little")
 return types.SimpleNamespace(address=pc,size=n,bytes=b,mnemonic="synthetic")
class RVCRegisterEffectsTests(unittest.TestCase):
 def test_register_writers_and_pure_stores(self):
  self.assertEqual(rvc_effect(raw(0x4000))["rd"],8)       # c.lw x8
  self.assertEqual(rvc_effect(raw(0xc000))["kind"],"PRESERVE") # c.sw
  self.assertTrue(rvc_effect(raw(0xc002))["may_write_memory"]) # c.swsp
  self.assertEqual(rvc_effect(raw(0x4282))["kind"],"WRITE_UNKNOWN") # c.lwsp x5
  self.assertEqual(rvc_effect(raw(0x829a))["rd"],5) # c.mv x5,x6
  self.assertEqual(rvc_effect(raw(0x929a))["rd"],5) # c.add x5,x6
 def test_q1_constants_and_unknown_code(self):
  self.assertEqual(rvc_effect(raw(0x4285))["value"],1) # c.li x5,1
  self.assertEqual(rvc_effect(raw(0x6285))["value"],0x1000) # c.lui x5,0x1
  self.assertEqual(rvc_effect(raw(0x0289))["imm"],2) # c.addi x5,2
  self.assertEqual(rvc_effect(raw(0xa001))["kind"],"CONTROL") # c.j
  self.assertEqual(rvc_effect(raw(0x2001))["kind"],"CONTROL") # c.jal
  self.assertEqual(rvc_effect(raw(0x9002))["kind"],"CONTROL") # c.ebreak
  self.assertEqual(rvc_effect(raw(0x2000))["kind"],"UNKNOWN") # F/D or non-RV32I
  self.assertEqual(rvc_effect(raw(0x0000))["kind"],"UNKNOWN") # illegal all zero
 def test_nonadjacent_rvc_constant_through_store(self):
  base=0x40001000
  seq=[inst(base,0x6285),inst(base+2,0x0289),
       inst(base+4,0xc002),inst(base+6,0x000280e7,4)]
  a=infer_register_value(seq,3,5)
  self.assertEqual(a["value"],0x1002)
  self.assertEqual(a["kind"],"UNIQUE_CFG_RV32C_DEFINITION")
 def test_compressed_move_clobber_fails(self):
  pc=0x40001000
  seq=[inst(pc,0x6285),inst(pc+2,0x829a),inst(pc+4,0x000280e7,4)]
  self.assertEqual(infer_register_value(seq,2,5)["unresolved"],"COMPRESSED_REGISTER_WRITER_UNSUPPORTED")
 def test_compressed_write_to_another_register_preserves_x5(self):
  pc=0x40001000
  seq=[inst(pc,0x6285),inst(pc+2,0x839a),inst(pc+4,0x000280e7,4)] # c.mv x7,x6
  self.assertEqual(infer_register_value(seq,2,5)["value"],0x1000)
 def test_unsupported_compressed_opcode_never_claims_a_function(self):
  pc=0x40001000
  seq=[inst(pc,0x6285),inst(pc+2,0x2000),inst(pc+4,0x000280e7,4)]
  self.assertEqual(infer_register_value(seq,2,5)["unresolved"],"UNMODELED_COMPRESSED_OPCODE")
 def test_first_party_capstone_independent_byte_names(self):
  from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
  d=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
  cases=[(0x4285,"c.li"),(0x6285,"c.lui"),(0x0289,"c.addi"),
         (0x829a,"c.mv"),(0x929a,"c.add"),(0xc002,"c.swsp"),
         (0x4000,"c.lw"),(0xc000,"c.sw"),(0x4282,"c.lwsp")]
  for code,expected in cases:
   seq=list(d.disasm(raw(code),0x40001000))
   self.assertEqual(len(seq),1,(hex(code),expected))
   self.assertEqual(seq[0].mnemonic,expected,(hex(code),expected))
if __name__=="__main__":unittest.main()
