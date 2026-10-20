"""ROM-001 SRAM provenance: original byte encodings and false-positive controls."""
import types,unittest
from rom_sram_writer_audit import real_store,static_register_value,detect_store,collect_sram_slots
def ins(raw,pc,mnemonic):
 return types.SimpleNamespace(bytes=int(raw).to_bytes(4,"little"),size=4,address=pc,mnemonic=mnemonic)
def lui(rd,hi):return 0x37|(rd<<7)|(hi&0xfffff000)
def addi(rd,rs,imm):return 0x13|(rd<<7)|(rs<<15)|((imm&0xfff)<<20)
def sw(src,base,imm):
 u=imm&0xfff
 return 0x23|((u>>5)<<25)|(src<<20)|(base<<15)|(2<<12)|((u&31)<<7)
class StaticSRAMWriterTests(unittest.TestCase):
 def sample(self,offset=0):
  return [ins(lui(5,0x3fce0000),0x40000000,"lui"),
          ins(addi(5,5,-1052),0x40000004,"addi"),
          ins(sw(10,5,offset),0x40000008,"sw")]
 def test_immutable_encoded_store_target_matches_SRAM_slot(self):
  got=detect_store(self.sample(),2,{0x3fcdfbe4})
  self.assertEqual(got["target_sram_slot"],"0x3fcdfbe4")
  self.assertEqual(got["stored_value_register"],10)
  self.assertIsNone(got["actual_written_function_pointer_value"])
  self.assertFalse(got["runtime_execution_verified"])
 def test_mutated_immediate_is_detected_not_accepted(self):
  self.assertIsNone(detect_store(self.sample(offset=4),2,{0x3fcdfbe4}))
 def test_negative_wrong_expected_slot(self):
  self.assertIsNone(detect_store(self.sample(),2,{0x3fcdfbe8}))
 def test_control_flow_barrier_refuses_guessed_const_register(self):
  s=self.sample()
  s.insert(2,ins(0x00000063,0x40000008,"beq"))
  s[3].address=0x4000000c
  self.assertIsNone(detect_store(s,3,{0x3fcdfbe4}))
 def test_compressed_sw_genuine_bits(self):
  # C.SW x10, 12(x9): imm[5:3]=001, imm[2]=1
  raw=(6<<13)|(1<<10)|(1<<7)|(1<<6)|(2<<2)
  z=types.SimpleNamespace(bytes=raw.to_bytes(2,"little"),size=2,address=0x40000000,mnemonic="c.sw")
  effect=real_store(z)
  self.assertEqual((effect["base_reg"],effect["value_reg"],effect["offset"],effect["width_bytes"]), (9,10,12,4))
  changed=types.SimpleNamespace(bytes=(raw^(1<<6)).to_bytes(2,"little"),size=2,address=0x40000000,mnemonic="c.sw")
  self.assertEqual(real_store(changed)["offset"],8)
 def test_compressed_swsp_genuine_bits(self):
  # C.SWSP x11, 124(sp): imm bits 2..5=1111, bits 6..7=01
  raw=(6<<13)|(15<<9)|(1<<7)|(11<<2)|2
  z=types.SimpleNamespace(bytes=raw.to_bytes(2,"little"),size=2,address=0x40000000,mnemonic="c.swsp")
  effect=real_store(z)
  self.assertEqual((effect["base_reg"],effect["value_reg"],effect["offset"]), (2,11,124))
 def test_non_store_c_extension_does_not_match(self):
  for raw in (0x0001,0x8082,0xc002):
   z=types.SimpleNamespace(bytes=raw.to_bytes(2,"little"),size=2,address=0,mnemonic="random")
   self.assertIsNone(real_store(z))
 def test_strict_store_opcodes_only(self):
  self.assertEqual(real_store(ins(sw(10,5,0),0x40000000,"sw"))["width_bytes"],4)
  self.assertIsNone(real_store(ins(addi(5,5,0),0x40000000,"addi")))
 def test_unsigned_negative_lower_bits(self):
  val=static_register_value(self.sample(),2,5)
  self.assertEqual(val[0],0x3fcdfbe4)
  self.assertEqual([v["kind"] for v in val[1]],["LUI","ADDI"])
if __name__=="__main__":unittest.main()
