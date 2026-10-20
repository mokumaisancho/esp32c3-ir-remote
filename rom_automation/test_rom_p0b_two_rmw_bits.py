"""ROM001 independent machine-byte execution of the two static MMIO RMW shapes."""
import unittest
from rom_p0b_two_rmw_bits import CASE0,CASE1,evaluate_one,decode32,decode_c_alu
RF=["83a7461c","4177","b240","f98f","1567","13075755","d98f","23a2f61c"]
WIFI=["832707c0","93e7070f","2320f7c0"]
def mk(addr,rev,pcs,raw):
 return {"address":addr,"revision":rev,"machine_access_pc":hex(pcs[0]),
   "nearby_machine_instruction_window":[{"pc":hex(p),"raw_machine_bytes":b} for p,b in zip(pcs,raw)]}
class RMWSemanticsTests(unittest.TestCase):
 def test_rf_exact_mask_and_constant(self):
  r=evaluate_one(mk("0x600061c4","esp32c3_rev0_rom.elf",CASE0,RF))
  self.assertEqual(r["keep_mask"],"0xffff0000")
  self.assertEqual(r["constant_or"],"0x5555")
  self.assertTrue(r["read_modify_write_static_instruction_semantics_verified"])
  self.assertFalse(r["register_field_meaning_independently_verified"])
 def test_wifi_OR_exact_bitmask(self):
  r=evaluate_one(mk("0x60033c00","esp32c3_rev101_rom.elf",CASE1,WIFI))
  self.assertEqual(r["constant_or"],"0xf0")
  self.assertFalse(r["register_field_meaning_independently_verified"])
 def test_mutate_mmio_store_source_register_fails(self):
  x=list(RF);u=int.from_bytes(bytes.fromhex(x[-1]),"little")
  x[-1]=((u&~(31<<20))|(14<<20)).to_bytes(4,"little").hex()
  with self.assertRaisesRegex(RuntimeError,"RF_WRITEBACK_MUST_SAME_ADDRESS"):
   evaluate_one(mk("0x600061c4","esp32c3_rev0_rom.elf",CASE0,x))
 def test_write_to_different_mmio_offset_fails(self):
  x=list(WIFI);u=int.from_bytes(bytes.fromhex(x[2]),"little")
  x[2]=(u^(1<<7)).to_bytes(4,"little").hex()
  with self.assertRaisesRegex(RuntimeError,"WIFI_RMW_REGISTER_OR_ADDRESS_MISMATCH"):
   evaluate_one(mk("0x60033c00","esp32c3_rev101_rom.elf",CASE1,x))
 def test_mutate_intervening_lwsp_to_rf_value_register_fails(self):
  x=list(RF);x[2]="b247" # rd x15 in lwsp, clobbers value
  with self.assertRaisesRegex(RuntimeError,"RF_ALLOWED_LWSP_ONLY_RA"):
   evaluate_one(mk("0x600061c4","esp32c3_rev0_rom.elf",CASE0,x))
 def test_injected_instruction_gap_fails(self):
  pcs=list(CASE1);pcs[1]+=2
  with self.assertRaisesRegex(RuntimeError,"MISSING_EXACT_INSTRUCTION_PC|GAPPED_OR_CONTROL_FLOW_INSERTED_IN_RMW_SEQUENCE"):
   evaluate_one(mk("0x60033c00","esp32c3_rev101_rom.elf",pcs,WIFI))
 def test_direct_machine_bit_classifier_rejects_other_alu(self):
  self.assertEqual(decode32(bytes.fromhex("93e7070f"))["op"],"ori")
  self.assertEqual(decode_c_alu(bytes.fromhex("f98f"))["op"],"c.and")
  self.assertEqual(decode_c_alu(bytes.fromhex("d98f"))["op"],"c.or")
  self.assertEqual(decode_c_alu(bytes.fromhex("0100"))["op"],"unsupported")
if __name__=="__main__":unittest.main()
