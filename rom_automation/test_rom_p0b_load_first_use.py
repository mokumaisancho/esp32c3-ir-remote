"""ROM-001 P0-B machine-only first load-use falsification controls."""
import unittest
from rom_p0b_load_first_use import decode_consumer,analyze
from decision_gate import ROM_SHA

def raw32(x):return x.to_bytes(4,"little").hex()

class FirstUseTests(unittest.TestCase):
 def test_load_result_used_for_andi_mask(self):
  # ANDI x10, x15, 0x3
  w=(3<<20)|(15<<15)|(7<<12)|(10<<7)|0x13
  v=decode_consumer(raw32(w),15)
  self.assertEqual(v["status"],"READ_FOR_ALU")
  self.assertEqual(v["immediate"],3)
 def test_read_register_overwritten_before_use(self):
  # LUI x15,0x60000; not proof of use of preceding MMIO read
  self.assertEqual(decode_consumer(raw32(0x600007b7),15)["status"],"OVERWRITES")
 def test_branch_not_crossed_as_linear_evidence(self):
  # BEQ x10,x15,+4; marks read in control but cannot follow fallthrough as fact
  w=(15<<20)|(10<<15)|(0<<12)|(2<<8)|0x63
  self.assertEqual(decode_consumer(raw32(w),15)["status"],"CONTROL_USING_LOADED_REG")
 def test_unknown_compressed_is_not_ignored(self):
  self.assertEqual(decode_consumer((0x6000).to_bytes(2,"little").hex(),15)["status"],"UNKNOWN_OR_CONTROL")
 def test_compressed_memory_store_blocks_provenance(self):
  self.assertEqual(decode_consumer((0xc002).to_bytes(2,"little").hex(),15)["status"],"UNKNOWN_MEMORY_CONSUMPTION")
 def test_malformed_report_is_refused(self):
  with self.assertRaisesRegex(RuntimeError,"INPUT_SOURCE_MISMATCH"):
   analyze({"schema":"NO_VERIFIED_MACHINE_SOURCE","ROM_sha256":ROM_SHA})
 def test_synthetic_linear_next_pc_strict(self):
  report={"schema":"ROM001_P0B_TWO_PINNED_MACHINE_CALLSITE_CONTEXT_V1",
          "ROM_sha256":ROM_SHA,"two_reviewed_callsite_windows":[]}
  for addr in ("0x600061c4","0x60033c00"):
   read="0x40010004"
   report["two_reviewed_callsite_windows"].append({
    "destination_register_index":15,"revision":"synthetic","function":"synthetic",
    "address":addr,"machine_access_pc":read,
    "nearby_machine_instruction_window":[
     {"pc":"0x40010004","size":4,"raw_machine_bytes":raw32(0x00002783),"mnemonic":"lw"},
     {"pc":"0x40010008","size":4,"raw_machine_bytes":raw32(0x0037f513),"mnemonic":"andi"}]})
  r=analyze(report)
  self.assertEqual(len(r["per_read_context"]),2)
  self.assertTrue(all(x["first_nontrivial_or_unknown"]["status"]=="READ_FOR_ALU" for x in r["per_read_context"]))
if __name__=="__main__":unittest.main()
