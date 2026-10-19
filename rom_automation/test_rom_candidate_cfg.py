"""ROM-001: actual bounded 88-entry raw-byte CFG and denial cases."""
import os,pathlib,unittest,zipfile,json
from decision_gate import REVS
from rom_candidate_cfg import evaluate,control_target
M=pathlib.Path(os.environ["ROM_MACHINE_ZIP"])
class ByteCFGTests(unittest.TestCase):
 def test_all_original_rom_entries_and_local_gaps(self):
  r=evaluate(M)
  self.assertEqual(r["original_88"],88)
  self.assertFalse(r["full_rom_ac03_cfg_accepted"])
  self.assertFalse(r["hardware_verified"])
  for rev in REVS:
   stats=r["summary"][rev]
   self.assertEqual(stats["not_locally_reached_instructions"],76)
   self.assertEqual(stats["not_locally_reached_bytes"],188)
   self.assertEqual(stats["invalid_interior_target_functions"],0)
   self.assertEqual(stats["INTRA_FUNC_LOCAL_CFG"]+stats["ABSENT_SYMBOL"],88)
   gap={k for k,v in r["per_function"][rev].items() if v.get("not_locally_reached_instructions")}
   self.assertEqual(gap,{"_interrupt_handler","r_lld_test_start","spi_slave_download"})
 def test_raw_bytes_target_not_operand_text(self):
  with zipfile.ZipFile(M) as z:
   row=json.loads(z.read("output/candidate_full/"+REVS[0]+".candidate_full.json"))["ds_wait_idle"]["instruction_listing"][3]
  pc=int(row["pc"],16)
  control,target=control_target(row,pc)
  self.assertEqual(control,"BRANCH")
  self.assertEqual(target,pc+4)
  altered=dict(row);altered["operands"]="nonsense, 0"
  self.assertEqual(control_target(altered,pc),(control,target))
  word=int.from_bytes(bytes.fromhex(row["word"]),"little")
  altered["word"]=(word^(1<<2)).to_bytes(2,"little").hex()
  self.assertNotEqual(control_target(altered,pc)[1],target)
 def test_unknown_branch_encoding_fail_closed(self):
  with self.assertRaisesRegex(RuntimeError,"UNSUPPORTED_RAW_CONTROL"):
   control_target({"mnemonic":"beq","word":"0000","pc":"0x40000000"},0x40000000)
if __name__=="__main__":unittest.main()
