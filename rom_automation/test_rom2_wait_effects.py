"""ROM-001 raw-byte busy-loop proof and negative limits on the actual revision."""
import os,pathlib,unittest,zipfile,json
from rom2_wait_effects import evaluate,execute_bytes,reference,cases,NAMES,REV
from decision_gate import REVS
M=pathlib.Path(os.environ["ROM_MACHINE_ZIP"])
G=pathlib.Path(os.environ["ROM_GHIDRA_ZIP"])
class ROM2ByteBusyWaitTests(unittest.TestCase):
 def test_pinned_rom_real_bytes_and_external_tail(self):
  x=evaluate(M,G)
  self.assertEqual(x["name"],NAMES[0])
  self.assertEqual(x["revision_bodies"],1)
  self.assertEqual(x["vectors"],20)
  self.assertEqual(x["negative_raw_machine_byte_mutations"],2)
  self.assertTrue(x["unbounded_busy_limit_detected"])
  self.assertFalse(x["external_delay_callee_verified"])
  self.assertTrue(x["no_silicon_execution"])
  self.assertFalse(x["independent_semantic_review_approved"])
 def test_first_nonbusy_avoids_external_call(self):
  with zipfile.ZipFile(M) as z:
   rows=json.loads(z.read("output/candidate_full/"+REV+".candidate_full.json"))[NAMES[0]]["instruction_listing"]
  x=execute_bytes(rows,[0])
  self.assertEqual(x["event"],"RETURN_WITHOUT_EXTERNAL_CALL")
  self.assertEqual(x["busy_reads"],1)
 def test_volatile_infinite_busy_not_claimed_completed(self):
  with self.assertRaisesRegex(RuntimeError,"UNBOUNDED_BUSY_SCENARIO"):
   reference([0xffffffff]*5)
 def test_present_only_one_revision(self):
  with zipfile.ZipFile(M) as z:
   out=[json.loads(z.read("output/candidate_full/"+r+".candidate_full.json"))[NAMES[0]]["status"] for r in REVS]
  self.assertEqual([s!="ABSENT_SYMBOL" for s in out],[False,True,False])
if __name__=="__main__":unittest.main()
