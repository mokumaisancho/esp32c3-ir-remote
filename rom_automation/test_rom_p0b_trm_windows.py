"""ROM-001 vendor TRM table falsification: reserved is NOT novel."""
import unittest
from rom_p0b_trm_windows import TRM_RANGES,classify,compare
from decision_gate import ROM_SHA
class TRM14Tests(unittest.TestCase):
 def test_all_14_nonlisted_addr_in_three_reserved_windows(self):
  values=[0x600061c0,0x600061c4,0x6001c08c,0x6001c13c,
          0x6001c400,0x6001cc48,0x60031100,0x60033084,0x60033088,
          0x60033090,0x600330a0,0x60033c00,0x60033c64,0x60033ca0]
  self.assertEqual(len(values),len(set(values)))
  self.assertTrue(all(classify(x)["classification"]=="TRM_RESERVED" for x in values))
  self.assertEqual([sum(classify(x)["trm_window"][0]==hex(a) for x in values)
                    for a in (0x60005000,0x6001b000,0x6002e000)],[2,4,8])
 def test_nearby_published_addr_differs(self):
  self.assertEqual(classify(0x6001a050)["trm_label"],"eFuse Controller")
  self.assertEqual(classify(0x6003a000)["trm_label"],"AES Accelerator")
  self.assertEqual(classify(0x60005000)["classification"],"TRM_RESERVED")
  self.assertEqual(classify(0x60006fff)["classification"],"TRM_RESERVED")
  self.assertEqual(classify(0x60007000)["classification"],"TRM_RESERVED")
  self.assertEqual(classify(0x60004000)["trm_label"],"GPIO")
 def test_sorted_windows_disjoint(self):
  for (a,b,_),(c,d,__) in zip(TRM_RANGES,TRM_RANGES[1:]):
   self.assertLessEqual(a,b)
   self.assertLess(b,c)
 def test_synthetic_missing_candidate_is_not_novel(self):
  test={"schema":"ROM001_P0B_VENDOR_EXACT_ALL_13_V1","ROM_SHA256":ROM_SHA,
        "all_13_function_differences":[],"exact_match_addresses":[],
        "not_found_in_simple_register_macros":[]}
  with self.assertRaisesRegex(RuntimeError,"EXPECTED_13_NAME_FUNCTIONS"):
   compare(test)
 def test_incomplete_transcription_not_evidence_of_new_function(self):
  self.assertEqual(classify(0x70000000)["classification"],"UNMAPPED_IN_TRANSCRIBED_TRM")
  self.assertNotEqual(classify(0x70000000)["classification"],"NOVEL")
if __name__=="__main__":unittest.main()
