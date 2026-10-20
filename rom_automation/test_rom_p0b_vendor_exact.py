"""Official pinned register macro parser falsification and 13-function evidence tests."""
import unittest
from rom_p0b_vendor_exact import classify,check_headers
class RegisterMatchesTests(unittest.TestCase):
 def test_index_exact_offset_not_nearest_neighbor(self):
  fixture={"schema":"ROM001_P0B_MACHINE_MMIO_REV_DIFF_V1",
   "ROM_SHA256":"caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46",
   "all_differentials":[]}
  for i in range(13):
   fixture["all_differentials"].append({"function_name":"fn"+str(i),"all_static_evidence":{
    "rev0":[{"machine_mmio_sites":[{"address":"0x60008850","kind":"load","access_pc":"0x40000000","pattern":"LUI_ACCESS","source_bytes":"00000000"}]}]}})
  rows,known,missing=classify(fixture,{0x60008850:[{"symbol":"KNOWN_REG","header":"x.h","base_macro":"DR_REG_EFUSE_BASE"}]})
  self.assertEqual(len(rows),13)
  self.assertEqual(known,{0x60008850})
  self.assertEqual(missing,set())
  self.assertFalse(rows[0]["novel_register_proven"])
 def test_mutated_register_address_does_not_match_exact(self):
  fixture={"schema":"ROM001_P0B_MACHINE_MMIO_REV_DIFF_V1",
   "ROM_SHA256":"caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46",
   "all_differentials":[]}
  for i in range(13):fixture["all_differentials"].append({"function_name":str(i),"all_static_evidence":{"rev0":[{"machine_mmio_sites":[{"address":"0x60008854","kind":"load","access_pc":"0x40000000","pattern":"LUI_ACCESS","source_bytes":"00"}]}]}})
  _,known,missing=classify(fixture,{0x60008850:[{"symbol":"KNOWN","header":"vendor.h","base_macro":"DR_REG_EFUSE_BASE"}]})
  self.assertEqual(known,set())
  self.assertEqual(missing,{0x60008854})
 def test_input_counterexample_missing_function_fails_closed(self):
  d={"schema":"ROM001_P0B_MACHINE_MMIO_REV_DIFF_V1","ROM_SHA256":"caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46","all_differentials":[]}
  with self.assertRaisesRegex(RuntimeError,"P0B_13_CANDIDATE_DRIFT"):classify(d,{})
 def test_vendor_bases_must_match_exact_bytes(self):
  b=b"#define DR_REG_EFUSE_BASE 0x60008800\n"*40
  with self.assertRaisesRegex(RuntimeError,"PINNED_BASE_HEADER_MISMATCH"):
   check_headers(b.replace(b"800",b"804"),[],b)
if __name__=="__main__":unittest.main()
