"""Negative controls for cross-architecture exact address prior evidence."""
import unittest
from rom_p0b_crosschip_prior import git_blob,inspect,SOURCES
from decision_gate import ROM_SHA

class CrossChipPriorTests(unittest.TestCase):
 def test_git_blob_starts_with_content_and_object_frame(self):
  a=b"hello\n"
  self.assertEqual(git_blob(a),"ce013625030ba8dba906f756967f9e9ca394464a")
  self.assertNotEqual(git_blob(a+b"!"),git_blob(a))
 def test_S3_chip_name_is_not_ESP32_C3(self):
  self.assertEqual(SOURCES[0]["target_chip"],"ESP32-S3")
  self.assertNotEqual(SOURCES[0]["target_chip"],"ESP32-C3")
 def test_no_nearest_neighbor_matches(self):
  d={"schema":"ROM001_P0B_2025_PRIOR_ART_DEDUP_V1","ROM_source_sha256":ROM_SHA,
     "remaining_without_match_in_this_study":[hex(0x60033090+i*4) for i in range(11)]}
  sources={
   "S3_PHY_LIBRARY_MAP":("Register: 0x60033094","http://s3","abc"),
   "FLINTOS_RADIO_PLAN":("Register: 0x60033090, 0x600330a0","http://plan","def"),
   "THIRD_PARTY_C3_RADIO_CAPTURE":("observed 0x600330a0","http://capture","ghi")}
  r=inspect(d,sources)
  self.assertEqual(r["examined_remaining"],11)
  self.assertTrue(r["rows"][0]["source_hits"])
  self.assertFalse(r["rows"][0]["same_chip_exact_register_function_proven"])
  self.assertFalse(r["rows"][2]["source_hits"])
 def test_fails_on_11_candidate_number_change(self):
  with self.assertRaisesRegex(RuntimeError,"PRIOR_PENDING11_DRIFT"):
   inspect({"schema":"ROM001_P0B_2025_PRIOR_ART_DEDUP_V1",
    "ROM_source_sha256":ROM_SHA,"remaining_without_match_in_this_study":[]},{})
if __name__=="__main__":unittest.main()
