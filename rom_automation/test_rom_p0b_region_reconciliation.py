#!/usr/bin/env python3
"""Falsification suite: validated vendor base, window ownership vs bitfield claims."""
import copy, unittest
from rom_p0b_region_reconciliation import (
 BASE_FILE,BASE_GIT_BLOB_SHA1,TARGETS,git_blob_sha1,official_bases,
 investigate,WIFI_MAC_START,WIFI_MAC_LAST)
from rom_p0b_trm_windows import classify

class R0R1R2Reconciliation(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.raw=BASE_FILE.read_bytes()
  cls.bases=official_bases(cls.raw)
 def test_vendor_file_git_blob_matches_pinned(self):
  self.assertEqual(git_blob_sha1(self.raw),BASE_GIT_BLOB_SHA1)
 def test_mutated_vendor_header_must_fail_closed(self):
  with self.assertRaisesRegex(ValueError,"OFFICIAL_VENDOR_REG_BASE_UNPINNED"):
   official_bases(self.raw.replace(b"0x60006000",b"0x60006001"))
 def test_vendor_fe_block_base_and_offset(self):
  self.assertEqual(self.bases["DR_REG_FE_BASE"],0x60006000)
  self.assertEqual(TARGETS["R1"]["address"]-self.bases["DR_REG_FE_BASE"],0x1c4)
 def test_trm_reserved_does_not_erase_official_fe_block(self):
  result=investigate(self.bases)
  item=result["findings"][0]
  self.assertEqual(item["trm_v1_4"]["classification"],"TRM_RESERVED")
  self.assertEqual(item["region_owner"],"RF_FRONT_END_FE")
  self.assertFalse(item["exact_bitfield_function_proven"])
 def test_academic_mac_window_without_false_exact_field(self):
  addr=TARGETS["R2"]["address"]
  self.assertTrue(WIFI_MAC_START<=addr<=WIFI_MAC_LAST)
  row=investigate(self.bases)["findings"][1]
  self.assertEqual(row["region_evidence"]["offset"],"0xc00")
  self.assertEqual(row["region_evidence"]["kind"],"ACADEMIC_REVERSE_ENGINEERED_MAC_RANGE_NOT_EXACT_REGISTER")
  self.assertIsNone(row["region_evidence"]["exact_register_symbol"])
  self.assertFalse(row["physical_causal_test_proven"])
 def test_wrong_rf_base_fails(self):
  bases=dict(self.bases);bases["DR_REG_FE_BASE"]=0x60005000
  with self.assertRaisesRegex(ValueError,"RF_FRONT_END_WINDOW_MISMATCH"):
   investigate(bases)
 def test_shifted_wifi_address_fails(self):
  target=copy.deepcopy(TARGETS)
  target["R2"]["address"]=0x60036000
  with self.assertRaisesRegex(ValueError,"WIFI_MAC_RANGE_MISMATCH"):
   investigate(self.bases,target)
 def test_shifting_rf_address_fails(self):
  target=copy.deepcopy(TARGETS)
  target["R1"]["address"]=0x60007000
  with self.assertRaisesRegex(ValueError,"RF_FRONT_END_WINDOW_MISMATCH"):
   investigate(self.bases,target)
 def test_no_silent_novelty_or_runtime_pass(self):
  result=investigate(self.bases)
  self.assertEqual(result["new_rom_api_confirmed"],0)
  self.assertEqual(result["exact_bitfield_semantics_resolved"],0)
  self.assertEqual(result["silicon_tests_executed"],0)
  self.assertTrue(all(not row["novel_capability_proven"] and row["no_hardware_mutation"] for row in result["findings"]))
 def test_input_scope_must_not_expand_without_review(self):
  with self.assertRaisesRegex(ValueError,"TWO_TARGET_SCOPE_DRIFT"):
   investigate(self.bases,{"R1":TARGETS["R1"]})
if __name__=="__main__":unittest.main()
