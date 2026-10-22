#!/usr/bin/env python3
import hashlib
import unittest
from rom_api_prior_art_gate import VENDOR_BLOBS,blob_sha,extract_linker_symbols,commented_names,screen

class ROM001VendorPriorArtGate(unittest.TestCase):
 def test_all_21_manifest_entries_pinned(self):
  self.assertEqual(len(VENDOR_BLOBS),21)
  self.assertTrue(all(len(x)==40 and all(c in "0123456789abcdef" for c in x)
                      for x in VENDOR_BLOBS.values()))
 def test_git_blob_sha_correct(self):
  payload=b"hello"
  expected=hashlib.sha1(b"blob 5"+bytes([0])+payload).hexdigest()
  self.assertEqual(blob_sha(payload),expected)
  self.assertNotEqual(blob_sha(payload+b"!"),expected)
 def test_block_comments_and_line_comments_not_counted_as_exported(self):
  text="/* fake_api = 0x40000000; */\n// fake_second = 2;\nrom2_temp_to_power1 = 0x40001ab4;\nrom2_get_tx_gain_value1 = 0x40001bc0;\n"
  v=extract_linker_symbols(text)
  self.assertEqual(v,{"rom2_temp_to_power1":{0x40001ab4},"rom2_get_tx_gain_value1":{0x40001bc0}})
 def test_named_exports_rejected_even_if_implementation_address_differs(self):
  items=[{"name":n,"priority_score":100,"trivial_stub_candidate":False,"revisions":{}} for n in
         ["rom2_temp_to_power1","rom2_get_tx_gain_value1"]+[f"fake_name_{i}" for i in range(150)]]
  triage={"schema":"ESP32C3_ROM_REV101_UNMATCHED_FUNCTION_MACHINE_TRIAGE_V1","all_152_ranked":items}
  inventory={"rom2_temp_to_power1":[{"file":"esp32c3.rom.eco7.ld","exported_link_address":"0x40001ab4"}],
             "rom2_get_tx_gain_value1":[{"file":"esp32c3.rom.eco7.ld","exported_link_address":"0x40001bc0"}]}
  r=screen(triage,inventory,{})
  self.assertEqual(r["known_in_official_linkers"],2)
  self.assertEqual(r["not_in_these_21_official_linkers"],150)
  self.assertEqual(r["novel_api_verified"],0)
  self.assertFalse(r["unmatched_for_independent_followup"][0]["novelty_proven"])
 def test_hard_failure_for_missing_vendor_control(self):
  items=[{"name":n,"priority_score":0,"trivial_stub_candidate":False,"revisions":{}} for n in
         ["rom2_temp_to_power1","rom2_get_tx_gain_value1"]+[f"candidate_{i}" for i in range(150)]]
  with self.assertRaisesRegex(ValueError,"PRIOR_ART_FALSE_NEGATIVE"):
   screen({"schema":"ESP32C3_ROM_REV101_UNMATCHED_FUNCTION_MACHINE_TRIAGE_V1","all_152_ranked":items},{},{})
 def test_commented_definitions_are_published_but_not_exported(self):
  fake="/*\nr_llc_llcp_send_eco = 0x40001cf4;\n*/\nets_printf = 0x40000040;\n"
  self.assertEqual(commented_names(fake)["r_llc_llcp_send_eco"],{0x40001cf4})
  self.assertNotIn("r_llc_llcp_send_eco",extract_linker_symbols(fake))
  names=["rom2_temp_to_power1","rom2_get_tx_gain_value1","r_llc_llcp_send_eco"]+[f"candidate_{i}" for i in range(149)]
  t={"schema":"ESP32C3_ROM_REV101_UNMATCHED_FUNCTION_MACHINE_TRIAGE_V1",
      "all_152_ranked":[{"name":n,"priority_score":0,"trivial_stub_candidate":False,"revisions":{}} for n in names]}
  known={"rom2_temp_to_power1":[{"file":"eco7","exported_link_address":"0x40001ab4"}],
         "rom2_get_tx_gain_value1":[{"file":"eco7","exported_link_address":"0x40001bc0"}]}
  r=screen(t,known,{},{"r_llc_llcp_send_eco":[{"file":"bt","address":"0x40001cf4"}]})
  self.assertEqual(r["published_but_commented"],1)
  self.assertEqual(r["not_in_these_21_official_linkers"],149)
  self.assertEqual(r["published_commented_names"][0]["status"],"DOCUMENTED_BUT_COMMENTED_NOT_EXPORTED")
 def test_duplicate_candidate_rejected(self):
  t={"schema":"ESP32C3_ROM_REV101_UNMATCHED_FUNCTION_MACHINE_TRIAGE_V1","all_152_ranked":
     [{"name":"rom2_temp_to_power1"}]*152}
  with self.assertRaisesRegex(ValueError,"PINNED_152_CANDIDATES_INCOMPLETE"):screen(t,{},{})
if __name__=="__main__":unittest.main()
