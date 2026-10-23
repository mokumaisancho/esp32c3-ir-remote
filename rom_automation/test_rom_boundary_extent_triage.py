#!/usr/bin/env python3
import copy,unittest
from rom_boundary_extent_triage import classify

BASE=0x40000000

def fixture():
 starts=[{"entry_pc":hex(BASE),"size_bytes":8,"name":"known"}]
 c={"revision":"esp32c3_rev0_rom.elf","unrooted_halfword_candidate_count":3,
  "ranked_possible_entries":[hex(BASE),hex(BASE+2),hex(BASE+0x100)],
  "candidate_records":[]}
 for pc,rooted in ((BASE,1),(BASE+2,0),(BASE+0x100,0)):
  c["candidate_records"].append({"entry_pc":hex(pc),"rooted_call_witnesses":rooted,
    "encoded_link_sources":1,
    "machine_first_instruction":{"pc":hex(pc),"raw":"0100","opcode":"c.nop","length":2},
    "witnesses":[{"from_pc":hex(BASE),"opcode_hex":"ef008000"}]})
 o={"revision":"esp32c3_rev0_rom.elf","symbol_function_records":starts}
 return c,o

class IndependentExtentTriage(unittest.TestCase):
 def test_three_way_distinction(self):
  c,o=fixture();r=classify(c,o)
  self.assertEqual(list(r["triage_counts"].values()),[1,1,1])
  self.assertEqual(r["rooted_unclaimed_count"],0)
  self.assertFalse(r["unknown_entries"][0]["source_rooted"])
 def test_rooted_candidate_only_does_not_infer_novelty(self):
  c,o=fixture();c["candidate_records"][2]["rooted_call_witnesses"]=1
  r=classify(c,o)
  self.assertEqual(r["rooted_unclaimed_entries"],[hex(BASE+0x100)])
  self.assertTrue(r["no_independent_new_ROM_API_discovery"])
 def test_wrong_revision_fails(self):
  c,o=fixture();o["revision"]="esp32c3_rev3_rom.elf"
  with self.assertRaisesRegex(ValueError,"REVISION_ID_MISMATCH"):classify(c,o)
 def test_missing_witness_fails(self):
  c,o=fixture();c["candidate_records"]=c["candidate_records"][:-1]
  with self.assertRaisesRegex(ValueError,"MISSING_RAW_SOURCE_WITNESS"):classify(c,o)
 def test_count_corruption_detected(self):
  c,o=fixture();c["unrooted_halfword_candidate_count"]=4
  with self.assertRaisesRegex(ValueError,"CLASSIFICATION_TOTAL_CHANGED"):classify(c,o)
 def test_overlapping_function_extent_does_not_create_fake_gap(self):
  c,o=fixture()
  o["symbol_function_records"].append({"entry_pc":hex(BASE+4),"size_bytes":0x100,
      "name":"overlapping_function"})
  r=classify(c,o)
  self.assertEqual(r["triage_counts"]["OUTSIDE_NAMED_ELF_EXTENTS_UNJUDGED"],0)
if __name__=="__main__":unittest.main()
