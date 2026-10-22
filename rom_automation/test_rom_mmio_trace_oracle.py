#!/usr/bin/env python3
"""ROM-002 negative controls: outcomes from supplied events are not hardware PASS."""
import copy
import json
import os
import pathlib
import random
import unittest

from rom_mmio_trace_oracle import MODELS,audit,classify,computed

FIXTURE=pathlib.Path(__file__).with_name("fixtures")/"rom_mmio_synthetic_trace_v1.json"

def good():
 return json.loads(FIXTURE.read_text(encoding="utf-8"))

class ROM002PassiveTraceOracleTests(unittest.TestCase):
 def test_positive_synthetic_four_records(self):
  r=audit(good())
  self.assertEqual(r["total_pairs"],4)
  self.assertEqual(r["consistent_pairs"],4)
  self.assertEqual(r["contradictory_pairs"],0)
  self.assertTrue(r["all_pairs_consistent_with_static_model"])
 def test_synthetic_cannot_become_emulator_or_silicon_pass(self):
  r=audit(good())
  self.assertFalse(r["actual_emulator_execution_verified"])
  self.assertFalse(r["hardware_behavior_verified"])
  self.assertFalse(r["input_source_kind_independently_attested"])
  self.assertEqual(r["input_source_kind_claimed"],"synthetic")
 def test_claimed_silicon_origin_is_not_attested(self):
  payload=good()
  payload["source_kind"]="silicon"
  r=audit(payload)
  self.assertFalse(r["input_source_kind_independently_attested"])
  self.assertFalse(r["hardware_behavior_verified"])
 def test_wrong_store_value_is_detected_not_mistaken_as_pass(self):
  data=good()
  data["samples"][1]["events"][1]["value"]="0xdead5554"
  r=audit(data)
  self.assertEqual(r["contradictory_pairs"],1)
  self.assertEqual(r["contradictory_sample_ids"],["rev0_fe_deadbeef"])
  self.assertFalse(r["all_pairs_consistent_with_static_model"])
 def test_unknown_address_rejected(self):
  sample=good()["samples"][0]
  sample["events"][1]["address"]="0x600061c8"
  with self.assertRaisesRegex(ValueError,"ADDRESS_MISMATCH"):classify(sample)
 def test_wrong_pc_rejected(self):
  sample=good()["samples"][0]
  sample["events"][0]["pc"]="0x4003ba78"
  with self.assertRaisesRegex(ValueError,"REVISION_OR_PC_MISMATCH"):classify(sample)
 def test_revision_swap_rejected(self):
  sample=good()["samples"][0]
  sample["case"]="rev101_wifi"
  with self.assertRaisesRegex(ValueError,"REVISION_OR_PC_MISMATCH"):classify(sample)
 def test_out_of_order_write_is_error(self):
  sample=good()["samples"][0]
  sample["events"].reverse()
  with self.assertRaisesRegex(ValueError,"INVALID_EVENT_ORDER"):classify(sample)
 def test_missing_observed_read_is_error(self):
  sample=good()["samples"][0]
  sample["events"]=sample["events"][1:]
  with self.assertRaisesRegex(ValueError,"EXACTLY_ONE_READ_AND_WRITE_REQUIRED"):classify(sample)
 def test_invalid_hex_is_error(self):
  sample=good()["samples"][0]
  sample["events"][0]["value"]="00x1234"
  with self.assertRaisesRegex(ValueError,"MALFORMED_HEX"):classify(sample)
 def test_non_32_bit_register_values_fail(self):
  sample=good()["samples"][0]
  sample["events"][0]["value"]="0x100000000"
  with self.assertRaisesRegex(ValueError,"NOT_32_BIT"):classify(sample)
 def test_duplicate_sample_names_fail(self):
  sample=good()
  sample["samples"][1]["sample_id"]=sample["samples"][0]["sample_id"]
  with self.assertRaisesRegex(ValueError,"DUPLICATE_SAMPLE_ID"):audit(sample)
 def test_unsupported_hypothetical_case_is_error(self):
  sample=good()["samples"][0]
  sample["case"]="rev3_new_rf"
  with self.assertRaisesRegex(ValueError,"UNKNOWN_CASE"):classify(sample)
 def test_adversarial_extra_fields_fail(self):
  sample=good()["samples"][0]
  sample["silicon_verified"]=True
  with self.assertRaisesRegex(ValueError,"UNEXPECTED_FIELDS"):classify(sample)
 def test_root_schema_cannot_be_spoofed(self):
  data=good()
  data["schema"]="ROM003_UNREVIEWED"
  with self.assertRaisesRegex(ValueError,"TRACE_SCHEMA_DRIFT"):audit(data)
 def test_synthetic_arithmetic_noninvasive_coverage(self):
  rng=random.Random(20261023)
  for case in MODELS:
   for old in [0,1,0xff,0x100,0xffff,0x10000,0xaaaaaaaa,0x55555555,0xffffffff]:
    result=computed(case,old)
    self.assertGreaterEqual(result,0)
    self.assertLessEqual(result,0xffffffff)
   for _ in range(10000):
    old=rng.getrandbits(32)
    result=computed(case,old)
    if case=="rev0_fe":
     self.assertEqual(result>>16,old>>16)
     self.assertEqual(result&0xffff,0x5555)
    else:
     self.assertEqual(result&~0xf0,old&~0xf0)
     self.assertEqual(result&0xf0,0xf0)
 def test_real_fixture_not_required_to_import(self):
  # Generic unit-test discovery must not rely on external ROM archive or device.
  self.assertTrue(FIXTURE.is_file())
 def test_mismatch_in_multiple_samples_are_all_reported(self):
  data=good()
  data["samples"][0]["events"][1]["value"]="0x0"
  data["samples"][3]["events"][1]["value"]="0x12345678"
  out=audit(data)
  self.assertEqual(out["contradictory_pairs"],2)
  self.assertEqual(len(out["contradictory_sample_ids"]),2)
 def test_no_empty_sample_list(self):
  data=good();data["samples"]=[]
  with self.assertRaisesRegex(ValueError,"SAMPLE_COUNT_OUT_OF_RANGE"):audit(data)
 def test_no_malformed_origin(self):
  data=good();data["source_kind"]="external_proven"
  with self.assertRaisesRegex(ValueError,"UNKNOWN_ORIGIN_LABEL"):audit(data)

if __name__=="__main__":
 unittest.main()
