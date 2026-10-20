"""ROM-001 Table1 2025 peer reviewed prior art negative controls."""
import unittest
from rom_p0b_prior_art_2025 import TABLE1,compare
from decision_gate import ROM_SHA
class PriorArt2025Tests(unittest.TestCase):
 def test_exact_table_2025_contains_our_three(self):
  self.assertEqual(
   {0x60033084,0x60033088,0x60033ca0}&set(TABLE1),
   {0x60033084,0x60033088,0x60033ca0})
  self.assertNotIn(0x60033090,TABLE1)
 def test_adjacent_register_not_same_semantics(self):
  self.assertIn(0x60033088,TABLE1)
  self.assertNotIn(0x6003308c,TABLE1)
  self.assertNotIn(0x60033c64,TABLE1)
 def test_address_inside_reserved_window_not_automatically_published(self):
  self.assertNotIn(0x6001c08c,TABLE1)
  self.assertNotIn(0x600061c0,TABLE1)
 def test_fail_on_provenance_drift(self):
  with self.assertRaisesRegex(RuntimeError,"TRM_SOURCE"):
   compare({"schema":"OTHER","source_ROM_SHA256":ROM_SHA})
 def test_fail_on_wrong_ROM_source(self):
  with self.assertRaisesRegex(RuntimeError,"ROM_PIN_DRIFT"):
   compare({"schema":"ROM001_P0B_14_TRM_RESERVED_CLASSIFICATION_V1","source_ROM_SHA256":"mutated"})
if __name__=="__main__":unittest.main()
