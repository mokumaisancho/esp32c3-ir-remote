"""Synthetic holdouts to prevent turning raw ROM data into false functions."""
import unittest
from rom_p0a_indirect_roots import build_gaps,in_gap,collect_aligned_data_refs
class IndirectRootsTests(unittest.TestCase):
 def test_gapped_intervals_without_overlapping_covered_symbols(self):
  gaps=build_gaps([(0x1000,0x1100)],[(0x1000,0x1020),(0x1040,0x1080),(0x1070,0x1090)])
  self.assertEqual(gaps,[(0x1020,0x1040),(0x1090,0x1100)])
  self.assertTrue(in_gap(gaps,0x1020))
  self.assertFalse(in_gap(gaps,0x1040))
  self.assertFalse(in_gap(gaps,0x1010))
 def test_known_function_entry_must_not_appear_as_unknown_pointer(self):
  gaps=[(0x2000,0x2020)]
  data=(0x1000).to_bytes(4,"little")+(0x2008).to_bytes(4,"little")
  r=collect_aligned_data_refs(data,0x3ff00000,gaps)
  self.assertNotIn(0x1000,r)
  self.assertEqual(r[0x2008],[0x3ff00004])
 def test_off_alignment_word_not_misread_as_pointer_table(self):
  gaps=[(0x2000,0x2020)]
  data=b"0"+(0x2008).to_bytes(4,"little")+b"0"*4
  r=collect_aligned_data_refs(data,0x3ff00000,gaps)
  self.assertEqual(r,{})
 def test_last_pointer_word_in_bounds(self):
  gaps=[(0x2000,0x2020)]
  data=b"x"*4+(0x2000).to_bytes(4,"little")
  r=collect_aligned_data_refs(data,0x3ff00000,gaps)
  self.assertEqual(r[0x2000],[0x3ff00004])
 def test_equal_byte_address_at_end_is_excluded(self):
  gaps=[(0x2000,0x2020)]
  self.assertFalse(in_gap(gaps,0x2020))
  self.assertTrue(in_gap(gaps,0x201e))
 def test_zero_gap_list(self):
  self.assertEqual(build_gaps([(0x1000,0x1020)],[(0x1000,0x1020)]),[])
if __name__=="__main__":unittest.main()
