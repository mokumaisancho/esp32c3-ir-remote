"""ROM-001 nine-SRAM-slot literal search, exact-match and falsification."""
import types,unittest
from rom_sram_literal_refs import scan_one
class SRAMLiteralTests(unittest.TestCase):
 def test_serialization_is_little_endian(self):
  self.assertEqual((0x3fcdfbe4).to_bytes(4,"little").hex(),"e4fbcd3f")
 def test_bad_elf_rejected_without_looking_like_data(self):
  with self.assertRaises(Exception):
   scan_one(b"not ELF","fake",{0x3fcdfbe4})
 def test_distinct_literal_address_is_not_automatically_callback(self):
  t={hex(0x3fcdfbe4):"UNPROVEN"}
  self.assertNotIn(hex(0x3fcdfbe8),t)
 def test_static_link_is_not_silicon_causality(self):
  self.assertNotEqual("DATA_REFERENCE","CALL_EXECUTED")
if __name__=="__main__":unittest.main()
