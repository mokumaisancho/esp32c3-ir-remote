"""ROM-001: exact independent-fail-closed tests for exploratory ROM census."""
import pathlib, tempfile, unittest
from new_function_hunt import merged,clipped_coverage,name_inventory,evaluate,is_compiler_local_name
from decision_gate import REVS
from rom_opcode import jal,compressed_jump

class ExploratoryDiscoveryTests(unittest.TestCase):
 def test_prior_catalog_formats_and_false_matches(self):
  a={"repo":"eggfly/esp32c3_baremetal"}
  b={"repo":"motokultivator/ll-applications"}
  c={"repo":"psifertex/bnesp32"}
  self.assertEqual(name_inventory("40001000 T known_function\n",a),{"known_function"})
  self.assertEqual(name_inventory("known_function = 0x40001000;\n",b),{"known_function"})
  self.assertEqual(name_inventory('{"functions":{"0x40001000":"known_function"}}',c),{"known_function"})
  self.assertNotIn("known",name_inventory("40001000 T known_function\n",a))
 def test_elf_function_coverage_is_independent_of_gaps(self):
  ranges=[(0,100),(200,300)]
  sym=[(10,40),(20,50),(250,260)]
  self.assertEqual(clipped_coverage(ranges,sym),[(10,50),(250,260)])
  self.assertEqual(sum(b-a for a,b in clipped_coverage(ranges,sym)),50)
  self.assertEqual(200-50,150)
 def test_merge_overlapping_and_adjacent(self):
  self.assertEqual(merged([(2,5),(5,10),(1,3)]),[(1,10)])
  with self.assertRaisesRegex(RuntimeError,"INVALID_ELF_FUNCTION_RANGE"):
   merged([(7,7)])
 def test_known_gcc_local_symbols_not_features(self):
  self.assertTrue(is_compiler_local_name("check_condCOUNTER.3042"))
  self.assertTrue(is_compiler_local_name("check_condCOUNTER.5151"))
  self.assertFalse(is_compiler_local_name("rom2_phy_get_tsens_value"))
  self.assertFalse(is_compiler_local_name("check_condCOUNTER_extra"))
 def test_raw_jal_not_name_based(self):
  self.assertEqual(jal(bytes.fromhex("ef000000"),0x40000000),0x40000000)
  self.assertIsNone(jal(bytes.fromhex("00000000"),0x40000000))
 def test_bad_provenance_fails_before_results(self):
  with tempfile.TemporaryDirectory() as td:
   a=pathlib.Path(td)/"invalid-rom.tar.gz";a.write_bytes(b"made-up-content")
   b=pathlib.Path(td)/"invalid-machine.zip";b.write_bytes(b"made-up-content")
   with self.assertRaisesRegex(RuntimeError,"OFFICIAL_ELF_ARCHIVE_SHA"):
    evaluate(a,b,{},{})

if __name__=="__main__":unittest.main()
