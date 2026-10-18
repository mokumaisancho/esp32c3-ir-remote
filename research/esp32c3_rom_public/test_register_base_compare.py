"""Synthetic base-register fixtures; no targets copied from analyzed ROM."""
import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from register_base_compare import read_bases, classify_mmio

SYNTHETIC = """
#define DR_REG_ALPHA_BASE   0x60002000
#define DR_REG_BRAVO_BASE   0x60005000
#define DR_REG_BRAVO_OLD_BASE 0x60005000
#define NOT_A_BASE 0x60007000
"""

class TestOfficialBaseComparison(unittest.TestCase):
    def test_parse_independent_synthetic_bases(self):
        b=read_bases(SYNTHETIC)
        self.assertEqual(set(b),{0x60002000,0x60005000})
        self.assertEqual(len(b[0x60005000]),2)
    def test_positive_within_peripheral_window(self):
        b=read_bases(SYNTHETIC)
        x=classify_mmio("0x6000203c",b)
        self.assertEqual(x["base"],"0x60002000")
        self.assertEqual(x["offset"],"0x3c")
    def test_negative_no_covering_base(self):
        x=classify_mmio("0x60004000",read_bases(SYNTHETIC))
        self.assertEqual(x["classification"],"BASE_WINDOW_UNRESOLVED")
        self.assertIsNone(x["base"])
    def test_exclusive_window_end(self):
        x=classify_mmio("0x60003000",read_bases(SYNTHETIC))
        self.assertEqual(x["classification"],"BASE_WINDOW_UNRESOLVED")
    def test_farthest_nearest_base(self):
        b=read_bases(SYNTHETIC)
        self.assertEqual(classify_mmio("0x60005000",b)["bases"],
                         ["DR_REG_BRAVO_BASE","DR_REG_BRAVO_OLD_BASE"])
    def test_invalid_or_empty_baseline_fails(self):
        with self.assertRaises(ValueError):
            read_bases("#define DR_REG_ALPHA_BASE not_an_address")
if __name__=="__main__":
    unittest.main()
