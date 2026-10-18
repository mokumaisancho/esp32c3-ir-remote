"""Independent synthetic parser fixtures; not copied from ESP-IDF target headers."""
import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from exact_register_headers import parse_exact_registers

class TestExactRegisterOffsets(unittest.TestCase):
    def test_pure_constant_offset(self):
        x,u=parse_exact_registers("#define TEST_CONTROL_REG (DR_REG_EXAMPLE_BASE + 0x24)",
          {"DR_REG_EXAMPLE_BASE":0x60002000})
        self.assertEqual(x,[(0x60002024,"TEST_CONTROL_REG","DR_REG_EXAMPLE_BASE")])
        self.assertEqual(u,[])
    def test_unresolved_macro_retained(self):
        x,u=parse_exact_registers("#define TEST_CONTROL_REG (DR_REG_OTHER_BASE + 0x24)",
          {"DR_REG_EXAMPLE_BASE":0x60002000})
        self.assertEqual(x,[])
        self.assertEqual(u[0]["base_macro"],"DR_REG_OTHER_BASE")
    def test_computed_address_not_fabricated(self):
        x,u=parse_exact_registers("#define TEST_CONTROL_REG (REG_SPI_MEM_BASE(i) + 0x24)",
          {"DR_REG_EXAMPLE_BASE":0x60002000})
        self.assertEqual((x,u),([],[]))
    def test_symbol_without_reg_suffix_ignored(self):
        x,u=parse_exact_registers("#define TEST_CONTROL (DR_REG_EXAMPLE_BASE + 0x24)",
          {"DR_REG_EXAMPLE_BASE":0x60002000})
        self.assertEqual((x,u),([],[]))
    def test_decimal_offset(self):
        x,u=parse_exact_registers("#define TEST_CONTROL_REG (DR_REG_EXAMPLE_BASE + 32)",
          {"DR_REG_EXAMPLE_BASE":0x60002000})
        self.assertEqual(x[0][0],0x60002020)
if __name__=="__main__":
    unittest.main()
