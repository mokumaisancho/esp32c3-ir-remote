import unittest
from idf_known_inventory import linker_symbols, macros_and_declarations, address_expr

class KnownInventoryTests(unittest.TestCase):
    def test_numeric_symbol_and_comment_exclusion(self):
        sample="/* old_fn = 0x40001234; */\nvalid_fn = 0x40000018;\n"
        rows=linker_symbols(sample,"v4.4.8","components/esp_rom/esp32c3/ld/esp32c3.rom.ld")
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["symbol"],"valid_fn")
        self.assertEqual(rows[0]["address"],"0x40000018")
    def test_symbolic_alias(self):
        rows=linker_symbols("PROVIDE ( esp_rom_crc32_le = crc32_le );\n","v5.5.1","x.ld")
        self.assertEqual(rows[0]["symbol"],"esp_rom_crc32_le")
        self.assertEqual(rows[0]["alias_of"],"crc32_le")
    def test_eco_version_not_assumed_universal(self):
        rows=linker_symbols("some_fn = 0x40001000;\n","v5.5.1","esp32c3.rom.eco3.ld")
        self.assertEqual(rows[0]["ld_scope"],"REVISION_OR_ECO_SPECIFIC")
    def test_numeric_reg_formula(self):
        self.assertEqual(address_expr("(DR_REG_SYSTEM_BASE + 0x24)",{"DR_REG_SYSTEM_BASE":0x600c0000}),0x600c0024)
    def test_unresolved_reg_never_guess(self):
        self.assertIsNone(address_expr("(UNKNOWN_BASE + 0x24)",{}))
    def test_expression_rejects_code(self):
        self.assertIsNone(address_expr("__import__('os').system('true')",{}))
    def test_macro_and_prototype_evidence_separate(self):
        macros,decl=macros_and_declarations("#define DR_REG_SYSTEM_BASE 0x600c0000\nextern int test_fn(void);\n","now","header.h")
        self.assertEqual(macros[0]["name"],"DR_REG_SYSTEM_BASE")
        self.assertEqual([x["symbol"] for x in decl],["test_fn"])
    def test_macro_function_not_a_value(self):
        macros,_=macros_and_declarations("#define BIT(n) (1 << (n))\n","now","header.h")
        self.assertFalse(any(x["name"]=="BIT" for x in macros))

if __name__=="__main__":unittest.main()
