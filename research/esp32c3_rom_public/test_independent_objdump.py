"""Synthetic GNU RISC-V disassembly parser tests, independent of ROM output."""
import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from independent_objdump import parse_target_line,parse_objdump

class ObjDumpIndependentParser(unittest.TestCase):
    def test_jump_symbol(self):
        out=parse_target_line("40000018:  2944806f   j  400482ac <example_name>")
        self.assertEqual(out,(0x40000018,0x400482ac,"JUMP"))
    def test_jump_no_aliases(self):
        out=parse_target_line("40000018: 2944806f  jal zero,400482ac <func>")
        self.assertEqual(out,(0x40000018,0x400482ac,"JUMP"))
    def test_not_jump_cannot_fake_success(self):
        out=parse_target_line("40000018: 00000013  nop")
        self.assertEqual(out,(0x40000018,None,"NOT_JUMP"))
    def test_malformed_jump_fails_closed(self):
        out=parse_target_line("40000018: 2944806f  jal zero,unknown")
        self.assertEqual(out,(0x40000018,None,"UNPARSEABLE_BRANCH"))
    def test_without_raw_address_ignored(self):
        self.assertIsNone(parse_target_line("not an instruction line"))
    def test_duplicate_pc_inconsistent_fails(self):
        with self.assertRaisesRegex(RuntimeError,"DUPLICATE"):
            parse_objdump("40000018: 2944806f j 400482ac <a>\n40000018: 2944806f j 400482ae <b>")
if __name__=="__main__":unittest.main()
