"""MMIO negative/positive oracle is synthetic, separate from ESP32-C3 ROM input."""
import pathlib, sys, unittest, struct
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from rom_mmio import scan_adjacent

def w(v):
    return struct.pack("<I",v)

class MMIOTests(unittest.TestCase):
    def test_positive_lui_load(self):
        seq=[(0x100,w(0x600032b7)),(0x104,w(0x0542a083))]
        out=scan_adjacent(seq)
        self.assertEqual(len(out),1)
        self.assertEqual(out[0]["address"],"0x60003054")
        self.assertEqual(out[0]["kind"],"load")
        self.assertEqual(out[0]["pattern"],"LUI_ACCESS")
    def test_negative_base_register_mismatch(self):
        seq=[(0x100,w(0x600032b7)),(0x104,w(0x05432083))]
        self.assertEqual(scan_adjacent(seq),[])
    def test_negative_bad_opcode(self):
        seq=[(0x100,w(0x600032b7)),(0x104,w(0x00000013))]
        self.assertEqual(scan_adjacent(seq),[])
    def test_negative_noncontiguous_instructions(self):
        seq=[(0x100,w(0x600032b7)),(0x108,w(0x0542a083))]
        self.assertEqual(scan_adjacent(seq),[])
    def test_negative_ordinary_ram(self):
        seq=[(0x100,w(0x3fc002b7)),(0x104,w(0x0542a083))]
        self.assertEqual(scan_adjacent(seq),[])
    def test_negative_truncated(self):
        seq=[(0x100,b"\x00\x00"),(0x104,w(0x0542a083))]
        self.assertEqual(scan_adjacent(seq),[])
    def test_lui_addi_load(self):
        # LUI t0,0x60003 ; ADDI t0,t0,4 ; LW ra,0x50(t0)
        seq=[(0x100,w(0x600032b7)),(0x104,w(0x00428293)),(0x108,w(0x0502a083))]
        out=scan_adjacent(seq)
        self.assertEqual(len(out),1)
        self.assertEqual(out[0]["address"],"0x60003054")
        self.assertEqual(out[0]["pattern"],"LUI_ADDI_ACCESS")
    def test_negative_lui_addi_wrong_destination(self):
        # ADDI updates t1 instead, so not a proved t0 chain
        seq=[(0x100,w(0x600032b7)),(0x104,w(0x00428313)),(0x108,w(0x0502a083))]
        self.assertEqual(scan_adjacent(seq),[])

if __name__=="__main__":
    unittest.main()
