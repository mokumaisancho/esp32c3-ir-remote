"""ROM-001 P0-B: independent raw-byte MMIO negative controls and base coverage."""
import unittest
from rom_mmio_revision_diff import bases,REG_BASE
from rom_mmio import scan_adjacent
from rom_opcode import csr_number

def lui(reg,upper):
 return (upper|(reg<<7)|0x37).to_bytes(4,"little")
def store(rs,base,offset):
 u=offset&0xfff
 w=((u>>5)<<25)|(rs<<20)|(base<<15)|(2<<12)|((u&31)<<7)|0x23
 return w.to_bytes(4,"little")

class MMIODifferentialTests(unittest.TestCase):
 def test_known_official_base_file_is_used(self):
  b=bases(REG_BASE.read_text())
  self.assertGreater(len(b),30)
  self.assertEqual(b[0x60024000],"DR_REG_SPI2_BASE")
 def test_byte_encoded_spi2_store(self):
  pc=0x40001000;inst=[(pc,lui(5,0x60024000)),(pc+4,store(10,5,0x9c))]
  x=scan_adjacent(inst)
  self.assertEqual(len(x),1)
  self.assertEqual(x[0]["address"],"0x6002409c")
  self.assertEqual(x[0]["kind"],"store")
 def test_mutated_register_not_credit_mmio(self):
  pc=0x40001000;inst=[(pc,lui(5,0x60024000)),(pc+4,store(10,6,0x9c))]
  self.assertEqual(scan_adjacent(inst),[])
 def test_mutated_peripheral_base_not_implicitly_vendor_supported(self):
  b=bases(REG_BASE.read_text())
  self.assertNotIn(0x6002409c,b)
  self.assertIn(0x60024000,b)
 def test_csr_not_memory_instruction(self):
  self.assertIsNone(csr_number(lui(5,0x60024000)))
if __name__=="__main__":unittest.main()
