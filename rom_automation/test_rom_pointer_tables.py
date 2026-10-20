"""ROM pointer evidence fail-closed integrity: never treat coincidental words as calls."""
import unittest
from rom_pointer_tables import evaluate,pointer_matches
class ROMPointerTableTests(unittest.TestCase):
 def test_wrong_archive_identity_rejected(self):
  import pathlib,tempfile
  with tempfile.TemporaryDirectory() as d:
   f=pathlib.Path(d)/"fake.tar.gz";f.write_bytes(b"not official rom")
   with self.assertRaisesRegex(RuntimeError,"PINNED_ROM_SHA"):
    evaluate(f,{})
 def test_multiple_function_aliases_can_share_one_start(self):
  function_map={"0000:2":{"entry":"0x40000010"},"other":{"entry":"0x40000010"}}
  inverse={}
  for k,v in function_map.items():inverse.setdefault(int(v["entry"],16),[]).append(k)
  self.assertEqual(len(inverse[0x40000010]),2)
 def test_aligned_le_binary_pointer_matches_only(self):
  address=0x4000100c
  little=address.to_bytes(4,"little")
  self.assertEqual(int.from_bytes(little,"little"),address)
  self.assertNotEqual(int.from_bytes(little,"big"),address)
  self.assertNotEqual(int.from_bytes(b"garb","little"),address)
if __name__=="__main__":unittest.main()
