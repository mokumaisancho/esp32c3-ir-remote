"""Pinned Espressif linker symbols independently corroborate ROM SRAM readsites."""
import json,os,pathlib,unittest
from rom_sram_vendor_symbols import inspect,linker_symbols,EXPECTED_SHA1

ENV=("ROM_VENDOR_LD","ROM_FAST_GRAPH_JSON","ROM_STRICT_JSON","ROM_WRITER_JSON")
class VendorSymbolsTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if not all(os.environ.get(x) for x in ENV):raise unittest.SkipTest("vendor/graph data absent outside dedicated exploratory workflow")
  cls.linker=pathlib.Path(os.environ["ROM_VENDOR_LD"]).read_text()
  cls.graph=json.loads(pathlib.Path(os.environ["ROM_FAST_GRAPH_JSON"]).read_text())
  cls.strict=json.loads(pathlib.Path(os.environ["ROM_STRICT_JSON"]).read_text())
  cls.writer=json.loads(pathlib.Path(os.environ["ROM_WRITER_JSON"]).read_text())
 def test_actual_pinned_vendor_address_and_sample_readers(self):
  result=inspect(self.strict,self.writer,self.graph,self.linker,EXPECTED_SHA1)
  self.assertEqual(result["new_address_variable_names_correlated_per_revision"],2)
  self.assertEqual(result["storage_initializers_proven"],0)
  self.assertEqual(result["physical_callee_execution_proven"],0)
  for rev,v in result["revisions"].items():
   self.assertEqual(v["unresolved_writer_address_count"],9)
   self.assertEqual(v["exact_vendor_name_address_matches"],2)
   self.assertEqual(v["unmapped_addresses"],7)
   self.assertIn("pp_process_hmac_waiting_txq",v["addresses"]["0x3fcdf8d0"]["bounded_ROM_function_consumers"])
   self.assertIn("r_sch_slice_init",v["addresses"]["0x3fcdfc04"]["bounded_ROM_function_consumers"])
 def test_same_name_at_adjacent_address_does_not_count(self):
  lines=linker_symbols(self.linker)
  self.assertEqual(lines[0x3fcdf8d0],["g_net80211_tx_func"])
  self.assertNotIn("g_net80211_tx_func",lines.get(0x3fcdf8cc,[]))
  self.assertEqual(lines[0x3fcdfc04],["rwip_param"])
  self.assertNotIn("rwip_param",lines.get(0x3fcdfc08,[]))
 def test_modified_vendor_bytes_rejected_even_if_digest_parameter_same(self):
  changed=self.linker.replace("g_net80211_tx_func = 0x3fcdf8d0;","g_net80211_tx_func = 0x3fcdf8d4;")
  self.assertNotEqual(changed,self.linker)
  with self.assertRaisesRegex(RuntimeError,"VENDOR_LINKER_CONTENT_SHA_MISMATCH"):
   inspect(self.strict,self.writer,self.graph,changed,EXPECTED_SHA1)
 def test_malformed_external_source_pin_rejected(self):
  with self.assertRaisesRegex(RuntimeError,"VENDOR_GIT_BLOB_PIN_MISMATCH"):
   inspect(self.strict,self.writer,self.graph,self.linker,"not official")
if __name__=="__main__":unittest.main()
