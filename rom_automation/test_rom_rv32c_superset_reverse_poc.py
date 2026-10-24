#!/usr/bin/env python3
"""RV32IC pre-disassembly superset graph negative controls and planted call roots."""
import copy,unittest
from rom_boundary_source_seal import CANDIDATE_SCHEMA,digest
from rom_rv32c_superset_reverse_poc import (
  supergraph,seeded_paths,backtrack,inspect,rawmap)

B=0x40000000
JAL8=bytes.fromhex("ef008000")
RET=bytes.fromhex("67800000")
NOP=bytes.fromhex("0100")
MIDWORD=bytes.fromhex("93001934") # 32bit addi with C.JAL-looking 2nd halfword

def pub(data):
 return {"schema":CANDIDATE_SCHEMA,"revision":"esp32c3_rev0_rom.elf",
  "isa":"RISCV32_LE_RV32IMC","root_pc":hex(B),"exec_regions":[
   {"start_pc":hex(B),"raw_hex":data.hex(),"byte_count":len(data),
    "sha256":digest(data)}]}

def oracle(*named):
 return {"revision":"esp32c3_rev0_rom.elf",
   "symbol_function_records":[{"entry_pc":hex(pc),"size_bytes":size,"name":f"f_{pc:x}"}
                              for pc,size in named]}

def unclaimed(dest,source,raw):
 return {"revision":"esp32c3_rev0_rom.elf","unknown_entries":[{
    "pc":hex(dest),"witnesses":[{"from_pc":hex(source),"opcode_hex":raw.hex()}]}]}

class SupersetTests(unittest.TestCase):
 def test_rooted_direct_call_reverse_chain(self):
  data=JAL8+RET+JAL8+RET+NOP+NOP
  nodes,edges,reverse,stoppers=supergraph(pub(data))
  p,_=seeded_paths(nodes,edges,[B])
  path=backtrack(B+8,p)
  self.assertIsNotNone(path)
  self.assertEqual(path[0]["from_pc"],hex(B))
  self.assertEqual(path[0]["to_pc"],hex(B+8))
 def test_no_false_linear_fallthrough_after_return(self):
  data=RET+JAL8+RET+NOP+NOP+NOP
  nodes,edges,reverse,_=supergraph(pub(data))
  p,_=seeded_paths(nodes,edges,[B])
  self.assertNotIn(B+4,p)
  self.assertIsNone(backtrack(B+4,p))
 def test_middle_of_32bit_has_syntactic_node_but_not_rooted(self):
  data=MIDWORD+NOP+NOP+NOP+NOP
  nodes,edges,reverse,_=supergraph(pub(data))
  self.assertIn(B+2,nodes)
  rooted,_=seeded_paths(nodes,edges,[B])
  self.assertNotIn(B+2,rooted)
  self.assertIsNone(backtrack(B+2,rooted))
 def test_bogus_symbol_seed_is_not_boot_execution_proof(self):
  data=RET+JAL8+RET+NOP+NOP+NOP
  nodes,edges,reverse,_=supergraph(pub(data))
  boot,_=seeded_paths(nodes,edges,[B])
  named,_=seeded_paths(nodes,edges,[B+4])
  self.assertNotIn(B+4,boot)
  self.assertIn(B+4,named)
 def test_entire_undecodable_region_does_not_become_node(self):
  data=b"\x00\x00"*10
  nodes,edges,reverse,_=supergraph(pub(data))
  self.assertEqual(len(nodes),0)
 def test_mutated_call_has_no_rooted_direct_target(self):
  data=JAL8+RET+NOP+RET
  nodes,edges,reverse,_=supergraph(pub(data))
  self.assertTrue(any(x[0]==B+8 for x in edges[B]))
  changed=bytearray(data);changed[0]=0x6f # jal x0,+8
  nodes2,edges2,reverse2,_=supergraph(pub(bytes(changed)))
  self.assertFalse(any(x[1]=="DIRECT_CALL" for x in edges2[B]))
 def test_exact_direct_call_witness_and_sealed_oracle_do_not_upgrade_api(self):
  data=JAL8+RET+JAL8+RET+NOP+NOP
  p=pub(data)
  r=inspect(p,oracle((B,8)),unclaimed(B+16,B+8,JAL8))
  self.assertEqual(r["source_grade_counts"].get("ROOTED_AT_ELF_ENTRY_STATIC_SUPERSET_PATH"),1)
  self.assertEqual(r["new_verified_usable_ROM_APIs"],0)
  self.assertFalse(r["source_results"][0]["physical_executability_proven"])
 def test_raw_source_byte_mutation_fails_closed(self):
  data=JAL8+RET+JAL8+RET+NOP+NOP
  with self.assertRaisesRegex(ValueError,"RAW_LINK_MISMATCH_WITH_SUPERGRAPH"):
   inspect(pub(data),oracle((B,8)),unclaimed(B+16,B+8,bytes.fromhex("ef000000")))
 def test_wrong_revision_fails(self):
  data=JAL8+RET+JAL8+RET+NOP+NOP
  bad=oracle((B,8));bad["revision"]="esp32c3_rev3_rom.elf"
  with self.assertRaisesRegex(ValueError,"REVISION_MISMATCH"):
   inspect(pub(data),bad,unclaimed(B+16,B+8,JAL8))
 def test_oracle_symbol_leak_into_raw_input_rejected(self):
  p=pub(JAL8+RET+NOP+RET)
  p["symbol_function_records"]=[{"entry_pc":hex(B)}]
  with self.assertRaisesRegex(ValueError,"CANDIDATE_SCHEMA_TOPLEVEL_FIELDS"):
   supergraph(p)
if __name__=="__main__":unittest.main()
