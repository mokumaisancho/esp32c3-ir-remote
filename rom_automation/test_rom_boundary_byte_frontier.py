#!/usr/bin/env python3
"""E1: actual RV32I/C bytes, roots vs unrooted syntactically valid code-looking data."""
import copy,unittest
from rom_boundary_source_seal import CANDIDATE_SCHEMA,digest
from rom_boundary_byte_frontier import analyze,direct

BASE=0x40000000
RET=bytes.fromhex("67800000")
CALL8=bytes.fromhex("ef008000") # jal ra, +8
NOP=bytes.fromhex("0100")
B8=bytes.fromhex("63040000") # beq zero,zero,+8

def inp(raw):
 return {"schema":CANDIDATE_SCHEMA,"revision":"esp32c3_rev0_rom.elf",
   "isa":"RISCV32_LE_RV32IMC","root_pc":hex(BASE),"exec_regions":[{
    "start_pc":hex(BASE),"raw_hex":raw.hex(),"byte_count":len(raw),"sha256":digest(raw)}]}

class ByteFrontierTest(unittest.TestCase):
 def test_jal_link_bit_and_signed_immediate(self):
  self.assertEqual(direct(CALL8,BASE),(BASE+8,"DIRECT_CALL"))
  self.assertEqual(direct(B8,BASE),(BASE+8,"BASIC_BLOCK_BRANCH"))
 def test_rooted_call_recovers_machine_byte_candidate(self):
  raw=CALL8+RET+NOP+RET
  result=analyze(inp(raw))
  self.assertIn(hex(BASE+8),result["rooted_entry_candidates"])
  self.assertIn(hex(BASE+8),result["ranked_possible_entries"])
  row=next(x for x in result["candidate_records"] if x["entry_pc"]==hex(BASE+8))
  self.assertGreaterEqual(row["rooted_call_witnesses"],1)
  self.assertFalse(row["real_function_proven"])
  self.assertEqual(row["witnesses"][0]["opcode_hex"],CALL8.hex())
 def test_basic_block_branch_not_function_start(self):
  result=analyze(inp(B8+RET+NOP+RET))
  self.assertIn(hex(BASE+8),result["rooted_basic_block_only_targets"])
  self.assertNotIn(hex(BASE+8),result["rooted_entry_candidates"])
  self.assertNotIn(hex(BASE+8),result["ranked_possible_entries"])
 def test_unrooted_code_looking_data_not_promoted(self):
  raw=RET+CALL8+NOP+NOP+NOP
  result=analyze(inp(raw))
  self.assertEqual(result["rooted_entry_candidates"],[])
  row=next(x for x in result["candidate_records"] if x["entry_pc"]==hex(BASE+12))
  self.assertEqual(row["rooted_call_witnesses"],0)
  self.assertEqual(row["witnesses"][0]["source_provenance"],"UNROOTED_RAW_HALFWORD_MAY_BE_DATA")
  self.assertFalse(row["real_function_proven"])
 def test_corrupted_call_opcode_removes_proven_rooted_entry(self):
  raw=CALL8+RET+NOP+RET
  changed=bytearray(raw);changed[0]^=0x02
  result=analyze(inp(bytes(changed)))
  self.assertNotIn(hex(BASE+8),result["rooted_entry_candidates"])
 def test_mutated_input_sha_fail_closed(self):
  data=inp(CALL8+RET+NOP+RET)
  data["exec_regions"][0]["raw_hex"]="0100"+data["exec_regions"][0]["raw_hex"][4:]
  with self.assertRaisesRegex(ValueError,"CANDIDATE_BYTES_HASH_MISMATCH"):analyze(data)
 def test_symbol_boundary_leak_rejected(self):
  data=inp(CALL8+RET+NOP+RET);data["function_start"]=hex(BASE+8)
  with self.assertRaisesRegex(ValueError,"CANDIDATE_SCHEMA_TOPLEVEL_FIELDS"):analyze(data)
 def test_clipping_destination_outside_region_rejected(self):
  data=inp(CALL8+RET)
  result=analyze(data)
  self.assertEqual(result["rooted_entry_candidates"],[])
  self.assertEqual(result["ranked_possible_entries"],[])
  self.assertTrue(any(x["reason"]=="OUT_OF_EXEC_DIRECT_TARGET" for x in result["unresolved"]))
 def test_raw_scan_does_not_mistake_nonlink_jal_as_call(self):
  # jal x0, +8 : same offset but no return address link
  raw=bytes.fromhex("6f008000")+RET+NOP+RET
  result=analyze(inp(raw))
  self.assertNotIn(hex(BASE+8),result["ranked_possible_entries"])
 def test_output_has_no_private_evaluator_name(self):
  result=analyze(inp(CALL8+RET+NOP+RET))
  for prohibited in ("symbol_function_records","aliases","function_size","oracle_sha256"):
   self.assertNotIn(prohibited,str(result))
if __name__=="__main__":unittest.main()
