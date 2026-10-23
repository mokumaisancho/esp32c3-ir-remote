#!/usr/bin/env python3
"""ROM-003 source attestation mutation controls, not a discovery oracle."""
import copy,json,os,pathlib,unittest
from rom_boundary_byte_frontier import direct
from rom_boundary_source_seal import CANDIDATE_SCHEMA,digest
from rom_unclaimed_source_attestation import source_alignment,audit

BASE=0x40000000
CALL=bytes.fromhex("ef008000")
SECOND_HALF_CJAL=bytes.fromhex("1934")
SOURCE=BASE+2

def input_bytes(raw):
 return {"schema":CANDIDATE_SCHEMA,"revision":"esp32c3_rev0_rom.elf",
  "isa":"RISCV32_LE_RV32IMC","root_pc":hex(BASE),"exec_regions":[
    {"start_pc":hex(BASE),"raw_hex":raw.hex(),"byte_count":len(raw),
     "sha256":digest(raw)}]}

def data(raw,source,entry,source_bytes):
 pub=input_bytes(raw)
 ref={"revision":pub["revision"],"symbol_function_records":[
  {"entry_pc":hex(BASE),"size_bytes":4,"name":"known_func"}]}
 c={"revision":pub["revision"],"candidate_records":[
  {"entry_pc":hex(entry),"rooted_call_witnesses":0,"encoded_link_sources":1,
   "machine_first_instruction":{"pc":hex(entry),"raw":"0100","opcode":"c.nop","length":2},
   "witnesses":[{"from_pc":hex(source),"opcode_hex":source_bytes.hex(),
    "source_provenance":"UNROOTED_RAW_HALFWORD_MAY_BE_DATA"}]}],
  "ranked_possible_entries":[hex(entry)],"unrooted_halfword_candidate_count":1}
 return c,ref,pub

class CandidateSourceProof(unittest.TestCase):
 def test_second_half_of_real_32bit_instruction_is_not_named_call(self):
  raw=bytes.fromhex("93001934")+b"\x01\x00"*8
  r=source_alignment([(BASE,raw)],SOURCE,SECOND_HALF_CJAL,[(BASE,BASE+4)])
  self.assertEqual(r["classification"],"INSIDE_32BIT_INSTRUCTION_FROM_NAMED_ENTRY")
  self.assertEqual(r["straddling_raw"],raw[:4].hex())
  self.assertFalse(r["symbol_linear_boundary_proven"])
 def test_valid_linear_named_call_does_not_become_runtime_proof(self):
  raw=CALL+b"\x01\x00"*10
  r=source_alignment([(BASE,raw)],BASE,CALL,[(BASE,BASE+4)])
  self.assertEqual(r["classification"],"ELF_NAMED_LINEAR_CALL_SYNTAX_NOT_ROOTED")
  self.assertFalse(r["independent_reachable_execution_proven"])
 def test_named_second_half_pseudo_call_is_not_new_function(self):
  raw=bytes.fromhex("93001934")+b"\x01\x00"*8
  dest=direct(SECOND_HALF_CJAL,SOURCE)[0]
  c,g,p=data(raw,SOURCE,dest,SECOND_HALF_CJAL)
  r=audit(c,g,p)
  self.assertEqual(r["unclaimed_candidates"],1)
  self.assertEqual(r["witness_source_categories"]["INSIDE_32BIT_INSTRUCTION_FROM_NAMED_ENTRY"],1)
  self.assertEqual(r["candidates_with_independent_rooted_proof"],0)
 def test_source_without_named_extent_stays_unverified(self):
  raw=CALL+SECOND_HALF_CJAL+b"\x01\x00"*10
  source=BASE+4
  pc=direct(SECOND_HALF_CJAL,source)[0]
  c,g,p=data(raw,source,pc,SECOND_HALF_CJAL)
  # Inject exact source candidate bits only at unclaimed address; still not proven.
  r=audit(c,g,p)
  self.assertEqual(r["witness_source_categories"]["NO_ELF_NAMED_SOURCE"],1)
 def test_revision_mismatch_rejected(self):
  raw=bytes.fromhex("93001934")+b"\x01\x00"*8
  dest=direct(SECOND_HALF_CJAL,SOURCE)[0]
  c,g,p=data(raw,SOURCE,dest,SECOND_HALF_CJAL)
  g["revision"]="esp32c3_rev101_rom.elf"
  with self.assertRaisesRegex(ValueError,"REVISION_DRIFT"):audit(c,g,p)
 def test_byte_witness_not_independently_matching_pair_rejected(self):
  raw=bytes.fromhex("93001934")+b"\x01\x00"*8
  dest=direct(SECOND_HALF_CJAL,SOURCE)[0]
  c,g,p=data(raw,SOURCE,dest,SECOND_HALF_CJAL)
  c["candidate_records"][0]["witnesses"][0]["opcode_hex"]=bytes.fromhex("1930").hex()
  with self.assertRaisesRegex(ValueError,"WITNESS_NOT_A_BYTE_CORRECT_CALL"):audit(c,g,p)
 def test_fabricated_raw_source_witness_rejected_even_without_named_symbol(self):
  raw=CALL+b"\x01\x00"*10
  source=BASE+4
  dest=direct(SECOND_HALF_CJAL,source)[0]
  c,g,p=data(raw,source,dest,SECOND_HALF_CJAL)
  with self.assertRaisesRegex(ValueError,"SOURCE_WITNESS_BYTES_DO_NOT_MATCH_OFFICIAL_ROM"):
   audit(c,g,p)
 def test_merged_duplicate_names_do_not_double_witness(self):
  raw=bytes.fromhex("93001934")+b"\x01\x00"*8
  dest=direct(SECOND_HALF_CJAL,SOURCE)[0]
  c,g,p=data(raw,SOURCE,dest,SECOND_HALF_CJAL)
  g["symbol_function_records"].append({"entry_pc":hex(BASE),"size_bytes":4,"name":"alias"})
  self.assertEqual(audit(c,g,p)["total_raw_incoming_witnesses"],1)
 def test_unsupported_oracle_in_generator_fields_fails(self):
  raw=bytes.fromhex("93001934")+b"\x01\x00"*8
  dest=direct(SECOND_HALF_CJAL,SOURCE)[0]
  c,g,p=data(raw,SOURCE,dest,SECOND_HALF_CJAL)
  p["symbol_function_records"]=g["symbol_function_records"]
  with self.assertRaisesRegex(ValueError,"CANDIDATE_SCHEMA_TOPLEVEL_FIELDS"):audit(c,g,p)
 def test_actual_three_rom_provenance_counts(self):
  root=os.environ.get("ROM003_T5_REAL_DIR")
  if not root:self.skipTest("Full ROM artifacts not available")
  from rom_boundary_blind_evaluator import REVS
  path=pathlib.Path(root)
  counter=0
  for rev in REVS:
   c=json.loads((path/"candidates"/(rev+".json")).read_text())
   g=json.loads((path/"oracle"/(rev+".json")).read_text())
   p=json.loads((path/"raw"/(rev+".json")).read_text())
   result=audit(c,g,p)
   self.assertEqual(result["unclaimed_candidates"],{"esp32c3_rev0_rom.elf":81,
     "esp32c3_rev101_rom.elf":76,"esp32c3_rev3_rom.elf":95}[rev])
   self.assertEqual(result["candidates_with_independent_rooted_proof"],0)
   counter+=result["total_raw_incoming_witnesses"]
  self.assertEqual(counter,260)
if __name__=="__main__":unittest.main()
