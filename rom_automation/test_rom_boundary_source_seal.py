#!/usr/bin/env python3
"""E0 controls: real ELF symbol-name mutation leaves raw executable input fixed."""
import copy
import hashlib
import io
import json
import os
import pathlib
import tarfile
import unittest
from elftools.elf.elffile import ELFFile
from rom_boundary_source_seal import (
 CANDIDATE_SCHEMA,REVS,digest,source_from_elf,split_official_archive,
 validate_candidate_input,write_split,
)

def small_candidate():
 return {"schema":CANDIDATE_SCHEMA,"revision":REVS[0],
 "isa":"RISCV32_LE_RV32IMC","root_pc":"0x40000000",
 "exec_regions":[{"start_pc":"0x40000000","raw_hex":"01000100",
  "byte_count":4,"sha256":digest(bytes.fromhex("01000100"))}]}

class RawOnlyBoundaryOracleTests(unittest.TestCase):
 def test_candidate_whitelisted_schema(self):
  self.assertTrue(validate_candidate_input(small_candidate()))
 def test_injected_function_start_is_rejected(self):
  inp=small_candidate();inp["symbolic_function_starts"]=["0x40001000"]
  with self.assertRaisesRegex(ValueError,"CANDIDATE_SCHEMA_TOPLEVEL_FIELDS"):
   validate_candidate_input(inp)
 def test_injected_entry_inside_region_is_rejected(self):
  inp=small_candidate();inp["exec_regions"][0]["function_name"]="secret"
  with self.assertRaisesRegex(ValueError,"CANDIDATE_REGION_FIELD_LEAK"):
   validate_candidate_input(inp)
 def test_modified_machine_bytes_rejected(self):
  inp=small_candidate();inp["exec_regions"][0]["raw_hex"]="01000300"
  with self.assertRaisesRegex(ValueError,"CANDIDATE_BYTES_HASH_MISMATCH"):
   validate_candidate_input(inp)
 def test_bad_candidate_sha_rejected(self):
  inp=small_candidate();inp["exec_regions"][0]["sha256"]="0"*64
  with self.assertRaisesRegex(ValueError,"CANDIDATE_BYTES_HASH_MISMATCH"):
   validate_candidate_input(inp)
 def test_wrong_revision_fails(self):
  inp=small_candidate();inp["revision"]="esp32c3_rev5_rom.elf"
  with self.assertRaisesRegex(ValueError,"CANDIDATE_IDENTITY"):
   validate_candidate_input(inp)
 def test_wrong_isa_fails(self):
  inp=small_candidate();inp["isa"]="RISCV64"
  with self.assertRaisesRegex(ValueError,"CANDIDATE_IDENTITY"):
   validate_candidate_input(inp)
 def test_wrong_archive_fails_before_any_elf_use(self):
  import tempfile
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/"fake.tar.gz";p.write_bytes(b"untrusted")
   with self.assertRaisesRegex(ValueError,"OFFICIAL_ARCHIVE_HASH_DRIFT"):
    split_official_archive(p)
 def test_three_pinned_roms_real_source_and_label_mutation(self):
  file=os.environ.get("ROM003_E0_PINNED_ARCHIVE")
  if not file:self.skipTest("Pinned official ROM tar not provided")
  p=pathlib.Path(file)
  sources=split_official_archive(p)
  self.assertEqual(set(sources),set(REVS))
  for revision,(candidate,oracle) in sources.items():
   self.assertTrue(validate_candidate_input(candidate))
   self.assertNotIn("symbol_function_records",candidate)
   self.assertGreater(len(oracle["symbol_function_records"]),1000)
   self.assertGreater(sum(r["byte_count"] for r in candidate["exec_regions"]),8192)
  # Operate on the real vendor ELF, mutating the nonexecuting .strtab ONLY.
  with tarfile.open(p,mode="r:gz") as archive:
   rev=REVS[1]
   members=[m for m in archive.getmembers()
            if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   self.assertEqual(len(members),1)
   raw=archive.extractfile(members[0]).read()
  e=ELFFile(io.BytesIO(raw))
  chosen=None
  for sect in e.iter_sections():
   if sect["sh_type"]!="SHT_SYMTAB":continue
   tab=e.get_section(int(sect["sh_link"]))
   strings=tab.data()
   for sym in sect.iter_symbols():
    name=sym.name
    if (sym["st_info"]["type"]=="STT_FUNC" and
        len(name)>=8 and name[0]=="r" and name.isascii()):
     offset=strings.find(name.encode()+b"\x00")
     if offset>=0:
      chosen=(int(tab["sh_offset"])+offset,name)
      break
   if chosen:break
  self.assertIsNotNone(chosen,"NO_MUTATABLE_SYMBOL_NAME_FOUND")
  offset,name=chosen
  mutant=bytearray(raw)
  mutant[offset]=ord("z")
  source_a,oracle_a=source_from_elf(raw,rev)
  source_b,oracle_b=source_from_elf(bytes(mutant),rev)
  self.assertEqual(source_a,source_b,
    "THE CANDIDATE INPUT MUST BE INDEPENDENT OF SYMBOL-NAME MUTATIONS")
  self.assertNotEqual(oracle_a,oracle_b,
    "Evaluator oracle MUST reflect modified symbol metadata")
 def test_true_entrypoints_deduplicate_symbol_aliases(self):
  path=os.environ.get("ROM003_E0_PINNED_ARCHIVE")
  if not path:self.skipTest("Pinned official ROM tar not supplied")
  out=split_official_archive(pathlib.Path(path))
  expected_unique={REVS[0]:1968,REVS[1]:2100,REVS[2]:2040}
  for revision,(public,oracle) in out.items():
   records=oracle["symbol_function_records"]
   distinct={(e["entry_pc"],e["size_bytes"]) for e in records}
   self.assertEqual(len(distinct),expected_unique[revision],
     "PINNED_ELF_FUNCTION_START_SIZE_RANGE_CHANGED")
   self.assertEqual(len(records)-len(distinct),18,
     "DUPLICATE_SYMBOL_ALIAS_MUST_NOT_COUNT_AS_18_NEW_FUNCTIONS")

 def test_save_splits_not_mixed(self):
  import tempfile
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)
   case=small_candidate()
   oracle={"schema":"fake_private","symbol_function_records":[{"entry_pc":"0x40000000"}]}
   records=write_split({REVS[0]:(case,oracle)},p)
   self.assertEqual(len(records),1)
   self.assertNotIn("symbol_function_records",
     (p/"candidate"/(REVS[0]+".json")).read_text())
   self.assertIn("symbol_function_records",
     (p/"evaluator_sealed"/(REVS[0]+".json")).read_text())
if __name__=="__main__":unittest.main()
