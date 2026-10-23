#!/usr/bin/env python3
"""ROM-003 E0: mechanically separate raw executable RV32C bytes from symbol oracle.

The candidate side is an opaque executable-section byte manifest plus entry_pc.
The evaluator oracle is emitted separately. This is logical schema separation,
NOT adversarial process isolation and NOT yet unknown boundary recovery.
"""
import argparse,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile

ROM_SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
CANDIDATE_SCHEMA="ROM003_RAW_EXEC_CANDIDATE_INPUT_V1"
ORACLE_SCHEMA="ROM003_SEALED_SYMBOL_ORACLE_V1"

def need(v,why):
 if not v:raise ValueError(why)

def digest(data):
 return hashlib.sha256(data).hexdigest()

def source_from_elf(raw,revision):
 need(revision in REVS,"UNKNOWN_ROM_REVISION")
 elf=ELFFile(io.BytesIO(raw))
 need(elf.elfclass==32 and elf.little_endian and elf["e_machine"]=="EM_RISCV",
      "NOT_ESP32C3_32BIT_RISCV")
 regions=[]
 for sec in elf.iter_sections():
  if sec["sh_type"]!="SHT_PROGBITS" or not (int(sec["sh_flags"])&4) or int(sec["sh_size"])==0:
   continue
  addr=int(sec["sh_addr"]);payload=sec.data()
  need(addr%2==0 and len(payload)==int(sec["sh_size"]),"INVALID_EXEC_REGION")
  regions.append({"start_pc":hex(addr),"raw_hex":payload.hex(),
    "byte_count":len(payload),"sha256":digest(payload)})
 regions.sort(key=lambda x:int(x["start_pc"],16))
 need(regions and sum(r["byte_count"] for r in regions)>8192,"INCOMPLETE_EXECUTABLE_BYTES")
 for a,b in zip(regions,regions[1:]):
  need(int(a["start_pc"],16)+a["byte_count"]<=int(b["start_pc"],16),
       "EXEC_REGION_OVERLAP")
 root=int(elf.header["e_entry"])
 need(any(int(x["start_pc"],16)<=root<int(x["start_pc"],16)+x["byte_count"]
          for x in regions),"ELF_ENTRY_OUTSIDE_EXEC")
 public={"schema":CANDIDATE_SCHEMA,"revision":revision,
         "isa":"RISCV32_LE_RV32IMC","root_pc":hex(root),
         "exec_regions":regions}
 oracle=[]
 for s in elf.iter_sections():
  if s["sh_type"]!="SHT_SYMTAB":continue
  for sym in s.iter_symbols():
   if sym["st_info"]["type"]!="STT_FUNC" or not sym.name:continue
   addr=int(sym["st_value"]);size=int(sym["st_size"])
   if size<=0:continue
   if any(int(r["start_pc"],16)<=addr and
      addr+size<=int(r["start_pc"],16)+r["byte_count"] for r in regions):
    oracle.append({"entry_pc":hex(addr),"size_bytes":size,"name":sym.name})
 need(len(oracle)>=1000,"INSUFFICIENT_EVALUATOR_ORACLE")
 oracle.sort(key=lambda x:(int(x["entry_pc"],16),x["name"]))
 secret={"schema":ORACLE_SCHEMA,"revision":revision,
         "source_elf_sha256":digest(raw),
         "symbol_function_records":oracle,
         "function_entry_oracle_only":True}
 validate_candidate_input(public)
 return public,secret

def validate_candidate_input(document):
 need(type(document)==dict and
      set(document)=={"schema","revision","isa","root_pc","exec_regions"},
      "CANDIDATE_SCHEMA_TOPLEVEL_FIELDS")
 need(document["schema"]==CANDIDATE_SCHEMA and
      document["revision"] in REVS and
      document["isa"]=="RISCV32_LE_RV32IMC","CANDIDATE_IDENTITY")
 need(type(document["exec_regions"])==list and document["exec_regions"],
      "MISSING_EXEC_REGIONS")
 for region in document["exec_regions"]:
  need(type(region)==dict and set(region)=={"start_pc","raw_hex","byte_count","sha256"},
      "CANDIDATE_REGION_FIELD_LEAK")
  raw=bytes.fromhex(region["raw_hex"])
  need(len(raw)==region["byte_count"] and digest(raw)==region["sha256"],
       "CANDIDATE_BYTES_HASH_MISMATCH")
 return True

def split_official_archive(path):
 raw=path.read_bytes()
 need(digest(raw)==ROM_SHA,"OFFICIAL_ARCHIVE_HASH_DRIFT")
 out={}
 with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as tar:
  for revision in REVS:
   found=[m for m in tar.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==revision]
   need(len(found)==1,"ROM_ELF_REVISION_MISSING")
   byte_stream=tar.extractfile(found[0]).read()
   out[revision]=source_from_elf(byte_stream,revision)
 return out

def write_split(out,destination):
 public_dir=destination/"candidate"
 oracle_dir=destination/"evaluator_sealed"
 public_dir.mkdir(parents=True,exist_ok=True);oracle_dir.mkdir(parents=True,exist_ok=True)
 manifest=[]
 for rev,(candidate,oracle) in out.items():
  a=public_dir/(rev+".json");b=oracle_dir/(rev+".json")
  a.write_text(json.dumps(candidate,separators=(",",":"),sort_keys=True)+"\n")
  b.write_text(json.dumps(oracle,separators=(",",":"),sort_keys=True)+"\n")
  manifest.append({"revision":rev,
    "candidate_sha256":digest(a.read_bytes()),"oracle_sha256":digest(b.read_bytes()),
    "executable_bytes":sum(r["byte_count"] for r in candidate["exec_regions"]),
    "oracle_function_starts":len(oracle["symbol_function_records"]),
    "separation":"DIFFERENT_JSON_SCHEMA_AND_DIRECTORIES_NOT_ADVERSARIAL_ISOLATION"})
 return manifest

def main():
 parser=argparse.ArgumentParser()
 parser.add_argument("--rom",type=pathlib.Path,required=True)
 parser.add_argument("--outdir",type=pathlib.Path,required=True)
 args=parser.parse_args()
 manifest=write_split(split_official_archive(args.rom),args.outdir)
 (args.outdir/"manifest.json").write_text(json.dumps({
   "schema":"ROM003_RAW_EXEC_SPLIT_RECEIPT_V1",
   "source_ROM_sha256":ROM_SHA,
   "revisions":manifest,
   "candidate_does_not_include_function_labels_or_boundaries":True,
   "actual_function_recovery_test_performed":False,
   "adversarial_isolation_guaranteed":False},indent=2)+"\n")
 print("ROM003_E0_RAW_SPLIT",json.dumps([
  {"revision":x["revision"],"bytes":x["executable_bytes"],
   "oracle_functions_held_out":x["oracle_function_starts"],
   "candidate_sha256":x["candidate_sha256"]} for x in manifest],sort_keys=True))

if __name__=="__main__":main()
