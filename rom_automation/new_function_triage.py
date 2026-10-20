#!/usr/bin/env python3
"""ROM-001: deterministic machine-code shortlist of name-catalog-unmatched ROM functions.

These symbols exist in official ROM ELF, but lack a name match in only THREE
older selected symbol catalogs. All status labels are investigation priority,
never novel capability or safe physical execution assertions.
"""
import argparse,hashlib,io,json,pathlib,re,tarfile,collections
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,require,sha

WRITES={"sw","sh","sb","c.sw","c.swsp","sc.w"}
CSR_WRITES={"csrrw","csrrwi","csrrs","csrrsi","csrrc","csrrci"}
LOADS={"lw","lh","lhu","lb","lbu","c.lw","c.lwsp"}
RISKY_FLOAT={"flw","fsw","fld","fsd","c.flw","c.fsw","c.fld","c.fsd"}
TRAP={"ecall","ebreak","c.ebreak","unimp","c.unimp"}
CTRL_CALL={"c.jal","c.jalr","jal","jalr","jr","c.jr"}
FEATURE_WORDS=("get","read","query","is_dead","status","count")

def inspect_mnemonics(mnemonics,bytes_ok=True):
 """Fail-closed static hint, not a side-effect safety certification."""
 ops=[(x if isinstance(x,str) else x[0],"" if isinstance(x,str) else x[1]) for x in mnemonics]
 opcodes=[op for op,args in ops]
 invalid=[x for x in opcodes if x in RISKY_FLOAT or x in TRAP or x==".byte"]
 stores=sum(x in WRITES for x in opcodes)
 loads=sum(x in LOADS for x in opcodes)
 csrs=sum(x in CSR_WRITES for x in opcodes)
 def verified_return(op,args):
  normalized=args.replace(" ","")
  return op=="ret" or (op in ("c.jr","jr") and normalized=="ra") or (
    op=="jalr" and normalized in ("zero,0(ra)","x0,0(ra)"))
 rets=sum(verified_return(op,args) for op,args in ops)
 calls=sum(op in CTRL_CALL and not verified_return(op,args) for op,args in ops)
 indirect=sum(x in ("jalr","c.jalr","jr","c.jr") for x in opcodes)
 # Any call or unknown indirect target can hide effects in the callee.
 simple=(bool(ops) and bytes_ok and not invalid and stores==0
         and csrs==0 and calls==0 and rets>0)
 return {"machine_instructions":len(ops),"loads":loads,"stores":stores,
  "csr_updates":csrs,"calls_or_indirect_jumps":calls,
  "indirect_control_opcodes":indirect,"return_opcodes":rets,
  "unsupported_rv32imc_or_traps":len(invalid),
  "complete_byte_coverage":bytes_ok,
  "direct_local_effect_candidate":simple,
  "read_only_silicon_proven":False,"novelty_proven":False}

def revision_symbols(elf):
 out=collections.defaultdict(list)
 for s in elf.iter_sections():
  if s["sh_type"]!="SHT_SYMTAB":continue
  for sym in s.iter_symbols():
   if sym["st_info"]["type"]!="STT_FUNC" or not sym.name or not int(sym["st_size"]):continue
   out[sym.name].append((int(sym["st_value"]),int(sym["st_size"])))
 return out

def analyze(census,rom):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 require(sha(rom)==ROM_SHA,"ROM_ARCHIVE_SHA_MISMATCH")
 require(census["schema"]=="ESP32C3_ROM_NEW_FUNCTION_EXPLORATION_V1","CENSUS_SCHEMA_MISMATCH")
 require(census["official_elf_source_sha256"]==ROM_SHA,"CENSUS_SOURCE_MISMATCH")
 names=census["all_missing_names"]
 require(len(names)==177 and census["named_candidates_for_prior_art_followup"]==152,
         "PINNED_CANDIDATE_SET_DRIFT")
 allow={k for k in names if not re.fullmatch(r"check_condCOUNTER\.\d+",k)}
 require(len(allow)==152,"LOCAL_SYMBOL_FILTER_DRIFT")
 records={}
 with tarfile.open(rom,"r:gz") as t:
  for rev in sorted(census["revisions"]):
   found=[m for m in t.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   require(len(found)==1,"MISSING_ROM_REV")
   elf_bytes=t.extractfile(found[0]).read()
   require(hashlib.sha256(elf_bytes).hexdigest()==census["revisions"][rev]["elf_sha256"],"ELF_REV_SHA")
   elf=ELFFile(io.BytesIO(elf_bytes))
   symbols=revision_symbols(elf)
   sections=[s for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS"
    and int(s["sh_flags"])&4 and int(s["sh_size"])>0]
   decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
   decoder.skipdata=True
   for name in sorted(allow):
    if name not in symbols:continue
    instances=[]
    for addr,size in symbols[name]:
     chunk=None
     for s in sections:
      base=int(s["sh_addr"])
      if base<=addr and addr+size<=base+int(s["sh_size"]):
       chunk=s.data()[addr-base:addr-base+size]
       break
     require(chunk is not None,"ELF_SYMBOL_NOT_WITHIN_EXECUTABLE_BYTES:"+name)
     ops=list(decoder.disasm(chunk,addr))
     covered=sum(i.size for i in ops)==len(chunk)
     metrics=inspect_mnemonics([(i.mnemonic,i.op_str) for i in ops],bytes_ok=covered)
     # RV32IMC includes neither F/D, reject float decode even if Capstone parsed it.
     sample=[{"pc":hex(i.address),"mnemonic":i.mnemonic,"bytes":bytes(i.bytes).hex()}
              for i in ops[:10]]
     instances.append({"entry":hex(addr),"size_bytes":size,
                       "sha256":hashlib.sha256(chunk).hexdigest(),"metrics":metrics,
                       "first_ten_instructions":sample})
    if name not in records:records[name]={"name":name,"revisions":{}}
    records[name]["revisions"][rev]=instances
 for name,record in records.items():
  stats=[x["metrics"] for instances in record["revisions"].values() for x in instances]
  complete=bool(stats) and all(x["complete_byte_coverage"] for x in stats)
  simple=complete and all(x["direct_local_effect_candidate"] for x in stats)
  instr=sum(x["machine_instructions"] for x in stats)
  words=bool(any(w in name.lower() for w in FEATURE_WORDS))
  # This ranks research cost, not confidence in undocumented functionality.
  priority=(
    100*int(simple)
    +20*int(words)
    +min(20,sum(x["loads"] for x in stats))
    +20*int(complete)
    -min(40,instr//10)
    -40*int(any(x["stores"] or x["csr_updates"] for x in stats))
    -20*int(any(x["calls_or_indirect_jumps"] for x in stats))
   )
  record["prior_art_status"]="NOT_FOUND_IN_ONLY_3_SELECTED_CATALOGS"
  record["priority_score"]=priority
  record["machine_effect_status"]="UNREVIEWED_STATIC_OPCODE_TRIAGE"
  record["side_effect_certified"]=False
  record["physical_safety_certified"]=False
  record["new_function_proven"]=False
  record["novel_usable_capability_proven"]=False
  record["hypothesis"]=(f"Investigate a possible bounded data-read behavior in {name}; "
   "assert and falsify exact ISA effects from pinned bytes before any hardware operation.")
  record["refutation"]=(f"Find same semantics in dated official/public prior art OR "
   "observe unmodeled store, indirect/callee effect, illegal instruction or wrong revision.")
 require(len(records)==152,"INCOMPLETE_EXACT_REV101_SHORTLIST")
 ordered=sorted(records.values(),key=lambda x:(-x["priority_score"],x["name"]))
 return {"schema":"ESP32C3_ROM_REV101_UNMATCHED_FUNCTION_MACHINE_TRIAGE_V1",
  "original_issue_id":"ESP32C3-ROM-001","source_rom_sha256":ROM_SHA,
  "catalog_unmatched_total":177,"compiler_local_symbols_excluded":25,
  "actual_functions_screened":len(records),
  "top_twelve_for_static_inspection":[{k:x[k] for k in
    ("name","priority_score","revisions","hypothesis","refutation")} for x in ordered[:12]],
  "all_152_ranked":ordered,
  "status":"STATIC_NAME_BASED_INVESTIGATION_PRIORITY_NOT_NOVELTY_PROOF",
  "notes":[
   "Purely static local opcodes do not prove safe physical access: indirect calls and MMIO races are not modeled.",
   "Function names missing from three prior catalogs may have been published in other sources.",
   "Names and code are from current official ELF; this cannot alone establish a previously unknown ROM function.",
   "Do not invoke candidate addresses on physical hardware without authorized revision-specific guard."
  ]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--rom",required=True,type=pathlib.Path)
 p.add_argument("--census",required=True,type=pathlib.Path)
 p.add_argument("--out",required=True,type=pathlib.Path)
 a=p.parse_args()
 r=analyze(json.loads(a.census.read_text()),a.rom)
 a.out.parent.mkdir(exist_ok=True,parents=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_NEW_FUNCTION_TRIAGE",json.dumps({
  "screened":r["actual_functions_screened"],
  "top_names":[x["name"] for x in r["top_twelve_for_static_inspection"]],
  "direct_local_effect_candidate_count":sum(
   all(b["metrics"]["direct_local_effect_candidate"]
       for v in x["revisions"].values() for b in v)
   for x in r["all_152_ranked"]),
  "silicon_certified":0,"new_capability_certified":0
 },sort_keys=True))
if __name__=="__main__":main()
