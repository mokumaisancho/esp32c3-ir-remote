#!/usr/bin/env python3
"""Full evidence dossiers for ALL 88 ROM candidates; independent native disassembler check.

Never promote a function name, data register match, or static call edge to verified
runtime behavior or novel API. Source-level and instruction-level provenance only.
"""
import collections, csv, hashlib, io, json, pathlib, re, subprocess, tarfile, tempfile, urllib.request
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
from elftools.elf.elffile import ELFFile
from rom_opcode import jal, compressed_jump
from published_prior_art import PUBLISHED

ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"candidate_dossiers";OUT.mkdir(parents=True,exist_ok=True)
REV=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
ROM_URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
def read(path):return json.loads((ROOT/"output"/path).read_text())
def sha(x):return hashlib.sha256(x).hexdigest()
def objdump_words(path):
 text=subprocess.check_output(["riscv64-linux-gnu-objdump","-d",str(path)],text=True,timeout=120)
 words={}
 for line in text.splitlines():
  m=re.match(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{4}|[0-9a-fA-F]{8})\s+",line)
  if m:
   addr=int(m.group(1),16)
   if addr in words and words[addr]!=m.group(2).lower():raise RuntimeError("GNU_OBJDUMP_DUPLICATE:"+hex(addr))
   words[addr]=m.group(2).lower()
 if len(words)<10000:raise RuntimeError("GNU_DISASSEMBLY_UNEXPECTEDLY_SMALL")
 return words
def symbols(elf):
 result=collections.defaultdict(set)
 for section in elf.iter_sections():
  if section["sh_type"]!="SHT_SYMTAB":continue
  for sym in section.iter_symbols():
   if sym["st_info"]["type"]=="STT_FUNC" and sym.name and int(sym["st_value"]):
    result[sym.name].add((int(sym["st_value"]),int(sym["st_size"])))
 return result
def body_for(elf,name,symbols_by_name,gnu):
 names=symbols_by_name.get(name,set())
 if not names:return {"status":"NOT_PRESENT_IN_ELF_REVISION"}
 if len(names)!=1:return {"status":"AMBIGUOUS_FUNCTION_SYMBOL","definitions":sorted([list(x) for x in names])}
 start,length=next(iter(names))
 if length<=0:return {"status":"ZERO_SIZE_FUNCTION","address":hex(start)}
 sections=[s for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS" and (int(s["sh_flags"])&4)
           and int(s["sh_addr"])<=start and start+length<=int(s["sh_addr"])+int(s["sh_size"])]
 if len(sections)!=1:return {"status":"FUNCTION_SPANS_UNKNOWN_SECTIONS","address":hex(start),"size":length}
 section=sections[0]
 machine=section.data()[start-int(section["sh_addr"]):start-int(section["sh_addr"])+length]
 dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 instructions=list(dec.disasm(machine,start))
 if sum(x.size for x in instructions)!=length:
  return {"status":"PARTIAL_DECODE","address":hex(start),"size":length,"decoded_bytes":sum(x.size for x in instructions)}
 direct=[];indirect=[];branch=[];memory=[];csrs=[];rows=[]
 for ins in instructions:
  raw=bytes(ins.bytes)
  if gnu.get(ins.address)!=raw[::-1].hex():
   raise RuntimeError("CAPSTONE_GNU_WORD_DISAGREEMENT:"+name+":"+hex(ins.address))
  row={"pc":hex(ins.address),"machine":raw.hex(),"mnemonic":ins.mnemonic,"operands":ins.op_str}
  dest=jal(raw,ins.address)
  if dest is None:dest=compressed_jump(raw,ins.address)
  if dest is not None:
   row["direct_target"]=hex(dest);direct.append({"pc":row["pc"],"target":hex(dest),"mnemonic":ins.mnemonic})
  if ins.mnemonic in ("jalr","jr","c.jalr","c.jr"):
   indirect.append({"pc":row["pc"],"mnemonic":ins.mnemonic,"operands":ins.op_str})
  if ins.mnemonic in ("beq","bne","blt","bge","bltu","bgeu","c.beqz","c.bnez"):
   branch.append({"pc":row["pc"],"mnemonic":ins.mnemonic,"operands":ins.op_str})
  if ins.mnemonic.startswith(("lw","lh","lb","sw","sh","sb","c.lw","c.sw","c.lbu","c.sb")):
   memory.append({"pc":row["pc"],"mnemonic":ins.mnemonic,"operands":ins.op_str})
  if ins.mnemonic.startswith(("csr","csrr")):csrs.append(row)
  rows.append(row)
 return {"status":"CAPSTONE_GNU_VERIFIED","address":hex(start),"size":length,
    "machine_sha256":sha(machine),"instruction_count":len(rows),
    "direct_transfer_count":len(direct),"indirect_transfer_count":len(indirect),
    "conditional_branch_count":len(branch),"memory_instruction_count":len(memory),
    "csr_instruction_count":len(csrs),"direct_transfers":direct,
    "indirect_transfers":indirect,"branches":branch,"csr_instructions":csrs,
    "machine_instructions":rows}
def main():
 cand=read("internal_function_candidates.json")
 if len(cand["all_candidates"])!=88 or cand["candidate_count"]!=88:raise RuntimeError("ORIGINAL_88_IDENTITY_LOST")
 names=[x["elf_function_name"] for x in cand["all_candidates"]]
 if len(names)!=len(set(names)):raise RuntimeError("CANDIDATES_DUPLICATED")
 idf=read("idf_known/summary.json")
 if idf["candidate_count"]!=88:raise RuntimeError("IDF_INVENTORY_NOT_APPLICABLE")
 idf_by={x["name"]:x for x in idf["candidate_source_provenance"]}
 if set(idf_by)!=set(names):raise RuntimeError("IDF_CANDIDATE_IDENTITY_DIFFERENCE")
 raw=urllib.request.urlopen(urllib.request.Request(ROM_URL,headers={"User-Agent":"rom-88-dossier/1"}),timeout=120).read()
 if sha(raw)!=SHA:raise RuntimeError("ROM_ARCHIVE_SHA_MISMATCH")
 rev_out={};roll=collections.defaultdict(dict)
 with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as archive,tempfile.TemporaryDirectory() as tmp:
  for rev in REV:
   found=[x for x in archive.getmembers() if x.isfile() and pathlib.PurePosixPath(x.name).name==rev]
   if len(found)!=1:raise RuntimeError("ROM_REVISION_ELF_MISSING:"+rev)
   data=archive.extractfile(found[0]).read();location=pathlib.Path(tmp)/rev;location.write_bytes(data)
   elf=ELFFile(io.BytesIO(data));symbol_map=symbols(elf);gnu=objdump_words(location)
   records={}
   for name in names:
    row=body_for(elf,name,symbol_map,gnu)
    records[name]=row;roll[name][rev]={k:v for k,v in row.items() if k not in (
      "machine_instructions","direct_transfers","indirect_transfers","branches","csr_instructions")}
   (OUT/(rev+".functions.json")).write_text(json.dumps(records,indent=2)+"\n")
   rev_out[rev]={"elf_sha256":sha(data),"gnu_word_addresses":len(gnu),
     "verified_function_bodies":sum(x["status"]=="CAPSTONE_GNU_VERIFIED" for x in records.values()),
     "not_present":sum(x["status"]=="NOT_PRESENT_IN_ELF_REVISION" for x in records.values()),
     "other_statuses":{n:v["status"] for n,v in records.items() if v["status"] not in ("CAPSTONE_GNU_VERIFIED","NOT_PRESENT_IN_ELF_REVISION")}}
 callgraph={rev:read("callgraph/"+rev+".candidate_paths.json") for rev in REV}
 graph_by={rev:{x["candidate"]:x for x in callgraph[rev]} for rev in REV}
 mmio={rev:read("register_access/"+rev+".mmio.json") for rev in REV}
 csrs={rev:read("register_access/"+rev+".csr.json") for rev in REV}
 entry={}
 for candidate in cand["all_candidates"]:
  name=candidate["elf_function_name"]
  per={}
  for rev in REV:
   r=roll[name][rev];graph=graph_by[rev][name]
   hits=[{"type":"MMIO","pc":x["access_pc"],"register":x["address"],"bytes":x["source_bytes"],
       "prior_address_meaning":PUBLISHED.get(x["address"].lower())} for x in mmio[rev] if name in x.get("function_hints",[])]
   hits +=[{"type":"CSR","pc":x["address"],"register":x["csr"],"bytes":x["raw_bytes"]} for x in csrs[rev] if name in x.get("function_hints",[])]
   if rev in candidate["revisions"] and not hits:raise RuntimeError("CANDIDATE_MISSING_REGISTER_EVIDENCE:"+name+":"+rev)
   per[rev]={**r,"direct_incoming_callers":graph["direct_incoming_callers"],
      "possible_static_public_entry_path":graph["possible_static_public_entry_path"],
      "register_hits":hits}
  hashes={rev:per[rev].get("machine_sha256") for rev in REV if per[rev]["status"]=="CAPSTONE_GNU_VERIFIED"}
  known=idf_by[name];linker_known=known["classification"]=="KNOWN_IDF_LINKER_NAME"
  classification="OFFICIAL_IDF_LINKER_KNOWN_NAME" if linker_known else "ELF_NAMED_INTERNAL_FUNCTION_UNRESOLVED_PRIOR"
  entry[name]={"name":name,"knowledge_classification":classification,
    "known_source_provenance":known,"revisions":per,"function_identity_by_revision":hashes,
    "bit_identical_all_present_revisions":len(set(hashes.values()))==1 if len(hashes)>1 else None,
    "observed_behavior_proven":False,"novel_api_proven":False,
    "review_decision":"STATIC_EVIDENCE_COMPLETE_SEMANTIC_UNRESOLVED",
    "next_proof":"Trace instruction effects to concrete register bitfields and independently test a causal behavior"}
 if len(entry)!=88:raise RuntimeError("NOT_ALL_CANDIDATES_REVIEWED")
 report={"schema":"ESP32C3_ALL_88_CANDIDATE_MACHINE_CODE_DOSSIERS_V1",
   "original_issue_id":"ESP32C3-ROM-001","source_archive_sha256":SHA,
   "candidate_total":len(entry),"idf_named_known_count":sum(x["knowledge_classification"]=="OFFICIAL_IDF_LINKER_KNOWN_NAME" for x in entry.values()),
   "other_elf_named_count":sum(x["knowledge_classification"]=="ELF_NAMED_INTERNAL_FUNCTION_UNRESOLVED_PRIOR" for x in entry.values()),
   "reviewed_static_facts":len(entry),"function_behavior_verified_count":0,"novel_api_verified_count":0,
   "revisions":rev_out,"candidates":entry,
   "limitations":["Independent GNU decoder validates machine words not runtime function","ELF symbol names do not prove external API contract",
     "Linear decode and static paths may include unreachable code or misses via indirection",
     "Symbolic register hits and prior address labels do not prove causation",
     "All 88 candidates receive machine-code and provenance dossiers, not completed semantic certification",
     "No candidate-expansion scan is authorized until all 88 undergo semantic adjudication"]}
 (OUT/"all_88_dossiers.json").write_text(json.dumps(report,indent=2)+"\n")
 print("ALL_88_DOSSIER_SUMMARY "+json.dumps({k:v for k,v in report.items() if k!="candidates"},sort_keys=True))
if __name__=="__main__":main()
