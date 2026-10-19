#!/usr/bin/env python3
"""Complete 88-candidate function-body audit; independent GNU/Capstone byte witnesses.

Never infer silicon effects or novelty from register hits, symbol names, or call edges.
"""
import collections,csv,hashlib,io,json,pathlib,re,subprocess,tarfile,tempfile,urllib.request
from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
from elftools.elf.elffile import ELFFile
from rom_opcode import jal,compressed_jump
BASE=pathlib.Path(__file__).resolve().parent
OUT=BASE/"output"/"candidate_full"
OUT.mkdir(parents=True,exist_ok=True)
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
BRANCHES={"beq","bne","blt","bge","bltu","bgeu","c.beqz","c.bnez"}
def require(cond,msg):
 if not cond:raise RuntimeError(msg)
def symbols(elf):
 byname=collections.defaultdict(set);at=collections.defaultdict(set)
 for sec in elf.iter_sections():
  if sec["sh_type"]!="SHT_SYMTAB":continue
  for sym in sec.iter_symbols():
   if sym["st_info"]["type"]!="STT_FUNC" or not sym.name or not int(sym["st_value"]):continue
   a,n=int(sym["st_value"]),int(sym["st_size"])
   at[a].add(sym.name)
   if n:byname[sym.name].add((a,n))
 return byname,at
def native_words(path):
 txt=subprocess.check_output(["riscv64-linux-gnu-objdump","-d",str(path)],text=True,timeout=120)
 decoded={}
 for line in txt.splitlines():
  m=re.match(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{4}|[0-9a-fA-F]{8})\s+",line)
  if m:
   pc=int(m.group(1),16);op=m.group(2).lower()
   decoded.setdefault(pc,bytes.fromhex(op)[::-1].hex())
 return decoded
def scan(elf,name,byname,at,native):
 found=byname.get(name,set())
 if not found:return {"status":"ABSENT_SYMBOL"}
 if len(found)!=1:return {"status":"AMBIGUOUS_ELF_NAME","symbols":sorted(found)}
 a,n=next(iter(found))
 matching=[s for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS"
    and int(s["sh_flags"])&4 and int(s["sh_addr"])<=a
    and a+n<=int(s["sh_addr"])+int(s["sh_size"])]
 if len(matching)!=1:return {"status":"INVALID_EXECUTABLE_RANGE","address":hex(a),"size":n}
 sec=matching[0];blob=sec.data()[a-int(sec["sh_addr"]):a-int(sec["sh_addr"])+n]
 dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 dec.skipdata=True
 lines=[];branches=[];direct=[];indirect=[];bad=[];native_equal=0;zero_unimp=[]
 for ins in dec.disasm(blob,a):
  raw=bytes(ins.bytes).hex()
  loc={"pc":hex(ins.address),"word":raw,"mnemonic":ins.mnemonic,"operands":ins.op_str}
  if ins.mnemonic==".byte":bad.append(loc)
  else:
   compared=native.get(ins.address)
   if compared!=raw:
    if raw=="0000" and ins.mnemonic=="c.unimp" and compared is None:zero_unimp.append(loc)
    else:bad.append({"reason":"INDEPENDENT_GNU_WORD_MISMATCH","capstone":loc,"gnu":compared})
   else:native_equal+=1
   if ins.mnemonic in BRANCHES:branches.append(loc)
   target=jal(bytes(ins.bytes),ins.address)
   if target is None:target=compressed_jump(bytes(ins.bytes),ins.address)
   if target is not None:
    loc["target"]=hex(target);loc["exact_target_elf_names"]=sorted(at.get(target,()))
    direct.append(loc)
   if ins.mnemonic in ("jalr","c.jr","c.jalr","jr"):indirect.append(loc)
  lines.append(loc)
 if sum(len(bytes.fromhex(x["word"])) for x in lines)!=n:
  bad.append({"reason":"CAPSTONE_COVERAGE_NOT_EXACT"})
 return {"status":("FULL_BODY_VERIFIED_WITH_ZERO_TRAP_ENCODINGS" if zero_unimp else "FULL_BODY_VERIFIED") if not bad else "INCOMPLETE_OR_DISASSEMBLER_DISAGREEMENT",
   "start":hex(a),"bytes":n,"sha256":hashlib.sha256(blob).hexdigest(),
   "instruction_count":len(lines),"gnu_machine_words_checked":native_equal,
   "conditional_branch_count":len(branches),"direct_transfer_count":len(direct),
   "indirect_transfer_count":len(indirect),"direct_transfers":direct,
   "conditional_branches":branches,"indirect_transfers":indirect,
   "zero_trap_encoding_rows_unchecked_by_gnu":zero_unimp,"mismatches":bad,"instruction_listing":lines}
def main():
 db=json.loads((BASE/"output"/"internal_function_candidates.json").read_text())
 rows=db["all_candidates"]
 require(len(rows)==88 and len({x["elf_function_name"] for x in rows})==88,"INVENTORY_NOT_88_UNIQUE")
 names=sorted(x["elf_function_name"] for x in rows)
 sources={}
 with (BASE/"output"/"idf_known"/"candidates_reclassified.csv").open() as f:
  sources={x["name"]:x for x in csv.DictReader(f)}
 require(set(names)==set(sources),"IDF_KNOWN_CANDIDATES_NOT_SAME")
 request=urllib.request.Request(URL,headers={"User-Agent":"esp32c3-candidate-full-bodies/1"})
 archive=urllib.request.urlopen(request,timeout=120).read()
 require(hashlib.sha256(archive).hexdigest()==SHA,"PINNED_ELF_HASH_MISMATCH")
 inventory={x:{"elf_name":x,"idf_classification":sources[x]["classification"],"revisions":{}} for x in names}
 with tarfile.open(fileobj=io.BytesIO(archive),mode="r:gz") as tar,tempfile.TemporaryDirectory() as tmp:
  for rev in REVS:
   members=[m for m in tar.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   require(len(members)==1,"REVISION_MISSING")
   binary=tar.extractfile(members[0]).read();p=pathlib.Path(tmp)/rev;p.write_bytes(binary)
   elf=ELFFile(io.BytesIO(binary));byname,at=symbols(elf);gnu=native_words(p)
   reg=BASE/"output"/"register_access"
   mmio=json.loads((reg/(rev+".mmio.json")).read_text())
   csr=json.loads((reg/(rev+".csr.json")).read_text())
   graph=json.loads((BASE/"output"/"callgraph"/(rev+".candidate_paths.json")).read_text())
   graph_byname={x["candidate"]:x for x in graph}
   for name in names:
    entry=scan(elf,name,byname,at,gnu)
    matches=[dict(row) for row in mmio if name in row.get("function_hints",[])]
    accesses=[dict(row) for row in csr if name in row.get("function_hints",[])]
    entry["mmio_raw_hit_count"]=len(matches);entry["csr_raw_hit_count"]=len(accesses)
    entry["mmio_writes"]=sum(x["kind"].lower() in ("store","write") for x in matches)
    entry["mmio_reads"]=sum(x["kind"].lower() in ("load","read") for x in matches)
    entry["ambiguous_owner_hit_count"]=sum(len([x for x in row["function_hints"] if not x.startswith("OTHER_OVERLAP_OMITTED")])>1 for row in matches+accesses)
    entry["register_hit_evidence"]=matches+accesses
    entry["direct_public_root_witness"]=graph_byname[name]["possible_static_public_entry_path"]
    inventory[name]["revisions"][rev]=entry
   (OUT/(rev+".candidate_full.json")).write_text(json.dumps({n:inventory[n]["revisions"][rev] for n in names},indent=2)+"\n")
 stats=collections.Counter()
 rows_small=[]
 for name,item in sorted(inventory.items()):
  present=[x for x in item["revisions"].values() if x["status"]!="ABSENT_SYMBOL"]
  full=[x for x in present if x["status"].startswith("FULL_BODY_VERIFIED")]
  stats["candidate_names"]+=1;stats["present_function_bodies"]+=len(present)
  stats["validated_function_bodies"]+=len(full)
  stats["gnu_verified_instruction_words"]+=sum(x["gnu_machine_words_checked"] for x in full)
  stats["unimp_zero_encoding_occurrences"]+=sum(len(x["zero_trap_encoding_rows_unchecked_by_gnu"]) for x in full)
  stats["function_bodies_with_zero_trap_encodings"]+=sum(bool(x["zero_trap_encoding_rows_unchecked_by_gnu"]) for x in full)
  stats["ambiguous_mmio_csr_owner_hints"]+=sum(x["ambiguous_owner_hit_count"] for x in present)
  if len(full)!=len(present):stats["candidates_with_unverified_bodies"]+=1
  if any(x["direct_public_root_witness"] for x in present):stats["candidates_direct_root_reachable"]+=1
  if item["idf_classification"]=="KNOWN_IDF_LINKER_NAME":stats["known_idf_linker_names"]+=1
  if item["idf_classification"]=="UNRESOLVED_IN_SELECTED_IDF_SOURCES":stats["idf_unresolved_names"]+=1
  if any(x["indirect_transfer_count"] for x in full):stats["candidates_with_unresolved_indirect_transfers"]+=1
  if any(x["conditional_branch_count"] for x in full):stats["candidates_with_conditional_control_flow"]+=1
  code_sha=[x["sha256"] for x in full]
  if len(code_sha)>1 and len(set(code_sha))>1:stats["function_name_with_revision_code_difference"]+=1
  rows_small.append({"elf_name":name,"idf_classification":item["idf_classification"],
   "present_revisions":len(present),"fully_verified_revisions":len(full),
   "indirect":sum(x["indirect_transfer_count"] for x in full),
   "conditional":sum(x["conditional_branch_count"] for x in full),
   "mmio_hits":sum(x["mmio_raw_hit_count"] for x in present),
   "csr_hits":sum(x["csr_raw_hit_count"] for x in present),
   "owner_ambiguity":sum(x["ambiguous_owner_hit_count"] for x in present),
   "zero_trap_encoding_count":sum(len(x["zero_trap_encoding_rows_unchecked_by_gnu"]) for x in full),
   "direct_public_path":any(x["direct_public_root_witness"] for x in present),
   "different_machine_code_by_revision":len(code_sha)>1 and len(set(code_sha))>1})
 (OUT/"candidate_summary.json").write_text(json.dumps({"schema":"ROM_88_CANDIDATE_FUNCTION_BODY_AUDIT_V1",
   "archive_sha256":SHA,"counts":dict(stats),"all_candidates":rows_small,
   "limits":["A decoded function body demonstrates ROM bytes, not runtime execution",
    "An ELF symbol name does not establish API usability",
    "Static branch target not proof of reachability at runtime",
    "MMIO/CSR naming does not prove peripheral effects",
    "Known/unknown linker name is not a functional novelty judgment",
    "Encoding 0x0000 is c.unimp; GNU may skip it: recorded as unresolved trap/filler, not independently verified valid instruction",
    "Indirect transfers and register aliases require independent validation"]},indent=2)+"\n")
 print("CANDIDATE_FUNCTION_AUDIT "+json.dumps(dict(stats),sort_keys=True))
 if stats["candidate_names"]!=88 or stats["candidates_with_unverified_bodies"]:
  raise SystemExit("CANDIDATE_MACHINE_CODE_AUDIT_INCOMPLETE")
if __name__=="__main__":main()
