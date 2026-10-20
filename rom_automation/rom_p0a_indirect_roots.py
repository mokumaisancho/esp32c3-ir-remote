#!/usr/bin/env python3
"""ROM-001 P0-A indirect vector/table seeds into executable ELF function gaps.

Enumerate candidate roots from non-executable ALLOC data (aligned LE32),
ELF entrypoint and zero-size ELF STT_FUNC symbols; report but DO NOT promote
an address as an executable function from coincidence alone. Machine-byte
decoder is independent of source symbol names.
"""
import argparse,bisect,collections,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,REVS,require,sha
from new_function_hunt import merged
from rom_fast_graph import make_symbol_index

FORBIDDEN={"flw","fsw","fld","fsd","c.flw","c.fsw","c.fld","c.fsd","unimp","c.unimp","ecall","ebreak","c.ebreak",".byte"}

def build_gaps(executable,covered):
 valid=merged(covered)
 gaps=[]
 for a,b in sorted(executable):
  c=a
  for x,y in valid:
   if y<=a or x>=b:continue
   if c<x:gaps.append((c,min(x,b)))
   c=max(c,min(y,b))
  if c<b:gaps.append((c,b))
 return gaps

def in_gap(gaps,addr):
 starts=[a for a,b in gaps]
 i=bisect.bisect_right(starts,addr)-1
 return i>=0 and addr<gaps[i][1]

def collect_aligned_data_refs(data,base,valid_gaps):
 """Typed structure input: section starts at base, scan physical 4-byte boundaries."""
 refs=collections.defaultdict(list)
 for pos in range((-base)%4,len(data)-3,4):
  target=int.from_bytes(data[pos:pos+4],"little")
  if in_gap(valid_gaps,target):
   refs[target].append(base+pos)
 return refs

def analyze_one(blob,rev,graph):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 elf=ELFFile(io.BytesIO(blob))
 require(elf["e_machine"]=="EM_RISCV" and elf.elfclass==32 and elf.little_endian,"BAD_ELF_ISA")
 sections,bounds,pairs,owners,entries,_=make_symbol_index(elf)
 gaps=build_gaps(bounds,pairs)
 require(sum(b-a for a,b in gaps)>0,"NO_EXECUTABLE_GAPS_FOUND")
 roots=collections.defaultdict(lambda:{"source_witnesses":[],"classifications":set()})
 samples=collections.Counter()
 for section in elf.iter_sections():
  if section["sh_type"]!="SHT_PROGBITS" or not int(section["sh_size"]):continue
  if not int(section["sh_flags"])&2 or int(section["sh_flags"])&4:continue
  refs=collect_aligned_data_refs(section.data(),int(section["sh_addr"]),gaps)
  for target,from_addrs in refs.items():
   for src in from_addrs[:12]:
    roots[target]["source_witnesses"].append({"source":hex(src),"section":section.name,"type":"EXACT_ALIGNED_NONEXEC_LE32"})
   roots[target]["classifications"].add("NONEXEC_ALLOC_WORD_MATCH")
   samples["nonexec_word_matches"]+=len(from_addrs)
 for section in elf.iter_sections():
  if section["sh_type"]!="SHT_SYMTAB":continue
  for sym in section.iter_symbols():
   if not sym.name or sym["st_info"]["type"]!="STT_FUNC" or int(sym["st_size"])!=0:continue
   addr=int(sym["st_value"])
   if in_gap(gaps,addr):
    roots[addr]["source_witnesses"].append({"symbol":sym.name,"type":"ZERO_SIZE_ELF_FUNCTION_SYMBOL"})
    roots[addr]["classifications"].add("ZERO_SIZE_SYMBOL_IN_GAP")
 entry=int(elf.header["e_entry"])
 if in_gap(gaps,entry):
  roots[entry]["source_witnesses"].append({"type":"ELF_ENTRY_POINT","value":hex(entry)})
  roots[entry]["classifications"].add("ELF_ENTRY_IN_GAP")
 strict=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 executable={int(s["sh_addr"]):(int(s["sh_addr"])+int(s["sh_size"]),s.data())
             for s in sections}
 result=[]
 for addr,reason in sorted(roots.items()):
  present=next(((base,end,data) for base,(end,data) in executable.items() if base<=addr<end),None)
  require(present is not None,"TARGET_MISSING_EXECUTABLE_SECTION")
  base,end,data=present;pos=addr-base
  ins=list(strict.disasm(data[pos:min(pos+24,len(data))],addr))
  leading=[]
  for obj in ins[:4]:
   if obj.mnemonic in FORBIDDEN:break
   if not in_gap(gaps,obj.address):break
   leading.append({"pc":hex(obj.address),"mnemonic":obj.mnemonic,"machine_bytes":bytes(obj.bytes).hex()})
  result.append({"target":hex(addr),"provenance_types":sorted(reason["classifications"]),
    "witnesses":reason["source_witnesses"][:16],
    "syntactic_rv32imc_landing_instructions":leading,
    "landing_valid_at_least_two":len(leading)>=2,
    "call_edge_proven":False,"function_boundary_proven":False,
    "dynamic_execution_proven":False,"novelty_proven":False})
 return {"revision":rev,"ELF_sha256":hashlib.sha256(blob).hexdigest(),
  "gap_bytes":sum(b-a for a,b in gaps),
  "gap_intervals":len(gaps),
  "ELF_entry":hex(entry),"ELF_entry_in_gap":in_gap(gaps,entry),
  "nonexec_alloc_le32_matches":samples["nonexec_word_matches"],
  "distinct_root_candidates":len(result),
  "syntactic_two_instruction_landing":sum(x["landing_valid_at_least_two"] for x in result),
  "zero_size_symbol_roots":sum("ZERO_SIZE_SYMBOL_IN_GAP" in x["provenance_types"] for x in result),
  "roots":result,
  "unverified_boundaries":True,
  "limits":[
   "Exact pointer-like LE32 word can appear as data; source dereference and control-flow edge not established.",
   "Only ALLOC nonexecuting PROGBITS word refs, zero-size function symbols and ELF e_entry; excludes relocated and computed code pointer tables.",
   "Two valid RISC-V instruction decodes do not certify executable region rather than data.",
   "ELF symbol sizes may be incomplete or incorrect; verified root status remains false."
  ]}

def evaluate(rom,graph):
 require(sha(rom)==ROM_SHA,"PINNED_ROM_SHA")
 require(graph["schema"]=="ESP32C3_ALL_ROM_FAST_GRAPH_V1" and graph["rom_source_sha256"]==ROM_SHA,"GRAPH_ROM_MISMATCH")
 result={}
 with tarfile.open(rom,mode="r:gz") as archive:
  for rev in REVS:
   members=[x for x in archive.getmembers() if x.isfile() and pathlib.PurePosixPath(x.name).name==rev]
   require(len(members)==1,"REV_ELF_MISSING")
   elf_bytes=archive.extractfile(members[0]).read()
   require(hashlib.sha256(elf_bytes).hexdigest()==graph["all_revisions"][rev]["elf_sha256"],"REV_SHA")
   result[rev]=analyze_one(elf_bytes,rev,graph)
 return {"schema":"ROM001_P0A_INDIRECT_ROOT_CENSUS_V1",
  "original_issue_id":"ESP32C3-ROM-001",
  "ROM_archive_SHA256":ROM_SHA,"revisions":result,
  "verified_new_functions":0,"verified_silicon_executions":0}
def main():
 p=argparse.ArgumentParser()
 for name in ("rom","graph","out"):p.add_argument("--"+name,required=True,type=pathlib.Path)
 a=p.parse_args();r=evaluate(a.rom,json.loads(a.graph.read_text()))
 a.out.parent.mkdir(exist_ok=True,parents=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_P0A_INDIRECT_ROOTS",json.dumps({rev:{k:item[k] for k in ("gap_bytes","gap_intervals","nonexec_alloc_le32_matches","distinct_root_candidates","syntactic_two_instruction_landing","zero_size_symbol_roots","ELF_entry_in_gap")} for rev,item in r["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
