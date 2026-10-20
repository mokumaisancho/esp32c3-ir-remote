#!/usr/bin/env python3
"""ROM-001 fast exact pointer-target census for all ELF function starts.

Only enumerates 32-bit little-endian words in ALLOC PROGBITS sections; an
address equality is candidate provenance, NOT proof of an executed callback.
RISC-V function pointer may include compact encodings and AUIPC constructs,
which are not covered here. No dynamic/silicon claims.
"""
import argparse,collections,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile
from decision_gate import REVS,ROM_SHA,require,sha

def pointer_matches(blob,rev,graph):
 elf=ELFFile(io.BytesIO(blob))
 index=graph["function_byte_evidence"][rev]
 targets=collections.defaultdict(list)
 for key,item in index.items():
  targets[int(item["entry"],16)].append(key)
 counts=collections.Counter();examples=[];by_target=collections.defaultdict(lambda:{"nonexec_alloc_refs":0,"executable_embedded_word_refs":0,"sources":[]})
 for section in elf.iter_sections():
  if section["sh_type"]!="SHT_PROGBITS" or not int(section["sh_flags"])&2 or not int(section["sh_size"]):continue
  base=int(section["sh_addr"]);data=section.data()
  exec_flag=bool(int(section["sh_flags"])&4)
  typ="EXECUTABLE_WORD_COINCIDENCE" if exec_flag else "ALLOCATED_NONEXEC_WORD"
  for pos in range((-base)%4,len(data)-3,4):
   address=base+pos;word=int.from_bytes(data[pos:pos+4],"little")
   if word not in targets:continue
   counts[typ]+=1
   for target_key in targets[word]:
    item=by_target[target_key]
    if exec_flag:item["executable_embedded_word_refs"]+=1
    else:item["nonexec_alloc_refs"]+=1
    if len(item["sources"])<8:
     item["sources"].append({"section":section.name,"addr":hex(address),"target_entry":hex(word),"provenance":typ})
 total=len(index);flagged={k:v for k,v in by_target.items() if v["nonexec_alloc_refs"]}
 return {"revision":rev,
  "function_bodies_in_graph":total,
  "counted_word_matches":dict(counts),
  "function_entry_targets_in_nonexec_sections":len(flagged),
  "function_entry_targets_any_alloc_section":len(by_target),
  "by_function_target":dict(by_target),
  "pointer_refs_not_proven_called":True,
  "unsupported_compressed_pointer_tables":True,
  "limitations":["Exact 32bit aligned words only; absolute addresses and relocated tables may use other encodings.",
    "Matching a function entry in memory does not certify dynamic invocation.",
    "Executable-section coincidences include machine opcodes; never promote these to callbacks."]}
def evaluate(rom,graph):
 require(sha(rom)==ROM_SHA,"PINNED_ROM_SHA")
 require(graph["schema"]=="ESP32C3_ALL_ROM_FAST_GRAPH_V1","GRAPH_PROVENANCE")
 require(graph["rom_source_sha256"]==ROM_SHA,"GRAPH_ROM_PROVENANCE")
 out={}
 with tarfile.open(rom,"r:gz") as f:
  for rev in REVS:
   member=[v for v in f.getmembers() if v.isfile() and pathlib.PurePosixPath(v.name).name==rev]
   require(len(member)==1,"MISSING_REV")
   blob=f.extractfile(member[0]).read()
   require(hashlib.sha256(blob).hexdigest()==graph["all_revisions"][rev]["elf_sha256"],"ELF_REV_SHA")
   out[rev]=pointer_matches(blob,rev,graph)
 return {"schema":"ESP32C3_ROM_POINTER_TARGET_EVIDENCE_V1",
  "original_issue_id":"ESP32C3-ROM-001",
  "rom_sha256":ROM_SHA,"revisions":out,
  "indirect_targets_verified_executed":0,
  "ECV4_authority_invoked":False,
  "new_function_proven":False,
  "recommendation":"Use exact pointer matches as corroborating directed evidence, not verified call edges."}

def main():
 p=argparse.ArgumentParser()
 for k in ("rom","graph","out"):p.add_argument("--"+k,type=pathlib.Path,required=True)
 a=p.parse_args()
 result=evaluate(a.rom,json.loads(a.graph.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
 print("ROM_POINTER_TARGETS",json.dumps({r:{
  "nonexec_exact_refs":v["counted_word_matches"].get("ALLOCATED_NONEXEC_WORD",0),
  "executable_word_coincidences":v["counted_word_matches"].get("EXECUTABLE_WORD_COINCIDENCE",0),
  "known_func_entries_matched_in_nonexec":v["function_entry_targets_in_nonexec_sections"]
 } for r,v in result["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
