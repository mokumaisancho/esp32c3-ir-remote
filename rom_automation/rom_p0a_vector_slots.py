#!/usr/bin/env python3
"""ROM001: 32 RV32 mtvec vectored slots, direct-branch target evidence ONLY."""
import argparse,hashlib,io,json,pathlib,tarfile,collections
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,REVS,require,sha
from rom_fast_graph import make_symbol_index
from rom_p0a_entry_trampoline import direct_unconditional_j
from rom_p0a_indirect_roots import build_gaps,in_gap

def analyze(blob,rev,graph,trap):
 elf=ELFFile(io.BytesIO(blob))
 sections,bounds,pairs,owners,entries,_=make_symbol_index(elf)
 w=[x for x in trap["writers"] if x["name"]=="mtvec" and x["static_value_only_if_adjacent"]]
 require(len(w)==1,"NO_UNIQUE_MTVEC_PROOF")
 t=w[0]["static_value_only_if_adjacent"]
 base=int(t["potential_vector_base"],16)
 require(t["csr_mode_low_bits"]==1,"NOT_VECTORED_MODE")
 named=[(a,b) for a,b in owners(base)
        if "_vector_table" in entries[f"{a:08x}:{b-a:x}"]["aliases"]]
 require(len(named)==1 and named[0][0]==base and named[0][1]-base>=128,"VECTOR_SYMBOL_NOT_128_BYTES")
 sec=next(((int(x["sh_addr"]),x.data()) for x in sections if
    int(x["sh_addr"])<=base and base+128<=int(x["sh_addr"])+int(x["sh_size"])),None)
 require(sec is not None,"VECTOR_TABLE_BYTES_MISSING")
 start,data=sec;gaps=build_gaps(bounds,pairs)
 slots=[];counts=collections.Counter()
 for cause in range(32):
  pc=base+cause*4;raw=data[pc-start:pc-start+4]
  dest=direct_unconditional_j(raw,pc)
  linked=sorted({n for a,b in (owners(dest) if dest is not None else [])
                 for n in entries[f"{a:08x}:{b-a:x}"]["aliases"]})
  flag="DIRECT_INTO_GAP" if dest is not None and in_gap(gaps,dest) else (
       "DIRECT_INTO_NAMED" if linked else "DIRECT_OTHER" if dest is not None else "NON_DIRECT")
  counts[flag]+=1
  slots.append({"interrupt_or_exception_cause":cause,"pc":hex(pc),"raw":raw.hex(),
    "raw_direct_branch_target":hex(dest) if dest is not None else None,
    "target_ELF_names":linked,"target_in_symbol_gap":flag=="DIRECT_INTO_GAP",
    "classification":flag,
    "runtime_dispatch_proven":False,"novel_function_proven":False})
 return {"revision":rev,"ELF_sha256":hashlib.sha256(blob).hexdigest(),
   "mtvec_static_value":t["raw_written_value"],"vector_base":hex(base),
   "vector_table_symbol":"_vector_table","vector_table_size":named[0][1]-base,
   "slot_count":32,"category_counts":dict(counts),
   "distinct_direct_targets":len({x["raw_direct_branch_target"] for x in slots if x["raw_direct_branch_target"]}),
   "slots":slots,"new_function_proven":0,
   "limits":["Mode1 cause0 exception and further interrupt slots are possible, not observed runtime.",
     "Only unconditional direct JAL/C.J, no indirect control, handler effect or application follow-on CSR updates verified."]}

def evaluate(rom,graph,trap):
 require(sha(rom)==ROM_SHA,"PINNED_ROM_SHA")
 require(graph["schema"]=="ESP32C3_ALL_ROM_FAST_GRAPH_V1" and graph["rom_source_sha256"]==ROM_SHA,"GRAPH_IDENTITY")
 require(trap["schema"]=="ROM001_P0A_OTHER_TRAP_VECTOR_ROOTS_V1" and trap["ROM_SHA256"]==ROM_SHA,"TRAP_IDENTITY")
 result={}
 with tarfile.open(rom,"r:gz") as archive:
  for rev in REVS:
   refs=[x for x in archive.getmembers() if x.isfile() and pathlib.PurePosixPath(x.name).name==rev]
   require(len(refs)==1,"MISSING_ELF")
   blob=archive.extractfile(refs[0]).read()
   require(hashlib.sha256(blob).hexdigest()==graph["all_revisions"][rev]["elf_sha256"],"REV_SOURCE")
   result[rev]=analyze(blob,rev,graph,trap["revisions"][rev])
 return {"schema":"ROM001_P0A_VECTOR_TABLE_DISPATCH_CENSUS_V1",
  "original_issue_id":"ESP32C3-ROM-001","ROM_SHA256":ROM_SHA,
  "revisions":result,"independent_new_capability_confirmed":0,"silicon_tested":False}

def main():
 p=argparse.ArgumentParser()
 for n in ("rom","graph","trap","out"):p.add_argument("--"+n,required=True,type=pathlib.Path)
 a=p.parse_args();r=evaluate(a.rom,json.loads(a.graph.read_text()),json.loads(a.trap.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_P0A_VECTOR_SLOTS",json.dumps({rev:{"base":d["vector_base"],
  "slots":d["slot_count"],"categories":d["category_counts"],
  "distinct_targets":d["distinct_direct_targets"]}
  for rev,d in r["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
