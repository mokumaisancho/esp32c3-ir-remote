#!/usr/bin/env python3
"""ROM-001 P0-A direct machine-proven JALR -> unlabelled executable gap.

Reuse exact-neighbor def-use, readonly-only-pointer verification from
rom_strict_indirect.candidate_call; widen TARGET INDEX from STT_FUNC starts
to RV32IMC half-word executable gap addresses, but never equate a resolved
edge with execution, separate function, or unique hardware capability.

This resolves a concrete coverage blind spot in prior strict_indirect.py:
candidate_call previously required targets to equal positive-size STT_FUNC.
"""
import argparse,bisect,collections,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,REVS,require,sha
from rom_fast_graph import make_symbol_index
from rom_p0a_indirect_roots import build_gaps,in_gap
from rom_strict_indirect import candidate_call,decode_jalr,trace_load_base
MAX_TARGET_HALFWORDBYTES=32768

def inspect(blob,rev,graph):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 elf=ELFFile(io.BytesIO(blob))
 sections,bounds,pairs,owners,entries,_=make_symbol_index(elf)
 gaps=build_gaps(bounds,pairs)
 nbytes=sum(b-a for a,b in gaps)
 require(0<nbytes<MAX_TARGET_HALFWORDBYTES,"GAP_SCOPE_TOO_LARGE")
 # Every half-word address must be in the official executable sections, not symbol covered.
 targets={pc:["POTENTIAL_EXEC_GAP_HALFWORD_NOT_SYMBOL"] for a,b in gaps
          for pc in range(a+(a&1),b-1,2)}
 require(len(targets)>0,"EMPTY_GAP_TARGET_INDEX")
 named=graph["function_byte_evidence"][rev]
 decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 decoder.skipdata=True
 named_calls=0;total_jalrs=0;hits=[];unresolved_cause=collections.Counter()
 for s in sections:
  base=int(s["sh_addr"]);data=s.data()
  ins=list(decoder.disasm(data,base))
  require(sum(x.size for x in ins)==len(data),"DECODER_LOST_BYTES")
  starts=[x.address for x in ins]
  for key,f in named.items():
   a=int(f["entry"],16);b=a+f["size_bytes"]
   if not (base<=a<b<=base+len(data)):continue
   lo=bisect.bisect_left(starts,a);hi=bisect.bisect_left(starts,b)
   seq=ins[lo:hi]
   if not seq or seq[0].address!=a or seq[-1].address+seq[-1].size!=b:continue
   for i,x in enumerate(seq):
    j=decode_jalr(x)
    if j is None or (j["rs1"]==1 and j["rd"]==0 and j["imm"]==0):continue
    total_jalrs+=1
    result=candidate_call(seq,i,elf,targets)
    if result is None:
     unresolved_cause["NO_EXACT_NEIGHBOR_ROM_GAP_TARGET"]+=1
     continue
    target=int(result["resolved_callee"],16)
    require(in_gap(gaps,target),"BAD_GAP_TARGET_CLASSIFICATION")
    hits.append({"revision":rev,"caller_function_id":key,
      "caller_name_aliases":f["aliases"],**result,
      "callee_in_executable_without_STT_FUNC":True,
      "dynamic_execution_proven":False,"new_function_boundary_proven":False,
      "novel_function_proven":False})
 return {"revision":rev,"rom_sha256":hashlib.sha256(blob).hexdigest(),
   "gap_bytes":nbytes,
   "indexed_halfword_gap_targets":len(targets),
   "indirect_nonreturn_jalr_in_named_functions":total_jalrs,
   "resolved_static_JALR_into_gap":len(hits),
   "gap_edges":hits,
   "unresolved_reason_counts":dict(unresolved_cause),
   "limits":["Cannot infer JALR target loaded from writable RAM or through nonadjacent computed arithmetic.",
      "Resolved machine byte pattern is a potential static edge, not proof of actual execution.",
      "Gaps are absence of positive-sized ELF function symbol, not necessarily real code.",
      "No hardware behavior, API, function entry ABI or silicon novelty verified."]}

def evaluate(rom,graph):
 require(sha(rom)==ROM_SHA,"PINNED_OFFICIAL_ROM_SOURCE")
 require(graph.get("schema")=="ESP32C3_ALL_ROM_FAST_GRAPH_V1"
   and graph.get("rom_source_sha256")==ROM_SHA,"GRAPH_PROVENANCE")
 out={}
 with tarfile.open(rom,mode="r:gz") as t:
  for rev in REVS:
   files=[x for x in t.getmembers() if x.isfile() and pathlib.PurePosixPath(x.name).name==rev]
   require(len(files)==1,"ELF_REV_MATCH")
   blob=t.extractfile(files[0]).read()
   require(hashlib.sha256(blob).hexdigest()==graph["all_revisions"][rev]["elf_sha256"],"ROM_REV_BYTE_SHA")
   out[rev]=inspect(blob,rev,graph)
 return {"schema":"ROM001_P0A_STRICT_INDIRECT_INTO_GAPS_V1",
  "original_issue_id":"ESP32C3-ROM-001","ROM_source_sha256":ROM_SHA,
  "revisions":out,"confirmed_new_functions":0,"silicon_verified_calls":0}

def main():
 p=argparse.ArgumentParser()
 for name in ("rom","graph","out"):p.add_argument("--"+name,required=True,type=pathlib.Path)
 a=p.parse_args()
 r=evaluate(a.rom,json.loads(a.graph.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
 print("ROM_P0A_INDIRECT_GAP",json.dumps({
  rev:{"gap_bytes":v["gap_bytes"],"jalrs_examined":v["indirect_nonreturn_jalr_in_named_functions"],
   "exact_new_gap_targets":v["resolved_static_JALR_into_gap"]}
  for rev,v in r["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
