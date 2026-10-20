#!/usr/bin/env python3
"""ROM-001 P0-A: RV32IMC conditional-branch seeds into symbol-size gaps.

Research: Datalog Disassembly (USENIX 2020) + Disassembly as Weighted
Interval Scheduling with Learned Weights (IEEE S&P 2025). This implements
ONLY binary branch decoding and deterministic weighted interval selection;
NO learned weights, NO claim of novel function, NO executing firmware.
"""
import argparse,bisect,collections,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,REVS,require,sha
from new_function_hunt import merged
from rom_fast_graph import make_symbol_index
from rom_opcode import jal,compressed_jump

FORBIDDEN={"flw","fsw","fld","fsd","c.flw","c.fsw","c.fld","c.fsd","unimp","c.unimp",".byte"}
def sext(v,width):
 return v-(1<<width) if v&(1<<(width-1)) else v

def branch_target(raw,pc):
 """Decode branch directions from exact ISA bytes, not disassembler op_str."""
 b=bytes(raw)
 if len(b)==4:
  w=int.from_bytes(b,"little")
  if w&127==0x63 and (w>>12)&7 in (0,1,4,5,6,7):
   imm=(((w>>31)&1)<<12)|(((w>>7)&1)<<11)|(((w>>25)&63)<<5)|(((w>>8)&15)<<1)
   return pc+sext(imm,13),"B_RV32",False
  if w&127==0x6f:
   target=jal(b,pc)
   return target,"JAL_RV32",((w>>7)&31)!=0
 if len(b)==2:
  w=int.from_bytes(b,"little")
  if w&3==1 and (w>>13)&7 in (6,7):
   imm=(((w>>12)&1)<<8)|(((w>>5)&3)<<6)|(((w>>2)&1)<<5)|(((w>>10)&3)<<3)|(((w>>3)&3)<<1)
   return pc+sext(imm,9),"CB_RVC",False
  if w&3==1 and (w>>13)&7 in (1,5):
   target=compressed_jump(b,pc)
   return target,"CJ_RVC",((w>>13)&7)==1
 return None

def select_nonoverlapping(candidates):
 """Classic weighted interval scheduling, O(n log n), fixed integer weights."""
 ranked=sorted(candidates,key=lambda x:(x["stop"],x["start"],x["anchor_id"]))
 stops=[x["stop"] for x in ranked]
 prev=[bisect.bisect_right(stops,x["start"],0,i)-1 for i,x in enumerate(ranked)]
 dp=[0]
 for i,x in enumerate(ranked):
  use=x["weight"]+dp[prev[i]+1]
  dp.append(max(dp[-1],use))
 chosen=[];i=len(ranked)
 while i>0:
  x=ranked[i-1];use=x["weight"]+dp[prev[i-1]+1]
  if use>dp[i-1]:chosen.append(x);i=prev[i-1]+1
  else:i-=1
 return list(reversed(chosen))

def scan_one(blob,rev,graph):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 elf=ELFFile(io.BytesIO(blob))
 require(elf["e_machine"]=="EM_RISCV" and elf.elfclass==32 and elf.little_endian,"BAD_ISA")
 sections,bounds,pairs,owners,entries,_=make_symbol_index(elf)
 known_sections=[]
 covered=merged(pairs)
 starts=[a for a,b in covered]
 def contained(addr):
  i=bisect.bisect_right(starts,addr)-1
  return i>=0 and addr<covered[i][1]
 for sec in sections:
  known_sections.append((int(sec["sh_addr"]),int(sec["sh_addr"])+int(sec["sh_size"]),sec.data()))
 dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC);dec.skipdata=True
 evidence=collections.defaultdict(list);all_branches=collections.Counter();invalid_in_named=0
 source_ranges=graph["function_byte_evidence"][rev]
 for base,end,raw in known_sections:
  ins=list(dec.disasm(raw,base))
  require(sum(x.size for x in ins)==len(raw),"LOST_DISASSEMBLY_BYTES")
  for x in ins:
   if not contained(x.address):continue
   owners_here=owners(x.address)
   if not owners_here:continue
   if not any(a<=x.address and x.address+x.size<=b for a,b in owners_here):continue
   if x.mnemonic in FORBIDDEN:
    invalid_in_named+=1;continue
   target=branch_target(bytes(x.bytes),x.address)
   if target is None:continue
   dst,kind,link=target;all_branches[kind]+=1
   if not any(lo<=dst<hi for lo,hi,_ in known_sections):continue
   if contained(dst):continue
   for a,b in owners_here:
    fid=f"{a:08x}:{b-a:x}"
    require(fid in source_ranges,"UNKNOWN_ELF_CALLER")
    evidence[dst].append({"source_pc":hex(x.address),
      "source_function":fid,"source_aliases":source_ranges[fid]["aliases"][:4],
      "raw_instruction_bytes":bytes(x.bytes).hex(),
      "kind":kind,"link_bit":link})
 candidates=[]
 for target,edges in sorted(evidence.items()):
  record=next(((lo,hi,data) for lo,hi,data in known_sections if lo<=target<hi),None)
  require(record is not None,"MISSING_LANDING_REGION")
  lo,hi,data=record
  window=data[target-lo:min(len(data),target-lo+64)]
  strict=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
  seq=[]
  for instruction in strict.disasm(window,target):
   if instruction.mnemonic in FORBIDDEN:break
   if contained(instruction.address):break
   seq.append({"pc":hex(instruction.address),"mnemonic":instruction.mnemonic,
      "machine_bytes":bytes(instruction.bytes).hex(),"length":instruction.size})
   if len(seq)>=12 or instruction.mnemonic in ("c.j","j","ret","c.jr","jalr"):break
  call_sources=[x for x in edges if x["link_bit"]]
  if not seq:status="INVALID_RV32IMC_LANDING"
  elif call_sources:status="CALL_LINK_BIT_INTO_GAP_NEEDS_ENTRY_PROOF"
  else:status="POSSIBLE_GAP_BASIC_BLOCK_NOT_A_FUNCTION_ENTRY"
  if seq:
   # Interval is a candidate code slice, not proof of its instructions.
   candidates.append({"start":target,"stop":target+sum(s["length"] for s in seq),
    "weight":10*len({x["source_pc"] for x in edges})+len(seq),
    "anchor_id":hex(target)})
  evidence[target]={"entry":hex(target),"source_in_ELF_function":True,
    "witnesses":edges[:12],"unique_source_count":len({x["source_pc"] for x in edges}),
    "source_call_link_count":len(call_sources),"landing":seq,
    "classification":status,"validated_new_function":False,
    "silicon_behavior_proven":False}
 chosen=select_nonoverlapping(candidates)
 selected_ids={x["anchor_id"] for x in chosen}
 for addr,item in evidence.items():
  item["weighted_nonoverlapping_selected"]=item["entry"] in selected_ids
 return {"revision":rev,"ELF_sha256":hashlib.sha256(blob).hexdigest(),
  "symbol_covered_source_branches":dict(all_branches),
  "invalid_linear_items_in_named_source":invalid_in_named,
  "raw_gap_target_count":len(evidence),
  "gap_targets_with_call_link":sum(x["source_call_link_count"]>0 for x in evidence.values()),
  "weighted_nonoverlap_selected":len(chosen),
  "evidence_by_target":{hex(k):v for k,v in evidence.items()},
  "limitations":["Conditional branch into a gap is usually a basic block, not a function.",
  "Disassembler output is not an independent byte-vs-data proof.",
  "Weighted interval selection is an evidence-priority heuristic, not a full implementation of learned-weight WIS.",
  "No indirect computed dispatch, interrupt roots or unstated external roots included."]}

def evaluate(rom,graph):
 require(sha(rom)==ROM_SHA,"PINNED_ROM_SHA")
 require(graph["schema"]=="ESP32C3_ALL_ROM_FAST_GRAPH_V1" and
  graph["rom_source_sha256"]==ROM_SHA,"SOURCE_GRAPH_IDENTITY")
 results={}
 with tarfile.open(rom,"r:gz") as tar:
  for rev in REVS:
   files=[m for m in tar.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   require(len(files)==1,"PINNED_REV_MISSING")
   data=tar.extractfile(files[0]).read()
   require(hashlib.sha256(data).hexdigest()==graph["all_revisions"][rev]["elf_sha256"],"ELF_SHA")
   results[rev]=scan_one(data,rev,graph)
 return {"schema":"ROM001_P0A_BRANCH_SEEDED_GAP_WIS_V1",
  "original_issue_id":"ESP32C3-ROM-001","ROM_source_SHA256":ROM_SHA,
  "publication_methods":["Datalog Disassembly 2020","Weighted Interval Scheduling Disassembly 2025"],
  "models_trained":False,"proprietary_weights_used":False,
  "revisions":results,"new_function_proven":0,"original_issue_unchanged":True}
def main():
 p=argparse.ArgumentParser()
 for name in ("rom","graph","out"):p.add_argument("--"+name,type=pathlib.Path,required=True)
 a=p.parse_args();r=evaluate(a.rom,json.loads(a.graph.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,sort_keys=True,separators=(",",":"))+"\n")
 print("ROM_P0A_GAP_SEEDS",json.dumps({rev:{
  "targets":x["raw_gap_target_count"],"call_like":x["gap_targets_with_call_link"],
  "selected_nonoverlap":x["weighted_nonoverlap_selected"]}
  for rev,x in r["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
