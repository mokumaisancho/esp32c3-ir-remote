#!/usr/bin/env python3
"""ROM-003 B1 bounded RV32C pre-disassembly superset-CFG feasibility POC.

This is NOT the complete Amace algorithm (no global backward stack/register
abstract interpretation). It adapts the paper's every-halfword supergraph and
reverse predecessor checking. Paths from ELF STT_FUNC starts are CONDITIONAL,
not physical execution traces. Absence of rooted path is not proof of absence.
"""
import argparse, collections, hashlib, json, pathlib
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
from rom_boundary_source_seal import validate_candidate_input
from rom_boundary_byte_frontier import direct
from rom_boundary_extent_triage import classify as extent_classify
from rom_boundary_blind_evaluator import REVS

SCHEMA="ROM003_B1_SUPERSET_REVERSE_V1"
LIMIT_NODES=240000

def ensure(v,why):
 if not v:raise ValueError(why)

def rawmap(public):
 validate_candidate_input(public)
 return [(int(x["start_pc"],16),bytes.fromhex(x["raw_hex"]))
         for x in public["exec_regions"]]

def instruction_at(dec,base,raw,offset):
 pc=base+offset
 if offset+2>len(raw):return None
 width=2 if raw[offset]&3!=3 else 4
 if offset+width>len(raw):return None
 ins=next(dec.disasm(raw[offset:offset+width],pc,count=1),None)
 if ins is None or ins.size!=width or ins.mnemonic in (
   "unimp","c.unimp","ecall","ebreak","c.ebreak",".byte"):return None
 return width,ins.mnemonic,raw[offset:offset+width]

def dynamic_barrier(bytecode, mnemonic):
 if len(bytecode)==4:
  word=int.from_bytes(bytecode,"little")
  op=word&127
  if op==0x67:return True  # JALR is indirect, target unresolved
  if op==0x73:return ((word>>12)&7)==0  # only privileged/trap encodings stop; CSR ops continue
  return False/system
 w=int.from_bytes(bytecode,"little")
 # quadrant 2, funct3=100, rs2=0, rs1!=0 : c.jr/c.jalr
 if w&3==2 and (w>>13)&7==4 and ((w>>2)&31)==0 and ((w>>7)&31):
  return True
 return mnemonic in ("ret","mret","sret","uret","c.jr","c.jalr")

def supergraph(public):
 regions=rawmap(public)
 dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 nodes=set();edges={};reverse=collections.defaultdict(list);stoppers=collections.Counter()
 for base,blob in regions:
  for off in range(0,len(blob)-1,2):
   ins=instruction_at(dec,base,blob,off)
   if not ins:continue
   width,mnem,raw=ins;pc=base+off
   nodes.add(pc)
   branch=direct(raw,pc)
   if branch:
    dest,kind=branch
    opts=[(dest,kind,"EXPLICIT_MACHINE_DIRECT")]
    if kind in ("DIRECT_CALL","BASIC_BLOCK_BRANCH"):
     opts.append((pc+width,"FALLTHROUGH_ASSUMED_RETURN_IF_CALL","CONDITIONAL_FALLTHROUGH"))
   elif dynamic_barrier(raw,mnem):
    opts=[];stoppers["INDIRECT_OR_SYSTEM_STOP"]+=1
   else:
    opts=[(pc+width,"SEQUENTIAL","EXPLICIT_LENGTH")]
   edges[pc]=[(dest,kind,why,raw.hex()) for dest,kind,why in opts]
 ensure(len(nodes)<LIMIT_NODES,"SUPERSET_NODE_BUDGET_EXCEEDED")
 # Destination must be an actually decoded halfword-aligned candidate node.
 for pc,elist in edges.items():
  kept=[]
  for dest,kind,why,bits in elist:
   if dest in nodes:
    kept.append((dest,kind,why,bits))
    reverse[dest].append((pc,kind,why,bits))
  edges[pc]=kept
 return nodes,edges,reverse,stoppers

def seeded_paths(nodes,edges,seeds):
 """Amortized multi-seed graph walk, predecessor pointers for reverse witnesses.

 This only proves a path exists IN THE OVER-APPROXIMATED GRAPH.
 It never proves physical instruction execution or true function boundaries.
 """
 roots=sorted(set(seeds)&nodes)
 previous={pc:None for pc in roots}
 who={pc:pc for pc in roots};q=collections.deque(roots)
 while q:
  src=q.popleft()
  for dst,kind,why,bits in edges[src]:
   if dst not in previous:
    previous[dst]=(src,kind,why,bits)
    who[dst]=who[src];q.append(dst)
 return previous,who

def backtrack(pc,prev,max_steps=4096):
 if pc not in prev:return None
 path=[];seen=set();at=pc
 while prev[at] is not None and len(path)<max_steps:
  ensure(at not in seen,"PREDECESSOR_LOOP")
  seen.add(at)
  source,kind,why,bits=prev[at]
  path.append({"from_pc":hex(source),"to_pc":hex(at),
               "kind":kind,"provenance":why,"raw":bits})
  at=source
 ensure(prev[at] is None,"PATH_BUDGET_EXCEEDED")
 path.reverse()
 return path

def inspect(public,oracle,unclaimed):
 ensure(public["revision"]==oracle["revision"]==unclaimed["revision"],"REVISION_MISMATCH")
 nodes,edges,reverse,stop=supergraph(public)
 boot=int(public["root_pc"],16)
 boot_path,boot_origin=seeded_paths(nodes,edges,[boot])
 known=set(int(x["entry_pc"],16) for x in oracle["symbol_function_records"])
 named_path,named_origin=seeded_paths(nodes,edges,known)
 entries=[];counts=collections.Counter()
 for candidate in unclaimed["unknown_entries"]:
  dest=int(candidate["pc"],16)
  for w in candidate["witnesses"]:
   source=int(w["from_pc"],16)
   # Exact same raw link bytes must be decoded at that halfword.
   ensure(source in nodes and dest in nodes,"PSEUDO_SOURCE_OR_TARGET_NOT_A_DECODED_NODE")
   exact=any(target==dest and kind=="DIRECT_CALL" and bits==w["opcode_hex"]
     for target,kind,why,bits in edges[source])
   ensure(exact,"RAW_LINK_MISMATCH_WITH_SUPERGRAPH")
   bp=backtrack(source,boot_path)
   np=backtrack(source,named_path)
   if bp is not None:
    grade="ROOTED_AT_ELF_ENTRY_STATIC_SUPERSET_PATH"
   elif np is not None:
    grade="NAMED_ENTRY_CONDITIONAL_STATIC_PATH"
   else:
    grade="UNREACHED_IN_THIS_DIRECT_EDGE_SUPERSET"
   counts[grade]+=1
   entries.append({"candidate_pc":hex(dest),"source_pc":hex(source),
    "source_machine_bytes":w["opcode_hex"],
    "source_pc_decodable_at_halfword":True,
    "classification":grade,
    "boot_rooted_path":bp if bp is not None else None,
    "named_anchor_pc":hex(named_origin[source]) if np is not None else None,
    "named_anchor_path":np if np is not None else None,
    "physical_executability_proven":False,
    "new_function_boundary_proven":False,
    "novel_callable_ROM_API_proven":False})
 ensure(sum(counts.values())==sum(len(x["witnesses"]) for x in unclaimed["unknown_entries"]),
        "WITNESS_COUNTS_DROPPED")
 return {"revision":public["revision"],
  "superset_decodable_halfword_nodes":len(nodes),
  "superset_machine_edges":sum(map(len,edges.values())),
  "boot_syntactically_reachable_nodes":len(boot_path),
  "named_seeded_syntactically_reachable_nodes":len(named_path),
  "unclaimed_candidate_targets":len(unclaimed["unknown_entries"]),
  "raw_source_witnesses":len(entries),"source_grade_counts":dict(counts),
  "source_results":entries,
  "hardware_execution_traces":0,"new_verified_usable_ROM_APIs":0,
  "limitations":[
    "Superset CFG contains data-looking instructions and overlapped alternatives.",
    "A named STT_FUNC entry used as a seed is CONDITIONAL and not an observed boot execution.",
    "Call fallthrough is conditional on return; path existence does not prove execution.",
    "Unresolved CSR/vector, JALR/table and alternate control flow are omitted.",
    "This is a bounded RV32C subset inspired by Amace, NOT its full backward SP/register analysis.",
    "No path in this bounded overapproximation cannot prove that real ROM code is unreachable."]}

def main():
 a=argparse.ArgumentParser()
 a.add_argument("--raw-dir",required=True,type=pathlib.Path)
 a.add_argument("--oracle-dir",required=True,type=pathlib.Path)
 a.add_argument("--candidate-dir",required=True,type=pathlib.Path)
 a.add_argument("--out",required=True,type=pathlib.Path)
 p=a.parse_args();out={"schema":SCHEMA,"revisions":[],"verified_novel_ROM_APIs":0}
 for rev in REVS:
  raw=json.loads((p.raw_dir/(rev+".json")).read_text())
  oracle=json.loads((p.oracle_dir/(rev+".json")).read_text())
  c=json.loads((p.candidate_dir/(rev+".json")).read_text())
  r=inspect(raw,oracle,extent_classify(c,oracle))
  out["revisions"].append(r)
  print("ROM003_B1_REVERSE",json.dumps({"rev":rev,
   "nodes":r["superset_decodable_halfword_nodes"],
   "links":r["superset_machine_edges"],
   "boot_reach":r["boot_syntactically_reachable_nodes"],
   "named_reach":r["named_seeded_syntactically_reachable_nodes"],
   "source_counts":r["source_grade_counts"]},sort_keys=True))
 p.out.parent.mkdir(parents=True,exist_ok=True)
 p.out.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
