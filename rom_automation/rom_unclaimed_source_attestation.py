#!/usr/bin/env python3
"""ROM-003/T5 source witness attestation on the 252 unclaimed ELF extents.

Evaluator-only. The scanner never receives STT_FUNC starts/sizes. This checks
whether a raw potential C.JAL/JAL *source* occurs on a disassembler-confirmed
instruction boundary from a named ELF entry. A linear symbol decode is not an
execution proof and can be wrong in data or assembly corner cases.
"""
import argparse,bisect,collections,json,pathlib
from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
from rom_boundary_source_seal import validate_candidate_input
from rom_boundary_byte_frontier import direct
from rom_boundary_blind_evaluator import REVS
from rom_boundary_extent_triage import classify as extent_classify

SCHEMA="ROM003_T5_UNCLAIMED_SOURCE_PROVENANCE_V1"
def need(ok,msg):
 if not ok:raise ValueError(msg)

def source_alignment(raw_regions,source_pc,source_raw,holders):
 """Check independently decoded RV32C stream from each named function entry.

 States only whether pc is consistent with that *linear* instruction stream,
 not that the source is dynamically/root-call reachable.
 """
 d=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 for a,b in holders:
  region=next(((base,raw) for base,raw in raw_regions
              if base<=a<=source_pc<base+len(raw) and b<=base+len(raw)),None)
  if region is None:continue
  base,raw=region
  offset=a-base;sub=raw[offset:source_pc-base+4]
  boundary=None;last=None;gap=None
  for ins in d.disasm(sub,a):
   if ins.address==source_pc:
    boundary=ins;break
   if ins.address<source_pc<ins.address+ins.size:
    gap=ins;break
   last=ins
  if gap is not None:
   # Byte-wise ISA length confirms the 32-bit instruction straddling PC.
   insraw=bytes(gap.bytes)
   if insraw[0]&3==3 and len(insraw)==4:
    need(bytes(raw[source_pc-base:source_pc-base+len(source_raw)])==source_raw,
         "SOURCE_BYTE_WITNESS_MISMATCH")
    return {"classification":"INSIDE_32BIT_INSTRUCTION_FROM_NAMED_ENTRY",
       "function_start":hex(a),"straddling_pc":hex(gap.address),
       "straddling_raw":insraw.hex(),
       "symbol_linear_boundary_proven":False,
       "independent_reachable_execution_proven":False}
   return {"classification":"INTERIOR_OF_DECODED_INSTRUCTION_FROM_NAMED_ENTRY",
     "function_start":hex(a),"straddling_pc":hex(gap.address),
     "symbol_linear_boundary_proven":False,"independent_reachable_execution_proven":False}
  if boundary is not None:
   if bytes(boundary.bytes)!=source_raw:
    return {"classification":"SOURCE_BYTES_DO_NOT_MATCH_NAMED_DECODE",
     "symbol_linear_boundary_proven":False,
     "independent_reachable_execution_proven":False}
   return {"classification":"ELF_NAMED_LINEAR_CALL_SYNTAX_NOT_ROOTED",
      "function_start":hex(a),"source_pc":hex(source_pc),
      "source_raw":source_raw.hex(),
      "symbol_linear_boundary_proven":True,
      "independent_reachable_execution_proven":False}
 return {"classification":"NAMED_EXTENT_BUT_LINEAR_SOURCE_UNRESOLVED",
   "symbol_linear_boundary_proven":False,
   "independent_reachable_execution_proven":False}

def audit(candidate,oracle,raw_input):
 need(candidate["revision"]==oracle["revision"]==raw_input["revision"],"REVISION_DRIFT")
 validate_candidate_input(raw_input)
 names={(int(x["entry_pc"],16),int(x["entry_pc"],16)+x["size_bytes"])
        for x in oracle["symbol_function_records"]}
 regions=[(int(x["start_pc"],16),bytes.fromhex(x["raw_hex"]))
          for x in raw_input["exec_regions"]]
 coarse=extent_classify(candidate,oracle)
 results=[];totals=collections.Counter()
 for item in coarse["unknown_entries"]:
  dest=int(item["pc"],16)
  need(item["rooted_call_witnesses"]==0 if "rooted_call_witnesses" in item
       else not item["source_rooted"],"ROOTED_UNCLAIMED_CLAIM_CONFLICT")
  verdict=[]
  for w in item["witnesses"]:
   source=int(w["from_pc"],16)
   raw=bytes.fromhex(w["opcode_hex"])
   parsed=(direct(raw,source) if len(raw) in (2,4) else None)
   need(parsed is not None and parsed[1]=="DIRECT_CALL" and parsed[0]==dest,
        "WITNESS_NOT_A_BYTE_CORRECT_CALL")
   candidates=[(a,b) for a,b in names if a<=source<b]
   if not candidates:
    status={"classification":"NO_ELF_NAMED_SOURCE",
      "symbol_linear_boundary_proven":False,
      "independent_reachable_execution_proven":False}
   else:
    statuses=[source_alignment(regions,source,raw,[pair]) for pair in sorted(candidates)]
    # If any named overlapping function has a valid linear boundary, do not
    # dismiss source based on another alias/overlap interpretation.
    valid=next((x for x in statuses if x["symbol_linear_boundary_proven"]),None)
    status=valid or statuses[0]
   status["source_pc"]=hex(source);status["byte_witness"]=raw.hex()
   totals[status["classification"]]+=1;verdict.append(status)
  results.append({"candidate_pc":hex(dest),"witnesses":verdict,
    "verified_incoming_control_flow_edge":False,
    "novel_function_entry_proven":False})
 counts=coarse["triage_counts"]
 need(len(results)==counts["OUTSIDE_NAMED_ELF_EXTENTS_UNJUDGED"],
      "UNCALCULATED_CANDIDATE")
 return {"revision":candidate["revision"],"unclaimed_candidates":len(results),
  "total_raw_incoming_witnesses":sum(totals.values()),
  "witness_source_categories":dict(totals),
  "candidates_with_independent_rooted_proof":0,
  "candidate_reviews":results,
  "limits":[
  "Symbols are used only in an evaluator job AFTER the E1 candidate run; they never seed candidate generation.",
  "A named ELF function range need not be complete or fully code; linear Capstone anchoring is a conservative witness, not dynamic proof.",
  "A raw C.JAL-looking halfword in the SECOND HALF of a 32-bit instruction is not a call under that linear decode.",
  "An alternate rooted jump into such a halfword cannot be ruled out solely by linear disassembly; remain UNKNOWN without that root.",
  "The remaining unclaimed-source cases may be data, code, or unresolved indirect entries; absence of evidence is not proof of absence.",
  "This audit makes no novel callable ABI, silicon behavior, or hardware safety claim."]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--candidate-dir",required=True,type=pathlib.Path)
 p.add_argument("--oracle-dir",required=True,type=pathlib.Path)
 p.add_argument("--raw-dir",required=True,type=pathlib.Path)
 p.add_argument("--out",required=True,type=pathlib.Path)
 a=p.parse_args()
 output={"schema":SCHEMA,"revisions":[],"confirmed_new_usable_ROM_APIs":0}
 for rev in REVS:
  c=json.loads((a.candidate_dir/(rev+".json")).read_text())
  o=json.loads((a.oracle_dir/(rev+".json")).read_text())
  r=json.loads((a.raw_dir/(rev+".json")).read_text())
  record=audit(c,o,r)
  output["revisions"].append(record)
  print("ROM003_SOURCE_ATTEST",json.dumps({"rev":rev,"candidates":record["unclaimed_candidates"],
    "raw_witnesses":record["total_raw_incoming_witnesses"],
    "source_categories":record["witness_source_categories"],
    "rooted_candidate_proofs":0},sort_keys=True))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(output,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
