#!/usr/bin/env python3
"""ROM-003: evaluator-only triage of symbol-unclaimed raw call targets.

This runs ONLY after the candidate job completes; it cannot influence source
ranking. Extent absence is NOT proof of code; symbol interiors aren't known
negative examples. All reasons are preserved without assigning novelty.
"""
import argparse,bisect,json,pathlib
from rom_boundary_blind_evaluator import REVS,addresses

def classify(candidate,oracle):
 if candidate.get("revision")!=oracle.get("revision"):
  raise ValueError("REVISION_ID_MISMATCH")
 records=oracle["symbol_function_records"]
 ranges=sorted({(int(x["entry_pc"],16),int(x["entry_pc"],16)+x["size_bytes"]) for x in records})
 starts={x[0] for x in ranges}
 lo=[x for x,y in ranges];hi=[];m=0
 for x,y in ranges:m=max(m,y);hi.append(m)
 def relation(pc):
  if pc in starts:return "ELF_NAMED_FUNCTION_START"
  i=bisect.bisect_right(lo,pc)-1
  if i>=0 and pc<hi[i]:return "INSIDE_NAMED_ELF_EXTENT_UNJUDGED"
  return "OUTSIDE_NAMED_ELF_EXTENTS_UNJUDGED"
 refs={int(x["entry_pc"],16):x for x in candidate["candidate_records"]}
 tally={k:0 for k in ("ELF_NAMED_FUNCTION_START",
  "INSIDE_NAMED_ELF_EXTENT_UNJUDGED","OUTSIDE_NAMED_ELF_EXTENTS_UNJUDGED")}
 unclaimed=[]
 rooted_unclaimed=[]
 for pc in addresses(candidate["ranked_possible_entries"]):
  status=relation(pc);tally[status]+=1
  if status=="OUTSIDE_NAMED_ELF_EXTENTS_UNJUDGED":
   entry=refs.get(pc)
   if entry is None:raise ValueError("MISSING_RAW_SOURCE_WITNESS:"+hex(pc))
   unclaimed.append({"pc":hex(pc),"classification":"UNJUDGED_BYTE_CANDIDATE_NOT_A_NEW_API",
    "source_rooted":entry["rooted_call_witnesses"]>0,
    "encoded_link_sources":entry["encoded_link_sources"],
    "machine_first_instruction":entry["machine_first_instruction"],
    "witnesses":entry["witnesses"]})
   if entry["rooted_call_witnesses"]>0:rooted_unclaimed.append(hex(pc))
 if sum(tally.values())!=candidate["unrooted_halfword_candidate_count"]:
  raise ValueError("CLASSIFICATION_TOTAL_CHANGED")
 return {"revision":candidate["revision"],"triage_counts":tally,
   "rooted_unclaimed_count":len(rooted_unclaimed),
   "rooted_unclaimed_entries":rooted_unclaimed,
   "unknown_entries":unclaimed,
   "no_independent_new_ROM_API_discovery":True,
   "limits":["Outside a positive-size ELF STT_FUNC interval is not proof of code or a function.",
    "A raw-call-target from a source not proven reachable can be executable-looking data.",
    "Function interior may contain shared tail code and alternative entrypoints, neither proof of new API.",
    "ELF oracle metadata is used only in this post-hoc evaluator process."]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--candidate-dir",type=pathlib.Path,required=True)
 p.add_argument("--evaluator-dir",type=pathlib.Path,required=True)
 p.add_argument("--output",type=pathlib.Path,required=True)
 a=p.parse_args();rs=[]
 for rev in REVS:
  c=json.loads((a.candidate_dir/(rev+".json")).read_text())
  g=json.loads((a.evaluator_dir/(rev+".json")).read_text())
  r=classify(c,g);rs.append(r)
  print("ROM003_E2_EXTENT_TRIAGE",json.dumps({"rev":rev,
   **r["triage_counts"],"rooted_unclaimed":r["rooted_unclaimed_count"]},
   sort_keys=True))
 out={"schema":"ROM003_E2_POSTHOC_ELF_EXTENT_TRIAGE_V1",
      "revisions":rs,"verified_new_usable_ROM_API_count":0}
 a.output.parent.mkdir(parents=True,exist_ok=True)
 a.output.write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")
if __name__=="__main__":main()
