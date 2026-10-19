#!/usr/bin/env python3
"""ROM-001 evidence-driven execution queue. No API novelty from names/CI status."""
import argparse,hashlib,json,pathlib,zipfile
from collections import Counter
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
GHIDRA_SHA="4a6dc279579db43844de466d0a9ff5b57dba54528f87e8c2cb4ef28387db5ea0"
MACHINE_SHA="cc08989ed0967d091b9d63eae9e714a661d03604fc54c6c57778b034ee264896"
ROM_SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
# Requires separate independent approval. Never populate from unreviewed model output.
APPROVED_REVIEW_SHA256=""
def require(x,code):
 if not x:raise RuntimeError("FAIL_CLOSED:"+code)
def sha(path):
 h=hashlib.sha256()
 with open(path,"rb") as f:
  for part in iter(lambda:f.read(1048576),b""):h.update(part)
 return h.hexdigest()
def read(z,key):return json.loads(z.read(key))
def evaluate(ghidra,machine,review_file,batch=8):
 require(sha(ghidra)==GHIDRA_SHA,"GHIDRA_SOURCE_HASH")
 require(sha(machine)==MACHINE_SHA,"MACHINE_SOURCE_HASH")
 with zipfile.ZipFile(ghidra) as g,zipfile.ZipFile(machine) as m:
  tri=read(g,"output/ghidra/triage_88.json")
  summary=read(m,"output/candidate_full/candidate_summary.json")
  cand=read(m,"output/internal_function_candidates.json")
  names={r["elf_function_name"] for r in cand["all_candidates"]}
  require(len(names)==88 and cand["candidate_count"]==88,"CANONICAL_88")
  require(names=={r["candidate_name"] for r in tri["reviewed"]},"GHIDRA_NAMES")
  require(names=={r["elf_name"] for r in summary["all_candidates"]},"MACHINE_NAMES")
  require(summary["archive_sha256"]==ROM_SHA,"OFFICIAL_ROM_HASH")
  bodies={r:read(m,"output/candidate_full/"+r+".candidate_full.json") for r in REVS}
  for rev in REVS:require(set(bodies[rev])==names,"REV_CANDIDATE_NAMES:"+rev)
  evidence=json.loads(pathlib.Path(review_file).read_text())
  require(evidence.get("schema")=="ROM_MANUALLY_REVIEWED_SEMANTIC_EVIDENCE_V1","REVIEW_SCHEMA")
  reviews={}
  for x in evidence.get("records",[]):
   name=x.get("name")
   require(name in names and name not in reviews,"REVIEW_DUPLICATE_OR_INVALID")
   require(x.get("verdict") in ("KNOWN_BEHAVIOR","FALSIFIED_HYPOTHESIS","UNRESOLVED"),"BAD_VERDICT")
   if x["verdict"]!="UNRESOLVED":
    require(bool(x.get("independent_reviewer")) and bool(x.get("counterexample_test")),"REVIEW_NOT_INDEPENDENT")
    require("machine" in x.get("evidence_kinds",[]) and bool({"silicon","independent_implementation"}&set(x["evidence_kinds"])),"INDEPENDENT_EVIDENCE_MISSING")
    require(len(set(x.get("evidence_uris",[])))>=2,"NOT_TWO_INDEPENDENT_SOURCES")
   reviews[name]=x
  q=[];closed=0;rows=[]
  for x in tri["reviewed"]:
   name=x["candidate_name"];changed=False;verified=0;indirect=False;conditional=False
   for rev in REVS:
    a=bodies[rev][name];b=x["ghidra_and_machine_witnesses"][rev]
    if a["status"]=="ABSENT_SYMBOL":
     require(b["status"]=="NOT_IN_THIS_ELF","GHOST_FUNCTION:"+name);continue
    require(a["status"].startswith("FULL_BODY_VERIFIED"),"FUNCTION_BODY_NOT_VERIFIED:"+name)
    require(b["status"]=="FUNCTION_CODE_AND_PSEUDOCODE_PRESENT","DECOMPILATION_MISSING:"+name)
    require(a["sha256"]==b["elf_machine_code_sha256"] and int(a["start"],16)==int(b["entry"],16),"FUNCTION_IDENTITY_MISMATCH:"+name)
    verified+=1;changed|=not b["ELF_vs_Ghidra_function_bytes_equal"]
    indirect|=bool(a.get("indirect_transfer_count",0))
    conditional|=bool(a.get("conditional_branch_count",0))
   require(verified>0,"NOT_IN_ANY_REV:"+name)
   reviewed=name in reviews and reviews[name]["verdict"]!="UNRESOLVED"
   closed+=int(reviewed)
   effect=bool(x.get("function_algorithm_witness"))
   known=x["idf_linker_status"]=="KNOWN_IDF_LINKER_NAME"
   priority=100*int(effect)+30*int(not known)+20*int(not conditional)+10*int(not changed)+10*int(not indirect)
   item={"task_id":"SEM_"+hashlib.sha256(name.encode()).hexdigest()[:12],"original_issue_id":"ESP32C3-ROM-001",
    "ac_ids":["AC04","AC05"],"name":name,"status":"REVIEWED" if reviewed else "NEEDS_INDEPENDENT_SEMANTIC_PROOF",
    "idf_name_known":known,"revision_function_bodies":verified,"ghidra_size_disagreement":changed,
    "indirect_transfer":indirect,"conditional_branch":conditional,"exact_opcode_witness":effect,
    "priority":priority,"novelty_proven":False,"blocker":None if reviewed else "SILICON_OR_INDEPENDENT_BEHAVIOR_AND_PRIOR_ART"}
   rows.append(item)
   if not reviewed:q.append(item)
  q.sort(key=lambda t:(-t["priority"],t["name"]))
  allow=closed==88 and bool(APPROVED_REVIEW_SHA256) and sha(review_file)==APPROVED_REVIEW_SHA256
  state={"schema":"ROM_RESEARCH_AUTOPILOT_V1","original_issue_id":"ESP32C3-ROM-001",
   "status":"READY_FOR_DISCOVERY" if allow else ("AWAITING_SIGNOFF" if closed==88 else "WAITING_FOR_INDEPENDENT_PROOF"),
   "candidate_count":88,"known_name_reviewed":88,"semantic_review_closed":closed,
   "semantic_review_pending":88-closed,"novel_api_proven":0,
   "release_discovery":allow,"reason":"Independent reviewed proof plus pinned signoff required",
   "source_sha256":{"ghidra":GHIDRA_SHA,"machine":MACHINE_SHA,"rom":ROM_SHA},
   "tasks":rows,"execution_queue":[{"task_id":t["task_id"],"name":t["name"],"priority":t["priority"]} for t in q[:batch]],
   "next_action":"Review candidate-specific function effects and prior code; do not retest unchanged data" if q else "Obtain approved evidence digest or scan additional ROM",
   "limitations":["An exact ROM symbol name is not a public API","Ghidra pseudocode does not prove real silicon behavior","No automated novel claim is issued","No new candidate search until all 88 separately adjudicated and approved"]}
  return state
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--ghidra",type=pathlib.Path,required=True);p.add_argument("--machine",type=pathlib.Path,required=True)
 p.add_argument("--review",type=pathlib.Path,required=True);p.add_argument("--out",type=pathlib.Path,required=True)
 a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
 state=evaluate(a.ghidra,a.machine,a.review)
 (a.out/"state.json").write_text(json.dumps(state,indent=2)+"\n")
 (a.out/"queue.json").write_text(json.dumps(state["execution_queue"],indent=2)+"\n")
 (a.out/"gate.env").write_text("discover="+str(state["release_discovery"]).lower()+"\n")
 for item in state["execution_queue"]:
  (a.out/(item["task_id"]+".json")).write_text(json.dumps({**item,"experiment_contract":{
    "prediction":"Derive exact register/branch effect from vendor ROM machine instructions",
    "controls":"Independent implementation or authorized silicon observation and counterexample",
    "novelty":"Compare the complete mechanism with dated code and publications",
    "result":"No functionality or novelty success may be claimed from emulation alone"}},indent=2)+"\n")
 print("ROM_AUTOPILOT_RESULT",json.dumps({k:state[k] for k in ("candidate_count","semantic_review_closed","semantic_review_pending","release_discovery","status")},sort_keys=True))
if __name__=="__main__":main()
