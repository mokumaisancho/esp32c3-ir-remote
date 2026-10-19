#!/usr/bin/env python3
"""Build full opcode/Ghidra evidence packets for next review batch without LLM invention."""
import argparse,json,pathlib,zipfile
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
def require(x,why):
 if not x:raise RuntimeError("FAIL_CLOSED_PACKET:"+why)
def load(zipf,path):return json.loads(zipf.read(path))
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--ghidra",type=pathlib.Path,required=True);p.add_argument("--machine",type=pathlib.Path,required=True)
 p.add_argument("--state",type=pathlib.Path,required=True);p.add_argument("--out",type=pathlib.Path,required=True)
 a=p.parse_args();state=json.loads(a.state.read_text())
 require(state.get("schema")=="ROM_RESEARCH_AUTOPILOT_V1" and state.get("candidate_count")==88,"WRONG_STATE")
 with zipfile.ZipFile(a.ghidra) as gh,zipfile.ZipFile(a.machine) as mc:
  gh_by={rev:{x["name"]:x for x in load(gh,"output/ghidra/"+rev+".decompiled.json")} for rev in REVS}
  machine_by={rev:load(mc,"output/candidate_full/"+rev+".candidate_full.json") for rev in REVS}
  queue=state["execution_queue"];task_by={t["name"]:t for t in state["tasks"]}
  a.out.mkdir(parents=True,exist_ok=True)
  summaries=[]
  for task in queue:
   name=task["name"];ident=task["task_id"]
   require(name in task_by and ident==task_by[name]["task_id"],"QUEUE_TAMPERING")
   details={}
   for rev in REVS:
    m=machine_by[rev][name]
    if m["status"]=="ABSENT_SYMBOL":continue
    g=gh_by[rev][name]
    require(m["status"].startswith("FULL_BODY_VERIFIED") and g["decompiler_status"]=="DECOMPILED","UNVERIFIED_GHIDRA_MACHINE")
    require(int(m["start"],16)==int(g["requested_address"],16),"ENTRY_MISMATCH")
    details[rev]={"entry":m["start"],"machine_sha256":m["sha256"],
      "instructions":m["instruction_listing"],"decompiled_c":g["pseudocode"],
      "ghidra_function_size_bytes":g["ghidra_function_body_address_count"],
      "elf_function_size_bytes":m["bytes"],"indirect_transfers":m["indirect_transfers"],
      "direct_transfers":m["direct_transfers"],"mmio_hits":m.get("mmio_hits",[]),"csr_hits":m.get("csr_hits",[])}
   packet={"schema":"ROM_88_FULL_MACHINE_AND_GHIDRA_EVIDENCE_PACKET_V1",
      "name":name,"task_id":ident,"priority":task["priority"],"revisions":details,
      "method":"Direct ELF machine instructions plus independently decompiled Ghidra C",
      "required_proof":["Specify exact input/side effect and branches","Independent implementation or authorized silicon witness",
        "Counterexample and dated prior-art equivalence check"],"novelty_proven":False,"hardware_test_executed":False}
   (a.out/(ident+".json")).write_text(json.dumps(packet,indent=2)+"\n")
   summaries.append({"name":name,"task_id":ident,"revision_bodies":len(details),
     "instruction_total":sum(len(x["instructions"]) for x in details.values())})
  (a.out/"packet_manifest.json").write_text(json.dumps({"schema":"ROM_BATCH_PACKET_MANIFEST_V1","count":len(summaries),"items":summaries},indent=2)+"\n")
  print("ROM_EVIDENCE_PACKET_RESULT",json.dumps({"queue_count":len(summaries),"all_instructions_preserved":True,"all_Ghidra_C_preserved":True,"names":[x["name"] for x in summaries]}))
if __name__=="__main__":main()
