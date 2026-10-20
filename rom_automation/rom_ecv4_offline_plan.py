#!/usr/bin/env python3
"""ROM function SCC -> candidate review plan, never an ECv4 runtime receipt."""
import argparse,json,pathlib,collections
from decision_gate import require,ROM_SHA
REV="esp32c3_rev101_rom.elf"
def convert(report):
 require(report.get("schema")=="ESP32C3_ALL_ROM_FAST_GRAPH_V1","GRAPH_SCHEMA")
 require(report.get("rom_source_sha256")==ROM_SHA,"GRAPH_PIN")
 graph=report["graph_and_ECV4_dependency_proposals"][REV]
 tasks={t["work_id"]:t for t in graph["work_tasks"]}
 selected={t["work_id"] for t in tasks.values()
           if set(t["members"])&set(graph["candidate_node_ids"])}
 require(len(selected)==152,"CANDIDATE_DRIFT")
 remaining=set(selected);todo=list(selected)
 while todo:
  for dep in tasks[todo.pop()]["depends_on"]:
   require(dep in tasks,"UNKNOWN_DEPENDENCY")
   if dep not in remaining:remaining.add(dep);todo.append(dep)
 require(len(remaining)<=512,"PLAN_TOO_LARGE")
 deps={k:sorted(set(tasks[k]["depends_on"])&remaining) for k in remaining}
 done=set();active=set();order=[]
 def visit(n):
  require(n not in active,"GRAPH_CYCLE")
  if n in done:return
  active.add(n)
  for d in deps[n]:visit(d)
  active.remove(n);done.add(n);order.append(n)
 for k in sorted(remaining):visit(k)
 issues=[]
 for issue in order:
  phases=["PRIOR_ART","REPAIR","REGRESSION","EVIDENCE"]
  works=[]
  for i,p in enumerate(phases):
   depends=([issue+":"+phases[i-1]] if i else
      [d+":EVIDENCE" for d in deps[issue]])
   works.append({"work_id":issue+":"+p,"kind":p,"depends_on":depends})
  issues.append({"issue_id":issue,"priority":"P0" if issue in selected else "P1",
   "blocker":False,"work":works,
   "function_aliases":tasks[issue]["symbol_aliases"],
   "original_issue_id":"ESP32C3-ROM-001",
   "independent_semantics_verified":False})
 return {"schema":"ROM_ECV4_OFFLINE_FUNCTION_PLAN_V1",
  "protocol":"EC_REMEDIATION_PLAN_V1",
  "authority":"EC_REMEDIATION_PLANNER_PROPOSAL",
  "primary_goal":"ESP32C3-ROM-001 inspect unseen function mechanisms, preserve evidence",
  "issues":issues,
  "dependency_graph":{k:deps[k] for k in sorted(deps)},
  "candidate_issues":len(selected),"dependency_closure_issues":len(remaining),
  "scc_cycles_after_compression":0,
  "ECV4SuiteBridge_executed":False,
  "verified_dynamic_state_context":False,
  "status":"OFFLINE_REVIEW_PLAN_REQUIRES_PRIVATE_RUNTIME_AUDIT"}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--graph",type=pathlib.Path,required=True)
 p.add_argument("--out",type=pathlib.Path,required=True)
 a=p.parse_args();r=convert(json.loads(a.graph.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,sort_keys=True,separators=(",",":"))+"\n")
 print("ROM_ECV4_OFFLINE_GRAPH",json.dumps({
  "candidates":r["candidate_issues"],"closure":r["dependency_closure_issues"],
  "ECV4_executed":False},sort_keys=True))
if __name__=="__main__":main()
