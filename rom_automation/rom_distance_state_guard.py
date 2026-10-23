#!/usr/bin/env python3
"""ROM-003 result-state consistency guard: rejects summaries with wrong columns.

CI generates metrics from immutable graph artifacts, then validates this
human-readable tracked JSON snapshot without trusting hand-written totals.
"""
import argparse
import json
import pathlib

REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")

def require(v,message):
 if not v:raise ValueError(message)

def verify(metrics,state):
 require(metrics.get("schema")=="ROM003_DISTANCE_DISCOVERY_PROXY_POC_V1","METRIC_SCHEMA")
 require(state.get("schema")=="ROM003_DISTANCE_BLIND_POC_EVIDENCE_V1","STATE_SCHEMA")
 require(metrics["pinned_graph_zip_sha256"]==state["source_artifact_sha256"],"SOURCE_SHA_MISMATCH")
 require(metrics["rom_archive_sha256"]==state["original_esp_rom_archive_sha256"],"ROM_SHA_MISMATCH")
 rows=metrics["revisions"]
 require(len(rows)==3 and {r["revision"] for r in rows}==set(REVS),"REVISION_SCOPE_CHANGED")
 vv=state["validation"]
 methods=metrics["methods_frozen_before_scoring"]
 require(methods==vv["methods"],"RANKER_SET_CHANGED")
 got={r["revision"]:r for r in vv["fivefold_per_revision"]}
 require(set(got)==set(REVS),"STATE_REVISION_SCOPE")
 sums={m:0 for m in methods};denominator=0
 for row in rows:
  revision=row["revision"];frozen_and_folds=row["frozen_fold_plus_five_sensitivity_folds"]
  require(len(frozen_and_folds)==6 and
   [x["split"] for x in frozen_and_folds]==["frozen"]+[f"fold_{i}" for i in range(5)],
   "FOLD_SET_CHANGED:"+revision)
  frozen=frozen_and_folds[0]
  require(frozen["masked_positive_count"]==vv["frozen_holdout_positives_per_revision"],
    "FROZEN_HOLDOUT_COUNT_CHANGED:"+revision)
  for method in methods:
   expected=frozen["scores"][method]["masked_known_roots"]["hits_at_100"]
   observed=vv["frozen_hits_at_100_by_revision"][revision][method]
   require(expected==observed,"FROZEN_HIT_MISMATCH:"+revision+":"+method)
  state_row=got[revision]
  for key,expected in (
   ("nodes",row["node_count"]),
   ("interfunction_direct_edges",row["direct_edges"]),
   ("isolated_nodes",row["graph_isolated_named_functions"]),
   ("root_reachable_candidates_frozen",frozen["structural_coverage"]["directed_from_roots"]),
   ("weakly_disconnected_candidates_frozen",frozen["structural_coverage"]["disconnected_weak"]),
   ("historical_public_names_proxy_count",row["historical_published_name_proxy_size"]),
  ):
   require(state_row[key]==expected,"STATE_METADATA_MISMATCH:"+revision+":"+key)
  total=sum(x["masked_positive_count"] for x in frozen_and_folds[1:])
  require(state_row["fivefold_masked_positives"]==total,"DENOMINATOR_MISMATCH:"+revision)
  denominator+=total
  for method in methods:
   count=sum(x["scores"][method]["masked_known_roots"]["hits_at_100"]
     for x in frozen_and_folds[1:])
   require(state_row["hits_at_100"][method]==count,
    "FIVEFOLD_METHOD_HITS_MISMATCH:"+revision+":"+method)
   sums[method]+=count
 require(denominator==vv["fivefold_total_labeled_positives"],"TOTAL_POSITIVE_DENOMINATOR_MISMATCH")
 require(sums==vv["fivefold_total_hits_at_100"],"TOTAL_METHOD_COUNTS_MISMATCH")
 require(vv["tests"]==13 and vv["passed"]==13 and vv["failed"]==0,
         "TEST_COUNT_REQUIRES_EVIDENCE_REVIEW")
 require(metrics["new_usable_rom_capabilities_verified"]==0 and
         state["new_callable_unknown_ROM_function_count"]==0,"NO_NOVELTY_CLAIM")
 return {"status":"PASS","revisions":3,"folds_each":5,
  "total_proxy_labels":denominator,"aggregate_hits_at_100":sums}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--metrics",required=True,type=pathlib.Path)
 p.add_argument("--state",required=True,type=pathlib.Path)
 args=p.parse_args()
 result=verify(json.loads(args.metrics.read_text()),json.loads(args.state.read_text()))
 print("ROM003_SUMMARY_INTEGRITY",json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
