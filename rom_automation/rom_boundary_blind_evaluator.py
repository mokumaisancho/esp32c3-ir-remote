#!/usr/bin/env python3
"""ROM-003 E2: evaluator-only function start scoring; NEVER import into scanner.

Positive set is ELF STT_FUNC start positions (deduplicated aliases) and is an
imperfect proxy, not a proof of novel usable ROM function or actual execution.
Unknown unjudged candidate positions are NOT verified negative examples.
"""
import argparse,hashlib,json,pathlib

SCHEMA="ROM003_E2_TRUE_BOUNDARY_HIDDEN_EVALUATION_V1"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
KS=(10,25,50,100,500,1000)
def ensure(condition,error):
 if not condition:raise ValueError(error)

def addresses(items):
 ensure(type(items) is list,"CANDIDATE_RANK_NOT_ARRAY")
 out=[];seen=set()
 for pc in items:
  ensure(type(pc) is str and pc.startswith("0x"),"CANDIDATE_PC_FORMAT")
  n=int(pc,16)
  ensure(n%2==0 and n<2**32,"CANDIDATE_PC_NOT_RV32_ALIGN")
  if n not in seen:out.append(n);seen.add(n)
 return out

def score(predicted,positive):
 ranks=addresses(predicted)
 actual=set(positive)
 ensure(actual,"MISSING_GOLDEN_TRUE_ENTRY")
 out={"ranked_candidates":len(ranks),
   "correct_labeled_entries_any_rank":len(set(ranks)&actual),
   "unjudged_other_candidate_addresses":len(set(ranks)-actual),
   "false_positive_rate_verified":None,
   "false_positive_rate_status":"NO_VERIFIED_NEGATIVE_ROM_CODE_SET"}
 for k in KS:
  hits=sum(p in actual for p in ranks[:k])
  out["hit_at_"+str(k)]=hits
  out["recall_at_"+str(k)]=round(hits/len(actual),6)
  out["positive_yield_at_"+str(k)]=round(hits/max(1,min(k,len(ranks))),6)
 return out

def evaluate(public_results,gold,source_proofs=None):
 ensure(set(public_results)==set(REVS) and set(gold)==set(REVS),"REVISION_SET_DRIFT")
 revisions=[];unique_positive=0
 for rev in REVS:
  candidate=public_results[rev];oracle=gold[rev]
  ensure(candidate.get("schema")=="ROM003_E1_BYTE_ONLY_CANDIDATES_V1" and
         oracle.get("schema")=="ROM003_SEALED_SYMBOL_ORACLE_V1" and
         candidate.get("revision")==rev and oracle.get("revision")==rev,
         "REVISION_OR_SCHEMA_MISMATCH")
  ensure(not candidate.get("true_function_boundary_verified",True)
         and not candidate.get("novel_usable_API_verified",True),
         "FALSE_DISCOVERY_CERTIFICATION")
  records=oracle["symbol_function_records"]
  pairs={(int(x["entry_pc"],16),x["size_bytes"]) for x in records}
  starts={p for p,n in pairs}
  ensure(len(pairs)>1000,"INSUFFICIENT_GOLDEN_BOUNDARIES")
  ensure(len(records)>len(pairs),"EXPECTED_ELF_SYM_ALIAS_DUPLICATES")
  unique_positive+=len(starts)
  methods={
   "rooted_calls":candidate["rooted_entry_candidates"],
   "byte_link_scan":candidate["ranked_raw_link_baseline"],
   "rooted_plus_byte_witness_rank":candidate["ranked_possible_entries"],
   "byte_link_address_order":sorted(candidate["ranked_raw_link_baseline"],key=lambda x:int(x,16))
  }
  ensure(set(methods["rooted_calls"])<=set(methods["rooted_plus_byte_witness_rank"]),
         "ROOTED_CANDIDATE_LOST_WITHOUT_REASON")
  ensure("symbol_function_records" not in json.dumps(candidate),
         "GOLDEN_SYMBOL_RECORD_LEAK_IN_CANDIDATE")
  results={method:score(ranks,starts) for method,ranks in methods.items()}
  revisions.append({"revision":rev,"symbol_record_count":len(records),
   "unique_start_size_pairs":len(pairs),"unique_true_start_pcs":len(starts),
   "duplicate_alias_records":len(records)-len(pairs),
   "rooted_code_instructions":candidate["instructions_rooted"],
   "rooted_calls_reported":candidate["rooted_call_count"],
   "raw_candidate_count":candidate["unrooted_halfword_candidate_count"],
   "scores":results})
 return {"schema":SCHEMA,"original_issue":"ESP32C3-ROM-001",
   "evaluation_type":"ELF_FUNCTION_STARTS_HIDDEN_FROM_BYTE_ONLY_CANDIDATE_JOB",
   "independent_process_oracle_cannot_be_loaded_in_candidate_job":True,
   "function_boundaries_supplied_to_candidate_ranker":False,
   "positive_entry_count_across_revisions":unique_positive,
   "revisions":revisions,
   "new_verified_unknown_function_count":0,
   "actual_new_usable_ROM_APIs":0,
   "hardware_runs":0,
   "all_unknown_candidate_addresses_are_negative":False,
   "test_limitations":[
    "ELF STT_FUNC start is a proxy and ambiguous extents exist; false positives on unjudged ROM code cannot be certified.",
    "Raw scan may decode data as instructions; it never provides physical execution proof.",
    "All revisions share code ancestry; their findings are not independent random samples.",
    "The current root set consists of ELF e_entry only; trap/vector/indirect targets are not proven complete.",
    "A candidate matching a known ELF function start is a recovery of a public start, not a genuinely novel API."]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--candidate-dir",type=pathlib.Path,required=True)
 p.add_argument("--evaluator-dir",type=pathlib.Path,required=True)
 p.add_argument("--output",type=pathlib.Path,required=True)
 a=p.parse_args()
 data={r:json.loads((a.candidate_dir/(r+".json")).read_text()) for r in REVS}
 gold={r:json.loads((a.evaluator_dir/(r+".json")).read_text()) for r in REVS}
 results=evaluate(data,gold)
 a.output.parent.mkdir(parents=True,exist_ok=True)
 a.output.write_text(json.dumps(results,indent=2,sort_keys=True)+"\n")
 for row in results["revisions"]:
  print("ROM003_E2_TRUE_BOUNDARY_HIDDEN",json.dumps({
   "rev":row["revision"],"oracle_positive_starts":row["unique_true_start_pcs"],
   "rooted":row["scores"]["rooted_calls"]["hit_at_100"],
   "byte_scan":row["scores"]["byte_link_scan"]["hit_at_100"],
   "combined":row["scores"]["rooted_plus_byte_witness_rank"]["hit_at_100"],
   "naive_order":row["scores"]["byte_link_address_order"]["hit_at_100"]
  },sort_keys=True))
if __name__=="__main__":main()
