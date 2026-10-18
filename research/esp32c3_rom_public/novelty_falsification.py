#!/usr/bin/env python3
"""Novelty falsification and testable-behavior pipeline. No novelty from missing overlap."""
import csv,json,pathlib,collections
ROOT=pathlib.Path(__file__).resolve().parent;O=ROOT/"output"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
PUBLIC_PRIOR=("r_emi_alloc_em_mapping_by_offset","r_emi_free_em_mapping_by_offset","GetSecurityInfoProc")
def classify(candidate,public_api,known_prior):
 name=candidate["elf_function_name"]
 reasons=[]
 if name in public_api:reasons.append("EXPORTED_ROM_FUNCTION")
 if name in known_prior:reasons.append("PRIOR_PUBLIC_IMPLEMENTATION_OR_FUNCTION")
 if candidate["matched_published_prior_addresses"]:reasons.append("KNOWN_REGISTER_ADDRESS_OVERLAP")
 return {"name":name,"classification":"KNOWN_EXPOSURE" if reasons[:2] and any(x in reasons for x in ("EXPORTED_ROM_FUNCTION","PRIOR_PUBLIC_IMPLEMENTATION_OR_FUNCTION")) else "UNPROVEN_NOVELTY",
         "reasons":reasons,"novel_function_proven":False,"executable_behavior_proven":False,
         "next_evidence":["independent code path and exact effect","hardware observation or interpreter calibrated to ROM bytes","exhaustive prior implementation search and dated comparison"]}
def test():
 dummy={"elf_function_name":"foo","matched_published_prior_addresses":[]}
 assert classify(dummy,set(),set())["novel_function_proven"] is False
 assert classify({**dummy,"matched_published_prior_addresses":["0x60033000"]},set(),set())["novel_function_proven"] is False
 assert classify({**dummy,"elf_function_name":"r_emi_alloc_em_mapping_by_offset"},set(),set(PUBLIC_PRIOR))["classification"]=="KNOWN_EXPOSURE"
 return 3
def main():
 count=test()
 c=json.loads((O/"internal_function_candidates.json").read_text())
 public=set()
 for rev in REVS:
  with (O/"targets"/(rev+".csv")).open() as f:
   for r in csv.DictReader(f):public.update(x for x in r["elf_function_names"].split(";") if x)
 rows=[classify(x,public,set(PUBLIC_PRIOR)) for x in c["all_candidates"]]
 report={"schema":"ESP32C3_NOVELTY_FALSIFICATION_V1","candidate_count":len(rows),
   "negative_controls":count,"known_prior_examples":list(PUBLIC_PRIOR),
   "proven_novel_count":sum(x["novel_function_proven"] for x in rows),
   "structural_not_semantic":True,"items":rows,
   "warning":"PUBLIC_PRIOR is an initial disproof set, NOT an exhaustive literature database. No novelty claim without device-backed causal effect and broad prior-art comparison."}
 p=O/"quality"/"novelty_falsification.json";p.parent.mkdir(exist_ok=True);p.write_text(json.dumps(report,indent=2)+"\n")
 print("NOVELTY_FALSIFICATION_RESULT "+json.dumps({k:v for k,v in report.items() if k!="items"},sort_keys=True))
if __name__=="__main__":main()
