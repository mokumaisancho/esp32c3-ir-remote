#!/usr/bin/env python3
"""Adjudicate original ROM AC03/04/05, never substitute post-hoc CFG requirements.
Cross-check independent coverage, candidate provenance, prior art and QA before PASS.
"""
import json,pathlib
ROOT=pathlib.Path(__file__).resolve().parent;O=ROOT/"output"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
def load(p):return json.loads((O/p).read_text())
def require(v,k):
 if not v:raise RuntimeError("AC_EVIDENCE_INVALID:"+k)
a=load("coverage/ac03.json"); cand=load("internal_function_candidates.json")
qa=load("quality_gate.json"); prior=load("register_access/published_prior_art_comparison.json")
reg=load("register_access/summary.json")
require(a.get("schema")=="ROM_AC03_INDEPENDENT_COVERAGE_V1","COVERAGE_SCHEMA")
require(qa.get("overall")=="INCOMPLETE","NO_SEMANTIC_OVERCLAIM")
revs=a["revision_metrics"]
for rev in REVS:
 r=revs[rev]
 require(r["executable_bytes"]==r["linearly_decoded_bytes"]+r["undecodable_bytes"],"AC03_BYTE_PARTITION")
 require(r["symbol_size_covered_bytes"]+r["not_symbol_size_covered_bytes"]==r["executable_bytes"],"AC03_SYMBOL_PARTITION")
 require(r["undecodable_bytes"]>=0 and r["not_symbol_size_covered_bytes"]>=0,"AC03_NEGATIVE")
 require(r["cfg_reachability"]=="NOT_CERTIFIED","AC03_OVERCLAIM")
require(cand.get("candidate_count")==len(cand.get("all_candidates",[])) and cand["candidate_count"]>0,"AC04_INVENTORY")
for x in cand["all_candidates"]:
 require(x.get("elf_function_name"),"AC04_NAME")
require(all(isinstance(reg["revisions"][rev].get("unique_mmio_addresses"),int) and reg["revisions"][rev]["unique_mmio_addresses"]>0 for rev in REVS),"AC04_REGISTERS")
require(all(prior["revisions"][rev].get("published_prior_count",0)>0 for rev in REVS),"AC05_PRIOR_ART")
verdict={"schema":"ROM_ORIGINAL_AC_ADJUDICATION_V1","issue_id":"ESP32C3-ROM-001",
 "ac_verdict":{"AC01":"PASS_EXISTING","AC02":"PASS_EXISTING",
    "AC03":"PASS_MEASUREMENT_WITH_CFG_LIMITATION","AC04":"PASS_CANDIDATE_EXTRACTION_NOT_FUNCTION_PROOF",
    "AC05":"PARTIAL_FALSE_POSITIVE_REVIEW_NOT_INDEPENDENTLY_CLOSED"},
 "evidence":{"ac03_coverage":{rev:{k:v for k,v in revs[rev].items() if k in ("executable_bytes","undecodable_bytes","not_symbol_size_covered_bytes","undecodable_percentage","symbol_size_gap_percentage")} for rev in REVS},
 "ac04_candidate_count":cand["candidate_count"],
 "ac04_unique_mmio":{rev:reg["revisions"][rev]["unique_mmio_addresses"] for rev in REVS},
 "ac05_prior_published_count":{rev:prior["revisions"][rev]["published_prior_count"] for rev in REVS}},
 "cautions":["Original AC03 requires a measured ratio, not proven CFG","Original AC04 calls for evidence-backed candidates, not proven hidden hardware","AC05 must retain separate independent false-positive review","ECv4 optional control integration is separate from original AC and cannot block AC03/AC04"]}
dest=O/"quality"/"original_ac_adjudication.json";dest.parent.mkdir(parents=True,exist_ok=True)
dest.write_text(json.dumps(verdict,indent=2)+"\n")
print("ORIGINAL_AC_ADJUDICATION",json.dumps(verdict,sort_keys=True))
