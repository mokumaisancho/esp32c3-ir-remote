#!/usr/bin/env python3
"""Validate restored immutable 167-file IDF inventory without refetching pinned sources.

Used after a verified GitHub Actions artifact SHA-256 check. Reject unexpected
candidate identity or IDF provenance changes; this is reuse, not re-analysis.
"""
import csv,json,pathlib
BASE=pathlib.Path(__file__).resolve().parent
ROOT=BASE/"output"
M=ROOT/"idf_known"
def readcsv(name):
 with (M/name).open(newline="") as f:return list(csv.DictReader(f))
def main():
 d=json.loads((M/"summary.json").read_text())
 sources=readcsv("sources.csv")
 linker=readcsv("linker_symbols.csv")
 classifications=readcsv("candidates_reclassified.csv")
 baseline=readcsv("baseline_crosscheck.csv")
 candidates=json.loads((ROOT/"internal_function_candidates.json").read_text())["all_candidates"]
 if len(sources)!=167 or len(linker)!=6825 or len(classifications)!=88 or len(baseline)!=864:
  raise RuntimeError("RESTORED_PINNED_ARTIFACT_COUNTS_INVALID")
 if d["idf_linker_distinct_names"]!=2334 or d["candidate_idf_linker_name_matches"]!=42:
  raise RuntimeError("RESTORED_SOURCE_MANIFEST_MISMATCH")
 if d["baseline_matching_primary_ld_address"]!=864:
  raise RuntimeError("RESTORED_OFFICIAL_LINKER_BASELINE_INCOMPLETE")
 if not all(x["any_matching_primary_address"]=="True" for x in baseline):
  raise RuntimeError("RESTORED_BASELINE_ADDRESS_DISAGREEMENT")
 if set(x["elf_function_name"] for x in candidates)!=set(x["name"] for x in classifications):
  raise RuntimeError("CANDIDATE_IDENTITY_CHANGED_SINCE_PINNED_SNAPSHOT")
 if len({(x["snapshot"],x["path"]) for x in sources})!=167:
  raise RuntimeError("SOURCE_PATHS_NOT_UNIQUE")
 if any(len(x["sha256"])!=64 or len(x["commit"])!=40 for x in sources):
  raise RuntimeError("UNPINNED_SOURCE_PROVENANCE")
 record={"schema":"IDF_VERIFIED_SNAPSHOT_REUSE_V1","source_count":167,
  "distinct_linker_names":2334,"candidate_names":88,"known_in_selected_idf":42,
  "source_bytes_refetched":0,"archival_verification":"GITHUB_ARTIFACT_DIGEST_VERIFIED_BY_WORKFLOW"}
 (M/"reuse_verdict.json").write_text(json.dumps(record,indent=2)+"\n")
 print("IDF_KNOWN_SNAPSHOT_REUSE",json.dumps(record,sort_keys=True))
if __name__=="__main__":main()
