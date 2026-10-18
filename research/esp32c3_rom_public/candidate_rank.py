#!/usr/bin/env python3
"""Deterministic priority queue of ELF internal functions with observed ROM register accesses.

Ranks RESEARCH TARGETS, never asserts undocumented API or MMIO semantics.
Public ROM entry jump targets are excluded using actual target_validate evidence.
"""
import collections
import csv
import json
import pathlib

from published_prior_art import PUBLISHED

ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")

def rank_candidates(hits_by_revision, public_names_by_revision, prior_addresses):
    aggregate={}
    excluded=collections.Counter()
    unattributed=collections.Counter()
    for rev, evidence in hits_by_revision.items():
        known=set(public_names_by_revision[rev])
        for kind,hit in evidence:
            names=[x for x in hit.get("function_hints",[]) if x and not x.startswith("OTHER_OVERLAP_OMITTED")]
            if not names:
                unattributed[rev]+=1
                continue
            for name in set(names):
                if name in known:
                    excluded[rev]+=1
                    continue
                ent=aggregate.setdefault(name,{"revisions":set(),"mmio_addresses":set(),"csr_numbers":set(),
                    "static_evidence":0,"first_evidence":[],"published_prior_addresses":set()})
                ent["revisions"].add(rev)
                ent["static_evidence"]+=1
                if kind=="mmio":
                    a=hit["address"].lower()
                    ent["mmio_addresses"].add(a)
                    if a in prior_addresses:
                        ent["published_prior_addresses"].add(a)
                else:
                    ent["csr_numbers"].add(hit["csr"].lower())
                if len(ent["first_evidence"])<6:
                    ent["first_evidence"].append({"revision":rev,"kind":kind,
                        "instruction":hit.get("access_pc",hit.get("address")),
                        "register":hit.get("address") if kind=="mmio" else hit.get("csr"),
                        "bytes":hit.get("source_bytes",hit.get("raw_bytes",""))})
    rows=[]
    for name,x in aggregate.items():
        rows.append({"elf_function_name":name,"revision_count":len(x["revisions"]),
            "revisions":sorted(x["revisions"]),"unique_mmio_addresses":len(x["mmio_addresses"]),
            "csr_count":len(x["csr_numbers"]),"mmio_addresses":sorted(x["mmio_addresses"]),
            "csr_numbers":sorted(x["csr_numbers"]),"static_evidence":x["static_evidence"],
            "matched_published_prior_addresses":sorted(x["published_prior_addresses"]),
            "first_evidence":x["first_evidence"],
            "classification":"NOT_EXPOSED_BY_FIXED_ROM_API_TABLE__NOT_A_HIDDEN_API_CLAIM"})
    rows.sort(key=lambda r:(-r["revision_count"],
                            -len(r["mmio_addresses"])-len(r["csr_numbers"]),
                            -r["static_evidence"],r["elf_function_name"]))
    return {"candidates":rows,"public_impl_excluded_hits":dict(excluded),
            "unattributed_hits":dict(unattributed)}

def main():
    hits={};public={}
    for rev in REVS:
        p=OUT/"targets"/(rev+".csv")
        if not p.is_file():raise RuntimeError("MISSING_VERIFIED_PUBLIC_ROM_TARGETS:"+rev)
        with p.open(newline="") as f:
            table=list(csv.DictReader(f))
        if len(table)!=648:raise RuntimeError("INCOMPLETE_PUBLIC_API_TARGETS:"+rev)
        known=set()
        for row in table:
            if not row.get("target_executable")=="True":
                raise RuntimeError("UNVERIFIED_PUBLIC_API_TARGET:"+rev)
            known.update(row["elf_function_names"].split(";"))
        public[rev]={x for x in known if x}
        mmio=json.loads((OUT/"register_access"/(rev+".mmio.json")).read_text())
        csr=json.loads((OUT/"register_access"/(rev+".csr.json")).read_text())
        hits[rev]=[("mmio",x) for x in mmio]+[("csr",x) for x in csr]
    ranked=rank_candidates(hits,public,set(PUBLISHED))
    output={"schema":"ROM_INTERNAL_FUNCTION_RESEARCH_PRIORITY_V1",
        "method":"Evidence grouped by ELF function metadata, public fixed ROM targets excluded",
        "source_revisions":list(REVS),"candidate_count":len(ranked["candidates"]),
        "all_candidates":ranked["candidates"],
        "top_candidates":ranked["candidates"][:50],
        "exclusions":{k:ranked[k] for k in ("public_impl_excluded_hits","unattributed_hits")},
        "limitations":["Absence from fixed ROM API table does not imply undocumented API",
            "Only register-access-hit functions ranked; other internal functions unexamined",
            "Function attribution based on ELF STT_FUNC address ranges, not complete CFG",
            "Same function name across revisions does not ensure identical behavior"],
        "status":"RESEARCH_PRIORITIZATION_ONLY"}
    (OUT/"internal_function_candidates.json").write_text(json.dumps(output,indent=2)+"\n")
    print("INTERNAL_FUNCTION_CANDIDATES_RESULT "+json.dumps({
        **{k:v for k,v in output.items() if k not in ("top_candidates","all_candidates")},
        "top_candidates":output["top_candidates"][:15]
    },separators=(",",":")))
    return output
if __name__=="__main__":
    main()
