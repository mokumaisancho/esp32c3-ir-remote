#!/usr/bin/env python3
"""AC05: external-source overlap and fail-closed negative controls.
Address-level corroboration is not function-level semantic validation.
"""
import csv,copy,json,pathlib
from published_prior_art import PUBLISHED
R=pathlib.Path(__file__).resolve().parent;O=R/"output"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
def review(candidates,known_per_rev,mmio_per_rev,prior):
    failures=[];report=[]
    for c in candidates:
        name=c["elf_function_name"];revisions=set(c["revisions"]);mmio=set(c["mmio_addresses"])
        prior_matched=sorted(mmio & set(prior))
        if c["revision_count"]!=len(revisions) or not revisions<=set(REVS):
            failures.append({"name":name,"why":"BAD_REVISION_SET"})
        if c["unique_mmio_addresses"]!=len(mmio) or c["csr_count"]!=len(c["csr_numbers"]):
            failures.append({"name":name,"why":"BAD_REGISTER_COUNTS"})
        if sorted(c["matched_published_prior_addresses"])!=prior_matched:
            failures.append({"name":name,"why":"PRIOR_ART_INTERSECTION_MISMATCH"})
        for rev in revisions:
            if name in known_per_rev[rev]:
                failures.append({"name":name,"why":"PUBLIC_API_FUNCTION_NOT_EXCLUDED","rev":rev})
            observed={h["address"].lower() for h in mmio_per_rev[rev] if name in h.get("function_hints",[])}
            if not observed<=mmio:
                failures.append({"name":name,"why":"RAW_MMIO_NOT_IN_CANDIDATE","rev":rev})
        report.append({"name":name,"published_prior_overlap":prior_matched,
                       "published_overlap_count":len(prior_matched),
                       "no_overlap_interpretation":"NOT_A_NOVELTY_PROOF",
                       "semantics":"NOT_CERTIFIED"})
    return failures,report
def negative_tests(base,known,mmio):
    def m1(a):a[0]["unique_mmio_addresses"]=-1
    def m2(a):a[0]["matched_published_prior_addresses"]=["0x00000000"]
    def m3(a):a[0]["revision_count"]=-1
    negatives=(m1,m2,m3)
    for i,mutate in enumerate(negatives):
        altered=copy.deepcopy(base);mutate(altered)
        errors,_=review(altered,known,mmio,PUBLISHED)
        if not errors:raise RuntimeError("NEGATIVE_CONTROL_MISSED:"+str(i))
    return len(negatives)
def main():
    obj=json.loads((O/"internal_function_candidates.json").read_text())
    names=set();known={};mmio={}
    for rev in REVS:
        with (O/"targets"/(rev+".csv")).open() as f:
            known[rev]={n for row in csv.DictReader(f) for n in row["elf_function_names"].split(";") if n}
        mmio[rev]=json.loads((O/"register_access"/(rev+".mmio.json")).read_text())
    candidates=obj["all_candidates"]
    if len(candidates)!=obj["candidate_count"] or len({x["elf_function_name"] for x in candidates})!=len(candidates):
        raise RuntimeError("INVENTORY_IDENTITY_MISMATCH")
    failures,rows=review(candidates,known,mmio,PUBLISHED)
    negative=negative_tests(candidates,known,mmio)
    matching=[x for x in rows if x["published_overlap_count"]>0]
    result={"schema":"ROM_AC05_PRIOR_ART_COUNTERCHECK_V1",
        "candidates":len(rows),"prior_source_year":2025,
        "candidate_names_with_prior_address_overlap":len(matching),
        "candidate_names_without_prior_address_overlap":len(rows)-len(matching),
        "negative_controls_caught":negative,
        "failure_count":len(failures),"failures":failures,
        "rows":rows,
        "verdict":"PASS_ADDRESS_LEVEL_REVIEW_ONLY" if not failures else "FAIL",
        "limitations":["Address overlap is not functional equivalence","No overlap does not prove undocumented behavior","Prior source is independent in publication time, but mapping still rests on static register extraction"]}
    folder=O/"quality";folder.mkdir(exist_ok=True)
    (folder/"ac05_prior_art_countercheck.json").write_text(json.dumps(result,indent=2)+"\n")
    print("AC05_PRIOR_ART_COUNTERCHECK",json.dumps({k:v for k,v in result.items() if k!="rows"},sort_keys=True))
    if failures:raise SystemExit("AC05_PRIOR_ART_COUNTERCHECK_FAIL")
if __name__=="__main__":main()
