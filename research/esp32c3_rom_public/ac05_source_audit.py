import csv,json,pathlib
P=pathlib.Path(__file__).resolve().parent
O=P/"output"
revs=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
c=json.loads((O/"internal_function_candidates.json").read_text())
source={}
counts={}
revision_hits={}
for rev in revs:
 with (O/"targets"/(rev+".csv")).open() as f:
  names={n for row in csv.DictReader(f) for n in row["elf_function_names"].split(";") if n}
 for kind in ("mmio","csr"):
  rows=json.loads((O/"register_access"/(rev+"."+kind+".json")).read_text())
  for h in rows:
   pc=h.get("access_pc",h.get("address"))
   reg=h["address"] if kind=="mmio" else h["csr"]
   b=h.get("source_bytes",h.get("raw_bytes",""))
   for name in h.get("function_hints",[]):
    if name and name not in names:
     source.setdefault(name,set()).add((rev,kind,str(pc),str(reg).lower(),str(b)))
     counts[name]=counts.get(name,0)+1
     revision_hits.setdefault(name,set()).add(rev)
errors=[];checked=0
for candidate in c["all_candidates"]:
 name=candidate["elf_function_name"]
 if name not in source:errors.append({"name":name,"error":"NO_SOURCE_HITS"})
 if counts.get(name,0)!=candidate["static_evidence"]:errors.append({"name":name,"error":"EVIDENCE_COUNT_MISMATCH","observed":counts.get(name,0),"reported":candidate["static_evidence"]})
 if len(revision_hits.get(name,set()))!=candidate["revision_count"]:errors.append({"name":name,"error":"REVISION_COUNT_MISMATCH"})
 for h in candidate["first_evidence"]:
  tup=(h["revision"],h["kind"],str(h["instruction"]),str(h["register"]).lower(),str(h["bytes"]))
  if tup not in source.get(name,set()):errors.append({"name":name,"error":"HIT_MISMATCH","hit":h})
  else:checked+=1
out={"schema":"ROM_AC05_SOURCE_AUDIT_V1","candidates":len(c["all_candidates"]),"sample_hits_checked":checked,"all_source_hit_count":sum(counts.values()),"full_candidate_tally_checked":len(c["all_candidates"]),"errors":errors,"status":"PASS_SOURCE_TRACE_ONLY" if not errors else "FAIL","semantic_certification":"NOT_GRANTED"}
target=O/"quality"/"ac05_source_audit.json";target.parent.mkdir(exist_ok=True)
target.write_text(json.dumps(out,indent=2)+"\n")
print("AC05_SOURCE_AUDIT",json.dumps(out))
if errors:raise SystemExit(1)
