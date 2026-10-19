#!/usr/bin/env python3
"""Cross-check decompilation rows against exact ELF entry points; preserve all pseudocode."""
import base64,csv,json,pathlib,collections
ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"ghidra"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
report={"schema":"ROM_GHIDRA_88_FUNCTION_DECOMPILATION_V1","revisions":{},
 "cautions":["Decompiler C is a hypothesis, not correct silicon semantics",
 "No proof of undisclosed API, hardware timing or novelty from pseudocode alone",
 "Ghidra function-range decisions can differ from ELF STT_FUNC boundaries"]}
for rev in REVS:
 expected={}
 with (OUT/(rev+".candidates.tsv")).open() as f:
  for line in f:
   name,addr=line.rstrip("\n").split("\t")
   if name in expected:raise RuntimeError("DUPLICATE_INPUT_NAME:"+name)
   expected[name]=addr
 path=OUT/(rev+".decompile.tsv")
 if not path.is_file():raise RuntimeError("GHIDRA_REVISION_OUTPUT_MISSING:"+rev)
 with path.open(newline="") as f:
  records=list(csv.DictReader(f,delimiter="\t"))
 if len(records)!=len(expected):raise RuntimeError("GHIDRA_CANDIDATE_ROW_COUNT_INCOMPLETE:"+rev+":"+str(len(records)))
 rows=[];seen=set();statuses=collections.Counter();out=[]
 for rec in records:
  name=rec["name"]
  if name not in expected or name in seen:raise RuntimeError("GHIDRA_WRONG_OR_DUPLICATE_NAME:"+rev+":"+name)
  seen.add(name)
  if int(rec["address"],16)!=int(expected[name],16):raise RuntimeError("GHIDRA_ADDRESS_DIFFERENCE:"+name)
  text=base64.b64decode(rec["decompilation_base64"]).decode()
  error=base64.b64decode(rec["error_base64"]).decode()
  status=rec["status"];statuses[status]+=1
  rows.append({"name":name,"requested_address":rec["address"],"decompiler_status":status,
   "resolved_entry":rec["function_entry"],"resolved_name":rec["function_name"],
   "ghidra_function_body_address_count":rec["body_address_count"],
   "pseudocode_length":len(text),"pseudocode":text,"error":error})
  out.append("==="+name+" @ "+rec["address"]+" ===\nSTATUS="+status+" NAME="+rec["function_name"]+" ERROR="+error+"\n"+text+"\n")
 (OUT/(rev+".decompiled.json")).write_text(json.dumps(rows,indent=2)+"\n")
 (OUT/(rev+".decompiled.txt")).write_text("\n".join(out))
 report["revisions"][rev]={"candidates":len(rows),"statuses":dict(statuses),
   "total_pseudocode_characters":sum(x["pseudocode_length"] for x in rows),
   "wrong_requested_addresses":0}
(OUT/"ghidra_summary.json").write_text(json.dumps(report,indent=2)+"\n")
print("GHIDRA_88_REVIEW_SUMMARY",json.dumps(report,sort_keys=True))
if sum(r["statuses"].get("DECOMPILED",0) for r in report["revisions"].values())<150:
 raise SystemExit("GHIDRA_INSUFFICIENT_DECOMPILATION_COVERAGE")
