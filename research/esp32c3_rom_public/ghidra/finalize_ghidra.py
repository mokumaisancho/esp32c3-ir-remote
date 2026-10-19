#!/usr/bin/env python3
"""Verify three Ghidra export files against 88 pinned ROM function addresses.
All decompiler output is retained, but none counts as novel hardware effect.
"""
import base64,csv,hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parent
O=R/"output"/"ghidra"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
def table(path):
 with path.open(newline="") as f:return list(csv.reader(f,delimiter="\t"))
def main():
 report={"schema":"ROM_GHIDRA_INDEPENDENT_DECOMPILATION_V1","revisions":{},
  "proof_boundary":"Ghidra reverse-compiled C is a hypothesis on recognized ROM bytes, not measured silicon function and not novelty"}
 for rev in REVS:
  expected=table(O/(rev+".names.tsv"));seen=table(O/(rev+".decompiled.tsv"))
  if len(expected)!=88 or len(seen)!=88:raise RuntimeError("GHIDRA_CANDIDATE_ROWS_INCOMPLETE:"+rev)
  results={};counts={}
  for (name,address),row in zip(expected,seen):
   if len(row)!=6:raise RuntimeError("GHIDRA_EXPORT_MALFORMED_ROW:"+name)
   got_name,got_addr,status,recognized,entry,encoded=row
   if got_name!=name or got_addr!=address:raise RuntimeError("GHIDRA_ROW_IDENTITY_MISMATCH")
   if address!="ABSENT" and status=="ABSENT_ELF_FUNCTION":raise RuntimeError("FALSE_ELF_ABSENCE")
   if address=="ABSENT" and status!="ABSENT_ELF_FUNCTION":raise RuntimeError("GHIDRA_INVENTED_FUNCTION")
   if status=="DECOMPILATION_COMPLETED_UNVALIDATED" and not entry:raise RuntimeError("MISSING_ENTRY")
   if entry and int(entry,16)!=int(address,16):raise RuntimeError("GHIDRA_WRONG_FUNCTION_ENTRY")
   c=base64.b64decode(encoded,validate=True).decode("utf-8")
   counts[status]=counts.get(status,0)+1
   results[name]={"vendor_elf_entry":address,"ghidra_entry":entry,"ghidra_symbol":recognized,
      "status":status,"pseudocode_c":c,"pseudocode_sha256":hashlib.sha256(c.encode()).hexdigest()}
  (O/(rev+".results.json")).write_text(json.dumps(results,indent=2)+"\n")
  report["revisions"][rev]={"total_candidates":len(results),"status_counts":counts,
   "completed":counts.get("DECOMPILATION_COMPLETED_UNVALIDATED",0),
   "not_present":counts.get("ABSENT_ELF_FUNCTION",0)}
 (O/"independent_decompiler_summary.json").write_text(json.dumps(report,indent=2)+"\n")
 print("GHIDRA_INDEPENDENT_DECOMPILER_RESULT",json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
