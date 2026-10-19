#!/usr/bin/env python3
"""Reproducible official-header and prior-study provenance triage of 46 names.

Input: independently saved full-machine and Ghidra artifacts. No novel API
claims are inferred from source-name absence, peripheral addresses or pseudocode.
"""
import argparse,collections,csv,io,json,re,zipfile
P=argparse.ArgumentParser();P.add_argument("--machine-zip",required=True);P.add_argument("--ghidra-zip",required=True);P.add_argument("--out",required=True)
a=P.parse_args();m=zipfile.ZipFile(a.machine_zip);g=zipfile.ZipFile(a.ghidra_zip)
refs=collections.defaultdict(set)
for x in csv.DictReader(io.StringIO(m.read("output/idf_known/header_register_addresses.csv").decode())):
 refs[x["address"].lower()].add(x["name"])
rev=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
c={r:{x["name"]:x["pseudocode"] for x in json.loads(g.read("output/ghidra/"+r+".decompiled.json"))} for r in rev}
tri=json.loads(g.read("output/ghidra/triage_88.json"));rows=[]
for item in tri["reviewed"]:
 if item["idf_linker_status"]!="UNRESOLVED_IN_SELECTED_IDF_SOURCES":continue
 name=item["candidate_name"];observed=set();written=set()
 for r in rev:
  code=c[r].get(name,"")
  observed.update("0x"+x.lower() for x in re.findall(r"_DAT_ram_([0-9a-fA-F]{8})",code))
  written.update("0x"+x.lower() for x in re.findall(r"_DAT_ram_([0-9a-fA-F]{8})\s*=(?!=)",code))
 known={addr:sorted(refs[addr]) for addr in sorted(observed) if refs[addr]}
 rows.append({"name":name,"memory_addresses":sorted(observed),"write_addresses_from_Ghidra_C":sorted(written),
  "official_vendor_register_macro_matches":known,"corroborated_by_vendor_header":bool(known),
  "overlap_with_2025_register_addresses":item["matched_prior_study_registers"],
  "corroborated_by_prior_register_address":bool(item["matched_prior_study_registers"]),
  "exact_opcode_mechanism_witness":bool(item["function_algorithm_witness"]),
  "new_function_proven":False})
if len(rows)!=46:raise RuntimeError("NOT_ALL_FORTY_SIX_NAMES")
summary={"total_unmatched_names":len(rows),
 "vendor_header_addr_overlap_names":sum(x["corroborated_by_vendor_header"] for x in rows),
 "prior_paper_addr_overlap_names":sum(x["corroborated_by_prior_register_address"] for x in rows),
 "machine_effect_witness_names":sum(x["exact_opcode_mechanism_witness"] for x in rows),
 "any_static_corroboration":sum(any((x["corroborated_by_vendor_header"],x["corroborated_by_prior_register_address"],x["exact_opcode_mechanism_witness"])) for x in rows)}
summary["no_selected_corroboration"]=len(rows)-summary["any_static_corroboration"]
out={"schema":"ROM_46_UNMATCHED_IDF_PROVENANCE_TRIAGE_V1","summary":summary,"rows":rows,
 "cautions":["Source classification is limited to three IDF revisions and selected headers",
  "Ghidra C memory references may reflect imprecise types/dataflow",
  "Overlap establishes a prior corresponding address, not function equivalence",
  "No matching source is NOT proof of novelty or undisclosed API"]}
open(a.out,"w").write(json.dumps(out,indent=2)+"\n")
print("ROM_46_SOURCE_TRIAGE",json.dumps(summary,sort_keys=True))
