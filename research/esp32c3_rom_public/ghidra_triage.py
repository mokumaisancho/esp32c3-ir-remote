#!/usr/bin/env python3
"""Complete static review dossier of all 88 ROM candidates using two disassemblers + Ghidra.
The report is not a hardware or novelty certificate.
"""
import collections,csv,json,pathlib,re
ROOT=pathlib.Path(__file__).resolve().parent
O=ROOT/"output"
GH=O/"ghidra";EXACT=O/"candidate_full"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
def read(path):return json.loads(path.read_text())
def main():
 baseline=read(EXACT/"candidate_summary.json")
 names=[x["elf_name"] for x in baseline["all_candidates"]]
 if len(names)!=88 or len(set(names))!=88:raise RuntimeError("INVALID_CANONICAL_88")
 summaries={x["elf_name"]:x for x in baseline["all_candidates"]}
 decompiled={rev:{x["name"]:x for x in read(GH/(rev+".decompiled.json"))} for rev in REVS}
 bodies={rev:read(EXACT/(rev+".candidate_full.json")) for rev in REVS}
 linker=collections.defaultdict(list)
 with (O/"idf_known"/"linker_symbols.csv").open(newline="") as f:
  for x in csv.DictReader(f):linker[x["symbol"]].append({"snapshot":x["snapshot"],"path":x["path"],"value":x["address"] or x["alias_of"]})
 cases=read(EXACT/"mechanism_witnesses.json") if (EXACT/"mechanism_witnesses.json").exists() else {"cases":{}}
 prior=read(O/"register_access"/"published_prior_art_comparison.json")
 published={x["address"].lower() for r in prior["revisions"].values() for x in r["matched_prior_evidence"]}
 reviews=[];total=collections.Counter()
 for name in names:
  entry={"candidate_name":name,
   "idf_linker_status":summaries[name]["idf_classification"],
   "idf_source_evidence":sorted(linker.get(name,[]),key=lambda x:(x["snapshot"],x["path"])),
   "ghidra_and_machine_witnesses":{},
   "identified_register_addresses":[],
   "status":"STATIC_MACHINE_AND_DECOMPILER_REVIEW_COMPLETE__NOT_FUNCTIONALLY_CERTIFIED",
   "dynamic_hardware_proof":"NOT_RUN",
   "novelty_proof":"NOT_ESTABLISHED"}
  reg=set();code_shas=set()
  for rev in REVS:
   body=bodies[rev][name]
   if body["status"]=="ABSENT_SYMBOL":
    if name in decompiled[rev]:raise RuntimeError("UNEXPECTED_GHIDRA_SYMBOL:"+rev+name)
    entry["ghidra_and_machine_witnesses"][rev]={"status":"NOT_IN_THIS_ELF"}
    continue
   record=decompiled[rev].get(name)
   if record is None:raise RuntimeError("MISSING_GHIDRA_CANDIDATE:"+name+":"+rev)
   if record["decompiler_status"]!="DECOMPILED" or not record["pseudocode"]:
    raise RuntimeError("GHIDRA_DECOMPILER_NOT_VERIFIED:"+name+":"+rev)
   if int(record["requested_address"],16)!=int(body["start"],16):raise RuntimeError("ENTRY_PC_DIFFERENCE:"+name+":"+rev)
   code_shas.add(body["sha256"])
   c=record["pseudocode"]
   reg.update("0x"+r.lower() for r in re.findall(r"_DAT_ram_([0-9a-fA-F]{8})",c))
   entry["ghidra_and_machine_witnesses"][rev]={
    "status":"FUNCTION_CODE_AND_PSEUDOCODE_PRESENT",
    "entry":body["start"],"elf_machine_code_sha256":body["sha256"],
    "function_bytes":body["bytes"],"gnu_machine_words_confirmed":body["gnu_machine_words_checked"],
    "ghidra_pseudocode_characters":len(c),
    "conditional_branch_count":body["conditional_branch_count"],
    "indirect_transfer_count":body["indirect_transfer_count"],
    "trap_zero_encodings":len(body["zero_trap_encoding_rows_unchecked_by_gnu"]),
    "direct_public_entry_possible_path":body["direct_public_root_witness"]}
   total["revision_bodies_reviewed"]+=1
  entry["identified_register_addresses"]=sorted(reg)
  entry["matched_prior_study_registers"]=sorted(reg&published)
  entry["code_differs_across_present_revisions"]=len(code_shas)>1
  entry["function_algorithm_witness"]=name in cases.get("cases",{})
  if entry["idf_linker_status"]=="KNOWN_IDF_LINKER_NAME":
   entry["novelty_screen"]="PREVIOUSLY_NAMED_IN_PINNED_ESP_IDF"
   total["candidate_names_known_in_idf"]+=1
  else:
   entry["novelty_screen"]="NOT_NAME_MATCHED_IN_SELECTED_IDF__NOT_PROOF_OF_NEW_FUNCTION"
   total["candidate_names_not_in_selected_idf"]+=1
  if entry["matched_prior_study_registers"]:total["candidates_prior_register_overlap"]+=1
  if entry["function_algorithm_witness"]:total["candidate_names_instruction_effect_documented"]+=1
  total["candidate_names_reviewed"]+=1
  reviews.append(entry)
 if total["candidate_names_reviewed"]!=88 or total["revision_bodies_reviewed"]!=222:
  raise RuntimeError("DOSSIER_INCOMPLETE")
 report={"schema":"ESP32C3_ALL_88_GHIDRA_CANDIDATE_EVIDENCE_V1",
  "total":dict(total),"reviewed":reviews,
  "method":["Three hash-pinned official ROM ELFs","Independent GNU objdump / Capstone machine-word verification",
   "Ghidra 12.1.4 full-function pseudocode by exact ELF address",
   "Three pinned ESP-IDF linker snapshots + register header names",
   "Independent 2025 register address prior comparison"],
  "closure":{"static_evidence_review":"PASS",
             "silicon_behaviour":"NOT_VERIFIED",
             "undocumented_novel_api_discovery":"NOT_CERTIFIED",
             "next_stage":"FIRST adjudicate all 88 semantic novelty claims; ONLY THEN scan ROM for other omitted candidates"},
  "cautions":["Exact symbol address does not establish externally callable API",
   "C-like pseudocode does not prove observed hardware behavior",
   "Register address matches and symbol names are insufficient novelty proof"]}
 (GH/"triage_88.json").write_text(json.dumps(report,indent=2)+"\n")
 print("GHIDRA_88_TRIAGE "+json.dumps({"totals":dict(total),"status":report["closure"]},sort_keys=True))
if __name__=="__main__":main()
