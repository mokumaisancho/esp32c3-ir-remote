#!/usr/bin/env python3
"""ROM-001: correlate nine static SRAM load sites with pinned vendor linker labels.

A linker variable name proves address provenance, not an initializer, callback
target, runtime action, or novelty. No hardware access or mutable state.
"""
import argparse,collections,hashlib,json,pathlib,re
from decision_gate import ROM_SHA,REVS,require
from rom_sram_writer_audit import collect_sram_slots

EXPECTED_SHA1="f615f3ac3a5125837c74636463bec92b6db2465b"
VENDOR_REF="espressif/esp-idf@383dda6c182e3dabf6355160166fe007df775629"

def linker_symbols(source):
 found=collections.defaultdict(set)
 for name,value in re.findall(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*(0x[0-9a-fA-F]+)\s*;",source):
  found[int(value,16)].add(name)
 require(len(found)>100,"VENDOR_LINKER_PARSE_INCOMPLETE")
 return {k:sorted(v) for k,v in found.items()}

def inspect(strict,writer,graph,linker_text,git_blob_sha1):
 require(git_blob_sha1==EXPECTED_SHA1,"VENDOR_GIT_BLOB_PIN_MISMATCH")
 require(strict.get("pinned_rom_sha256")==ROM_SHA,"STRICT_SOURCE_SHA")
 require(writer.get("source_ROM_sha256")==ROM_SHA,"WRITER_SOURCE_SHA")
 require(graph.get("rom_source_sha256")==ROM_SHA,"GRAPH_SOURCE_SHA")
 slots=collect_sram_slots(strict)
 labels=linker_symbols(linker_text);output={}
 for rev in REVS:
  used={int(v["target_sram_slot"],16) for v in writer["revisions"][rev]["exact_address_store_candidates"]}
  unresolved=slots[rev]-used
  require(len(unresolved)==9,"UNRESOLVED_NINE_EXPECTED")
  consumers=collections.defaultdict(set);sites=collections.Counter()
  for hit in strict["revisions"][rev]["unresolved_base_examples_per_class"]["STATIC_COMPUTED_BASE_REGION_NOT_YET_CONFIRMED"]:
   addr=int(hit["base_trace"]["candidate_readonly_slot"],16)
   if addr not in unresolved:continue
   fn=graph["function_byte_evidence"][rev].get(hit["caller_function_id"])
   require(fn is not None,"CALLER_ID_NOT_IN_GRAPH")
   consumers[addr].update(fn["aliases"])
   sites[addr]+=1
  detail={}
  for addr in sorted(unresolved):
   detail[hex(addr)]={
    "vendor_exact_linker_symbol_names":labels.get(addr,[]),
    "bounded_ROM_function_consumers":sorted(consumers[addr]),
    "evidence_sampled_callsites":sites[addr],
    "vendor_linker_name_proven":bool(labels.get(addr)),
    "actual_value_verified":False,"initializer_verified":False,
    "dynamic_call_to_target_verified":False}
  named={k:v for k,v in detail.items() if v["vendor_exact_linker_symbol_names"]}
  output[rev]={"unresolved_writer_address_count":9,
    "exact_vendor_name_address_matches":len(named),
    "unmapped_addresses":9-len(named),
    "addresses":detail}
 require(all(x["exact_vendor_name_address_matches"]==2 for x in output.values()),
         "VENDOR_ADDRESS_MATCH_COUNT_DRIFT")
 for rev,detail in output.items():
  require(detail["addresses"]["0x3fcdf8d0"]["vendor_exact_linker_symbol_names"]==["g_net80211_tx_func"],
          "WIFI_SYMBOL_ID_DRIFT")
  require(detail["addresses"]["0x3fcdfc04"]["vendor_exact_linker_symbol_names"]==["rwip_param"],
          "BLE_SYMBOL_ID_DRIFT")
 return {
  "schema":"ROM001_NINE_SRAM_VENDOR_CORRELATION_V1",
  "original_issue_id":"ESP32C3-ROM-001",
  "vendor_source_ref":VENDOR_REF,"vendor_linker_git_blob_sha1":git_blob_sha1,
  "ROM_archive_sha256":ROM_SHA,
  "revisions":output,
  "new_address_variable_names_correlated_per_revision":2,
  "storage_initializers_proven":0,"physical_callee_execution_proven":0,
  "independent_novel_capability_proven":0,
  "limits":["Exact name+address from vendor linker, not a runtime write receipt.",
            "20 selected readsites per revision do not exhaust all read or write sites.",
            "The two named variables are already documented; classify known, not novel.",
            "Other seven SRAM variables have no exact symbol in selected linker file; absence is not global proof."]}

def main():
 p=argparse.ArgumentParser()
 for name in ("strict","writer","graph","vendor-ld","out"):
  p.add_argument("--"+name,type=pathlib.Path,required=True)
 p.add_argument("--git-blob",required=True)
 a=p.parse_args()
 r=inspect(json.loads(a.strict.read_text()),json.loads(a.writer.read_text()),
           json.loads(a.graph.read_text()),a.vendor_ld.read_text(),a.git_blob)
 a.out.parent.mkdir(exist_ok=True,parents=True)
 a.out.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
 print("ROM_NINE_SRAM_VENDOR_NAMES",json.dumps({
   rev:{"matched":v["exact_vendor_name_address_matches"],"not_named":v["unmapped_addresses"]}
   for rev,v in r["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
