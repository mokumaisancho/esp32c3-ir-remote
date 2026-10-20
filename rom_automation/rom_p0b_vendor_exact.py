#!/usr/bin/env python3
"""ROM-001 P0-B: exact-register vendor match for 13 revision-specific MMIO deltas.

Uses a fixed Espressif esp-idf commit and 28 header files, pinned reg_base
byte equality, per-source SHA receipts. Not-found is NEVER 'undocumented'.
"""
import argparse,collections,concurrent.futures,hashlib,json,pathlib,sys
from decision_gate import ROM_SHA,require
ROOT=pathlib.Path(__file__).resolve().parents[1]
PUBLIC=ROOT/"research"/"esp32c3_rom_public"
sys.path.insert(0,str(PUBLIC))
from exact_register_headers import HEADERS,UPSTREAM_COMMIT,download,parse_exact_registers
from register_base_compare import read_bases

def check_headers(base_raw,header_items,expected_base):
 require(base_raw==expected_base,"PINNED_BASE_HEADER_MISMATCH")
 base_by_addr=read_bases(base_raw.decode())
 by_name={name:addr for addr,names in base_by_addr.items() for name in names}
 mapped=collections.defaultdict(list);file_shas={};unresolved=[]
 for name,raw in sorted(header_items):
  file_shas[name]=hashlib.sha256(raw).hexdigest()
  parsed,other=parse_exact_registers(raw.decode(),by_name)
  for addr,symbol,base in parsed:
   mapped[addr].append({"symbol":symbol,"header":name,"base_macro":base})
  unresolved.extend([{"header":name,**x} for x in other])
 return mapped,file_shas,unresolved

def classify(report,mapped):
 require(report["schema"]=="ROM001_P0B_MACHINE_MMIO_REV_DIFF_V1"
  and report["ROM_SHA256"]==ROM_SHA,"P0B_INPUT_PROVENANCE")
 diff=report["all_differentials"]
 require(len(diff)==13,"P0B_13_CANDIDATE_DRIFT")
 rows=[];matched=set();missing=set()
 for item in diff:
  all_addrs=sorted({int(hit["address"],16)
   for cells in item["all_static_evidence"].values() for row in cells
   for hit in row["machine_mmio_sites"]})
  per_rev={}
  for rev,sample in item["all_static_evidence"].items():
   per_rev[rev]=[
    {"address":hit["address"],"kind":hit["kind"],
     "access_pc":hit["access_pc"],"pattern":hit["pattern"],
     "raw_machine_bytes":hit["source_bytes"],
     "vendor_exact_registers":mapped.get(int(hit["address"],16),[]),
     "vendor_register_name_verdict":"EXACT_MACRO_MATCH" if int(hit["address"],16) in mapped else "NO_SIMPLE_MACRO_MATCH",
     "register_field_semantics_verified":False}
    for cell in sample for hit in cell["machine_mmio_sites"]]
  known=[a for a in all_addrs if a in mapped]
  unknown=[a for a in all_addrs if a not in mapped]
  matched.update(known);missing.update(unknown)
  rows.append({"function":item["function_name"],
   "revision_evidence":per_rev,
   "all_machine_mmio_addresses":[hex(v) for v in all_addrs],
   "matched_exact":[hex(a) for a in known],
   "not_matched_exact":[hex(a) for a in unknown],
   "novel_register_proven":False})
 return rows,matched,missing

def evaluate(p0b):
 base_local=(PUBLIC/"official_reg_base.h").read_bytes()
 _,vendor_base=download("reg_base.h")
 with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
  headers=list(pool.map(download,HEADERS))
 mapped,files,unresolved=check_headers(vendor_base,headers,base_local)
 rows,known,missing=classify(p0b,mapped)
 return {"schema":"ROM001_P0B_VENDOR_EXACT_ALL_13_V1",
  "original_issue_id":"ESP32C3-ROM-001",
  "ROM_SHA256":ROM_SHA,
  "esp_idf_vendor_commit":UPSTREAM_COMMIT,
  "vendor_register_header_count":len(HEADERS),
  "vendor_register_header_sha256":files,
  "vendor_base_bytes_sha256":hashlib.sha256(vendor_base).hexdigest(),
  "resolved_simple_register_definitions":sum(len(x) for x in mapped.values()),
  "vendor_register_macros_with_unresolved_base":len(unresolved),
  "all_13_function_differences":rows,
  "distinct_examined_addresses":len(known|missing),
  "distinct_addresses_with_exact_register_macros":len(known),
  "distinct_addresses_without_simple_exact_macros":len(missing),
  "exact_match_addresses":[hex(x) for x in sorted(known)],
  "not_found_in_simple_register_macros":[hex(x) for x in sorted(missing)],
  "unexplained_semantics_proven":0,
  "hardware_test_performed":False,
  "limitations":[
   "An exact macro name does not prove hardware behavior or vendor documented field semantics.",
   "No simple exact macro match does not mean the register is undocumented; dynamic/header alias definitions and internal wireless registers are excluded.",
   "Revision comparison of compiler sequences is not evidence of new silicon capability.",
   "Only instruction-local LUI/ADDI load/store matches; other accesses are unmodeled."
  ]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--p0b",required=True,type=pathlib.Path)
 p.add_argument("--out",required=True,type=pathlib.Path)
 args=p.parse_args()
 result=evaluate(json.loads(args.p0b.read_text()))
 args.out.parent.mkdir(parents=True,exist_ok=True)
 args.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print("ROM_P0B_VENDOR_EXACT",json.dumps({k:result[k] for k in ("vendor_register_header_count","distinct_examined_addresses","distinct_addresses_with_exact_register_macros","distinct_addresses_without_simple_exact_macros","unexplained_semantics_proven")},sort_keys=True))
if __name__=="__main__":main()
