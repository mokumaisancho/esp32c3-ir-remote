#!/usr/bin/env python3
"""ROM-001 R0/R1/R2: prove MMIO REGION ownership without inventing bit semantics.

Inputs: Git-blob-pinned, vendor-supplied ESP32-C3 reg_base.h in this repository
and preexisting TRM v1.4 region classifier. A distinct Espressif-authored C3
memory map independently labels the previously TRM-"Reserved" block FE.
Published academic Wi-Fi ranges only support block ownership, not exact register.
"""
import argparse,hashlib,json,pathlib,re,sys
from rom_p0b_trm_windows import classify as trm_classify

ROOT=pathlib.Path(__file__).resolve().parents[1]
BASE_FILE=ROOT/"research"/"esp32c3_rom_public"/"official_reg_base.h"
BASE_GIT_BLOB_SHA1="d0ef6acfeeb32f66365bdbb1410ab906450374dc"
VENDOR_BASE_SOURCE="https://github.com/espressif/esp-idf/blob/383dda6c182e3dabf6355160166fe007df775629/components/soc/esp32c3/register/soc/reg_base.h"
VENDOR_MAP_SOURCE="https://dl.espressif.com/public/esp32c3-mm.pdf"
ACADEMIC_SOURCE="https://arxiv.org/pdf/2501.17684"
ACADEMIC_PAPER="Mudraje et al., ENSsys 2025, sec 4.4 p.4 and Table 1"
# 2025 paper section 4.4 directly says C3 MAC ranges 0x60033000-0x60035fff.
# Paper's Table 1 does NOT include 0x60033c00: do not claim an exact match.
WIFI_MAC_START=0x60033000
WIFI_MAC_LAST=0x60035fff

TARGETS={
 "R1":{"address":0x600061c4,"rev":"esp32c3_rev0_rom.elf",
       "function":"rom_phy_xpd_rf","expected_base_macro":"DR_REG_FE_BASE",
       "expected_base":0x60006000,"operation":"(OLD & 0xffff0000) | 0x5555",
       "set_mask":0x00005555,"clear_mask":0x0000aaaa},
 "R2":{"address":0x60033c00,"rev":"esp32c3_rev101_rom.elf",
       "function":"wdev_mac_wakeup","operation":"OLD | 0xf0",
       "set_mask":0x000000f0,"clear_mask":0}
}

def git_blob_sha1(data):
 return hashlib.sha1(b"blob "+str(len(data)).encode()+bytes([0])+data).hexdigest()

def official_bases(raw,expected_sha=BASE_GIT_BLOB_SHA1):
 actual=git_blob_sha1(raw)
 if actual!=expected_sha:
  raise ValueError("OFFICIAL_VENDOR_REG_BASE_UNPINNED:"+actual)
 names={}
 for name,hexbase in re.findall(r"(?m)^\s*#define\s+(DR_REG_[A-Z0-9_]+_BASE)\s+(0x[0-9a-fA-F]+)(?!\S)",raw.decode("utf8")):
  if name in names:raise ValueError("VENDOR_BASE_DUPLICATE:"+name)
  names[name]=int(hexbase,16)
 if names.get("DR_REG_FE_BASE")!=0x60006000:
  raise ValueError("VENDOR_FE_BASE_CHANGED")
 if names.get("DR_REG_FE2_BASE")!=0x60005000:
  raise ValueError("VENDOR_FE2_BASE_CHANGED")
 return names

def investigate(bases,targets=TARGETS):
 if set(targets)!={"R1","R2"}:raise ValueError("TWO_TARGET_SCOPE_DRIFT")
 out=[]
 for key in ("R1","R2"):
  x=targets[key];a=x["address"]
  trm=trm_classify(a)
  if trm["classification"]!="TRM_RESERVED":
   raise ValueError("TRM_CONFLICT_EVIDENCE_CHANGED:"+key)
  if key=="R1":
   vendor_base=bases.get(x["expected_base_macro"])
   if vendor_base!=x["expected_base"] or not vendor_base<=a<vendor_base+0x1000:
    raise ValueError("RF_FRONT_END_WINDOW_MISMATCH")
   owner="RF_FRONT_END_FE";off=a-vendor_base
   matched={"kind":"VENDOR_REG_BASE_AND_PUBLISHED_VENDOR_MEMORY_MAP",
            "base_macro":x["expected_base_macro"],"base":hex(vendor_base),
            "offset":hex(off),"sources":[VENDOR_BASE_SOURCE,VENDOR_MAP_SOURCE],
            "external_map_text_proof":"FE labelled at 0x60006000 on official memory map page 2",
            "exact_register_symbol":None}
  else:
   if not (WIFI_MAC_START<=a<=WIFI_MAC_LAST):
    raise ValueError("WIFI_MAC_RANGE_MISMATCH")
   owner="WIFI_MAC_BLOCK";off=a-WIFI_MAC_START
   matched={"kind":"ACADEMIC_REVERSE_ENGINEERED_MAC_RANGE_NOT_EXACT_REGISTER",
            "base":hex(WIFI_MAC_START),"offset":hex(off),
            "sources":[ACADEMIC_SOURCE],
            "source_detail":ACADEMIC_PAPER,
            "literature_scope":"0x60033000..0x60035fff",
            "exact_register_symbol":None}
  out.append({"id":key,"address":hex(a),"target_rev":x["rev"],
     "observed_rom_function":x["function"],"prior_rom_machine_rmw":x["operation"],
     "rmw_set_mask":hex(x["set_mask"]),"rmw_clear_mask":hex(x["clear_mask"]),
     "trm_v1_4":trm,"region_owner":owner,"region_evidence":matched,
     "classification":"REGION_RESOLVED_BITFIELD_UNRESOLVED",
     "exact_bitfield_function_proven":False,"runtime_readback_proven":False,
     "physical_causal_test_proven":False,"novel_capability_proven":False,
     "no_hardware_mutation":True})
 return {"schema":"ROM001_R0_R1_R2_OFFICIAL_REGION_RECONCILIATION_V1",
  "source_vendor_base_git_blob_sha1":BASE_GIT_BLOB_SHA1,
  "vendor_memory_map_published_url":VENDOR_MAP_SOURCE,
  "academic_mac_range_source":ACADEMIC_SOURCE,
  "findings":out,
  "distinct_resolved_blocks":2,"exact_bitfield_semantics_resolved":0,
  "new_rom_api_confirmed":0,"silicon_tests_executed":0,
  "R0_evidence_gate":"PASS_FOR_SOURCE_INTEGRITY_STATIC_ONLY",
  "R1_region_gate":"PASS_OWNER_ONLY",
  "R2_region_gate":"PASS_OWNER_ONLY",
  "R1_R2_field_semantics_gate":"OPEN",
  "limits":[
  "A TRM Reserved window and an FE peripheral in a separate official map can coexist; absence from TRM register catalog is not an unimplemented register.",
  "Exact field semantics are NOT established from function name or a bitmask.",
  "Academic paper MAC window contains address R2 but its Table 1 does not contain R2 exact register.",
  "Published memory map PDF and 2025 paper are human-checked source evidence, not SHA-pinned PDF binaries.",
  "RAM/ROM static machine RMW never proves actual silicon runtime execution.",
  "Do not write any internal RF/WiFi MMIO register as an experiment without independent revision-specific safety assessment."]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--vendor-header",type=pathlib.Path,default=BASE_FILE)
 p.add_argument("--output",required=True,type=pathlib.Path)
 args=p.parse_args()
 bases=official_bases(args.vendor_header.read_bytes())
 result=investigate(bases)
 args.output.parent.mkdir(parents=True,exist_ok=True)
 args.output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf8")
 print("ROM001_R0_R1_R2",json.dumps({
  "region_statuses":{x["id"]:x["classification"] for x in result["findings"]},
  "regions":{x["id"]:x["region_owner"] for x in result["findings"]},
  "field_semantics_proven":0,"silicon_tests":0,"new_apis":0},sort_keys=True))
if __name__=="__main__":main()
