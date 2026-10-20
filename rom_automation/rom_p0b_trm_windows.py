#!/usr/bin/env python3
"""ROM-001 P0-B: publicly pinned TRM v1.4 peripheral-window classification.

The Espressif ESP32-C3 Technical Reference Manual v1.4, printed pp. 98-99
(PDF zero-based pages 97-98), table 3.3-3 is transcribed below by exact ranges.
It says 'Reserved', NOT 'unimplemented' or proof of novel hardware.
Input is the prior exact-vendor macro audit of 13 functions / 16 addresses.
"""
import argparse,collections,json,pathlib
from decision_gate import ROM_SHA,require

SOURCE="https://documentation.espressif.com/esp32-c3_technical_reference_manual_en.pdf"
TRM_VERSION="1.4"
TRM_TABLE="3.3-3"
TRM_PRINTED_PAGES=[98,99]
# Source table 3.3-3 pp.98-99; all ranges inclusive, exact public labels.
TRM_RANGES=[
 (0x60000000,0x60000fff,"UART Controller 0"),
 (0x60001000,0x60001fff,"Reserved"),
 (0x60002000,0x60002fff,"SPI Controller 1"),
 (0x60003000,0x60003fff,"SPI Controller 0"),
 (0x60004000,0x60004fff,"GPIO"),
 (0x60005000,0x60006fff,"Reserved"),
 (0x60007000,0x60007fff,"Reserved"),
 (0x60008000,0x60008fff,"Low-Power Management"),
 (0x60009000,0x60009fff,"IO MUX"),
 (0x6000a000,0x6000ffff,"Reserved"),
 (0x60010000,0x60010fff,"UART Controller 1"),
 (0x60011000,0x60012fff,"Reserved"),
 (0x60013000,0x60013fff,"I2C Controller"),
 (0x60014000,0x60014fff,"UHCIO"),
 (0x60015000,0x60015fff,"Reserved"),
 (0x60016000,0x60016fff,"Remote Control Peripheral"),
 (0x60017000,0x60018fff,"Reserved"),
 (0x60019000,0x60019fff,"LED PWM Controller"),
 (0x6001a000,0x6001afff,"eFuse Controller"),
 (0x6001b000,0x6001efff,"Reserved"),
 (0x6001f000,0x6001ffff,"Timer Group 0"),
 (0x60020000,0x60020fff,"Timer Group 1"),
 (0x60021000,0x60022fff,"Reserved"),
 (0x60023000,0x60023fff,"System Timer"),
 (0x60024000,0x60024fff,"SPI Controller 2"),
 (0x60025000,0x60025fff,"Reserved"),
 (0x60026000,0x60026fff,"SYSCON"),
 (0x60027000,0x6002afff,"Reserved"),
 (0x6002b000,0x6002bfff,"TWAI"),
 (0x6002c000,0x6002cfff,"Reserved"),
 (0x6002d000,0x6002dfff,"I2S Controller"),
 (0x6002e000,0x60039fff,"Reserved"),
 (0x6003a000,0x6003afff,"AES Accelerator"),
 (0x6003b000,0x6003bfff,"SHA Accelerator"),
 (0x6003c000,0x6003cfff,"RSA Accelerator"),
 (0x6003d000,0x6003dfff,"RSA Digital Signature Peripheral"),
 (0x6003e000,0x6003efff,"HMAC Accelerator"),
 (0x6003f000,0x6003ffff,"GDMA Controller"),
 (0x60040000,0x60040fff,"ADC Controller"),
 (0x60043000,0x60043fff,"USB Serial/JTAG Controller"),
 (0x600c0000,0x600c0fff,"System Registers"),
 (0x600c1000,0x600c1fff,"PMS Registers"),
 (0x600c2000,0x600c2fff,"Interrupt Matrix"),
 (0x600cc000,0x600ccfff,"External Memory Encryption and Decryption"),
 (0x600ce000,0x600cefff,"Assist Debug"),
 (0x600d0000,0x600d0fff,"World Controller")
]
def classify(address):
 matches=[(a,b,name) for a,b,name in TRM_RANGES if a<=address<=b]
 require(len(matches)<=1,"OVERLAPPING_TRM_WINDOWS")
 if not matches:return {"classification":"UNMAPPED_IN_TRANSCRIBED_TRM","trm_label":None,"trm_window":None}
 a,b,name=matches[0]
 return {"classification":"TRM_RESERVED" if name=="Reserved" else "TRM_NAMED_PERIPHERAL",
         "trm_label":name,"trm_window":[hex(a),hex(b)]}

def compare(previous):
 require(previous.get("schema")=="ROM001_P0B_VENDOR_EXACT_ALL_13_V1","INPUT_SCHEMA")
 require(previous.get("ROM_SHA256")==ROM_SHA,"INPUT_ROM_SHA")
 named=previous["all_13_function_differences"]
 require(len(named)==13,"EXPECTED_13_NAME_FUNCTIONS")
 matches={int(x,16) for x in previous["exact_match_addresses"]}
 missing={int(x,16) for x in previous["not_found_in_simple_register_macros"]}
 require(not(matches&missing) and len(matches)==2 and len(missing)==14,"EXPECT_TWO_PLUS_FOURTEEN")
 result=[]
 for addr in sorted(matches|missing):
  kinds=collections.defaultdict(list)
  for row in named:
   for rev,rr in row["revision_evidence"].items():
    for ev in rr:
     if int(ev["address"],16)==addr:
      kinds[row["function"]].append({"revision":rev,"access_pc":ev["access_pc"],
        "machine_bytes":ev["raw_machine_bytes"],"operation":ev["kind"]})
  require(kinds,"MMIO_ADDRESS_HAS_NO_FUNCTION_EVIDENCE")
  match=classify(addr)
  result.append({"address":hex(addr),**match,
    "in_simple_esp_idf_register_macro_list":addr in matches,
    "vendor_macro_name_evidence":[y["vendor_exact_registers"] for rr in named
      for rev in rr["revision_evidence"].values() for y in rev if int(y["address"],16)==addr
      and y["vendor_exact_registers"]][:3],
    "function_access_provenance":dict(kinds),
    "classification_does_not_establish_runtime_execution":True,
    "new_capability_proven":False})
 reserved=[x for x in result if x["classification"]=="TRM_RESERVED"]
 require(len(reserved)==14,"RESERVED_14_EXPECTED_FROM_PINNED_ELF")
 require(all(not x["in_simple_esp_idf_register_macro_list"] for x in reserved),
         "RESERVED_MACRO_CONTRADICTION")
 return {"schema":"ROM001_P0B_14_TRM_RESERVED_CLASSIFICATION_V1",
  "original_issue_id":"ESP32C3-ROM-001","source_ROM_SHA256":ROM_SHA,
  "trm":{"url":SOURCE,"edition":TRM_VERSION,"table":TRM_TABLE,"printed_pages":TRM_PRINTED_PAGES,
    "pdf_page_indices":[97,98],"verification":"human-reviewed official document table transcribed; not independent PDF binary SHA"},
  "examined_mmio_address_count":len(result),
  "in_published_TRM_reserved_windows":len(reserved),
  "in_published_TRM_named_peripherals":len(result)-len(reserved),
  "reserved_by_window":dict(sorted(collections.Counter(
    x["trm_window"][0]+".."+x["trm_window"][1] for x in reserved).items())),
  "all_address_evidence":result,
  "TRM_reserved_means_novel_hardware":False,
  "new_silicon_capability_proven":0,
  "required_followup":"Find trustworthy Espressif internal RF/WiFi/PHY naming/errata to resolve reserved locations, then verify read/write semantics without guessing.",
  "limitations":["Reserved in the public TRM means not covered by that published module address map, not necessarily physically absent.",
   "Known firmware routinely accesses vendor internal PHY/RF blocks omitted from public peripheral register documentation.",
   "This is a static ROM byte-level access + independent public TRM classification; runtime semantics not observed."]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--vendor",type=pathlib.Path,required=True)
 p.add_argument("--out",type=pathlib.Path,required=True)
 a=p.parse_args();r=compare(json.loads(a.vendor.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_P0B_TRM14",json.dumps({k:r[k] for k in
   ("examined_mmio_address_count","in_published_TRM_reserved_windows","in_published_TRM_named_peripherals","reserved_by_window","new_silicon_capability_proven")},sort_keys=True))
if __name__=="__main__":main()
