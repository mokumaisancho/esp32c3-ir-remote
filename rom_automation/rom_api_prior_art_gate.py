#!/usr/bin/env python3
"""ROM-001: fail-closed named API prior-art gate using SHA-pinned vendor linker definitions.

Names present in historical vendor ROM linker tables are NOT newly discovered
APIs. Names absent from these files are only "not in this frozen catalog":
do not promote them to world-wide novelty.
"""
import argparse,hashlib,json,pathlib,re,urllib.request

PINNED_COMMIT="383dda6c182e3dabf6355160166fe007df775629"
VENDOR_DIR="components/esp_rom/esp32c3/ld"
BASE=f"https://raw.githubusercontent.com/espressif/esp-idf/{PINNED_COMMIT}/{VENDOR_DIR}/"
# Frozen snapshot verified through Git blob object identifiers. Includes ALL .ld
# files in the version-pinned directory, not a manually cherry-picked subset.
VENDOR_BLOBS={
"esp32c3.rom.api.ld":"3c6079d4e6be91a9601fa2aaf3166d1009fcafd6",
"esp32c3.rom.ble_50.ld":"d5662c347de771cfe02b39137454acbc236ff937",
"esp32c3.rom.ble_cca.ld":"95e6de0642743d8a3f6ddfa00d39d43bf41dd134",
"esp32c3.rom.ble_dtm.ld":"aeede90250df8f77489d55d608f6be984e0c13d8",
"esp32c3.rom.ble_master.ld":"e7d2db0cbff1187b4a41de0ebc4778f824b41d57",
"esp32c3.rom.ble_scan.ld":"eda6c721a1bf4f0f9f9e12f62cc65393e65a58bf",
"esp32c3.rom.ble_smp.ld":"9d1e9fcb99eeb3bbf4c2ebd2dd1a7c3f26df373b",
"esp32c3.rom.ble_test.ld":"0c821cf5ba892680cc826dbe0b378ab6bb37643f",
"esp32c3.rom.bt_funcs.ld":"1671c5dffbf37490e74aae047b4bc8ea138984f9",
"esp32c3.rom.eco3.ld":"edad2237dc73b143e81ec34adb74446419916a81",
"esp32c3.rom.eco3_bt_funcs.ld":"15f347f2dab1b6a60e0415da4be259805a6ebe46",
"esp32c3.rom.eco7.ld":"e49badf07e08522066679d04793c252bc5ed5962",
"esp32c3.rom.eco7_bt_funcs.ld":"d746b0846bdc9846e849bb16a4757f5fd429dace",
"esp32c3.rom.ld":"f615f3ac3a5125837c74636463bec92b6db2465b",
"esp32c3.rom.libc-suboptimal_for_misaligned_mem.ld":"61aa184d24da42eb7cf78568498acddeb829b993",
"esp32c3.rom.libc.ld":"f206243491b5da34dfa57b8075f884ab906addcb",
"esp32c3.rom.libgcc.ld":"bda6a38058041402db60f96cb3047e0f005b6c29",
"esp32c3.rom.newlib-nano.ld":"f195477efe0667301cc933ad7c4c0b253e621833",
"esp32c3.rom.newlib-time.ld":"27734ced890aa256182eabb104ea3a9354694d67",
"esp32c3.rom.newlib.ld":"40c5529153fc242ed3d282867d0dfed551a32a03",
"esp32c3.rom.version.ld":"723afa0161ba31d0a5504f07811b492c8a156e4b",
}
assert len(VENDOR_BLOBS)==21

def blob_sha(data):
 return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\\0"+data).hexdigest()

# To avoid including a commented-out symbol as an actual exported API.
C_BLOCK=re.compile(r"/\\*.*?\\*/",re.DOTALL)
C_LINE=re.compile(r"//[^\\n]*")
ASSIGN=re.compile(r"(?m)^\\s*([A-Za-z_$][A-Za-z0-9_.$]*)\\s*=\\s*(0x[0-9A-Fa-f]+|[0-9]+)\\s*;")

def extract_linker_symbols(text):
 clean=C_LINE.sub("",C_BLOCK.sub("",text))
 out={}
 for m in ASSIGN.finditer(clean):
  out.setdefault(m.group(1),set()).add(int(m.group(2),0))
 return out

def get_official(cached=None):
 inventory={};sources={}
 for filename,expected in VENDOR_BLOBS.items():
  if cached:
   data=(cached/filename).read_bytes()
  else:
   req=urllib.request.Request(BASE+filename,headers={"User-Agent":"ROM001-pinned-audit/1.0"})
   with urllib.request.urlopen(req,timeout=25) as resp:data=resp.read()
  digest=blob_sha(data)
  if digest!=expected:raise ValueError("VENDOR_SOURCE_HASH_MISMATCH:"+filename+":"+digest)
  symbols=extract_linker_symbols(data.decode("utf-8"))
  sources[filename]={"git_blob_sha1":digest,"extracted_symbols":len(symbols),
                     "url":"https://github.com/espressif/esp-idf/blob/"+PINNED_COMMIT+"/"+VENDOR_DIR+"/"+filename}
  for name,values in symbols.items():
   for value in values:
    inventory.setdefault(name,[]).append({"file":filename,"exported_link_address":hex(value)})
 if "nets_printf" not in inventory:raise ValueError("MISSING_POSITIVE_KNOWN_ROM_EXPORT")
 if "rom2_temp_to_power1" not in inventory:raise ValueError("MISSING_ECO7_KNOWN_PRIOR_ART_CONTROL")
 return inventory,sources

def screen(triage,inventory,sources):
 if triage.get("schema")!="ESP32C3_ROM_REV101_UNMATCHED_FUNCTION_MACHINE_TRIAGE_V1":
  raise ValueError("UNEXPECTED_CANDIDATE_SCHEMA")
 items=triage.get("all_152_ranked",[])
 if len(items)!=152 or len({x["name"] for x in items})!=152:
  raise ValueError("PINNED_152_CANDIDATES_INCOMPLETE")
 allrows=[];matched=[];unmatched=[]
 for x in items:
  name=x["name"];refs=inventory.get(name,[])
  record={
   "name":name,"triage_score":x["priority_score"],
   "trivial_stub":x["trivial_stub_candidate"],
   "vendor_linker_locations":refs,
   "in_this_pinned_vendor_linker_catalog":bool(refs),
   "status":("KNOWN_OFFICIAL_LINKER_EXPORT" if refs else "NOT_IN_21_PINNED_VENDOR_LINKERS_NOT_NOVELTY"),
   "novelty_proven":False,
   "callable_abi_proven":False,
   "silicon_proven":False,
   "static_machine_metrics":{r:[v["metrics"] for v in arr]
       for r,arr in x["revisions"].items()}
  }
  allrows.append(record);(matched if refs else unmatched).append(record)
 for n in ("rom2_temp_to_power1","rom2_get_tx_gain_value1"):
  if n not in {x["name"] for x in matched}:raise ValueError("PRIOR_ART_FALSE_NEGATIVE:"+n)
 # Evidence is a publication of the name and exported linker entry; the
 # internal STT_FUNC body is a different address, not a contradictory match.
 return {
  "schema":"ROM001_VENDOR_21_LINKER_PRIOR_ART_GATE_V1",
  "original_issue_id":"ESP32C3-ROM-001","vendor_commit":PINNED_COMMIT,
  "vendor_linker_files":sources,
  "total_candidates":len(allrows),
  "known_in_official_linkers":len(matched),
  "not_in_these_21_official_linkers":len(unmatched),
  "known_exports":matched,
  "unmatched_for_independent_followup":unmatched,
  "complete_rows":allrows,
  "novel_api_verified":0,"callability_verified":0,"silicon_verified":0,
  "limits":[
    "Not in the 21 SHA-pinned linker files does not mean unpublished or undiscovered.",
    "Official linker exported address is commonly a ROM trampoline; compare names, never require the internal ELF implementation address to match.",
    "This is a cross-reference/novelty rejection gate, not hardware execution or semantic certification.",
    "Searched this single commit of Espressif's repository, not all history or third-party prior art."
  ]
 }

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--triage",required=True,type=pathlib.Path)
 p.add_argument("--out",required=True,type=pathlib.Path)
 p.add_argument("--vendor-dir",type=pathlib.Path)
 a=p.parse_args();source_bytes=a.triage.read_bytes()
 inventory,sources=get_official(a.vendor_dir)
 result=screen(json.loads(source_bytes),inventory,sources)
 result["triage_json_sha256"]=hashlib.sha256(source_bytes).hexdigest()
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print("ROM001_PRIOR_ART_GATE",json.dumps({
  "total":result["total_candidates"],"known_official_linker_names":result["known_in_official_linkers"],
  "pending_other_prior_art":result["not_in_these_21_official_linkers"],
  "new_api_verified":0,"control_temp_to_power1":inventory["rom2_temp_to_power1"],
  "control_tx_gain_value1":inventory.get("rom2_get_tx_gain_value1",[])
 },sort_keys=True))
if __name__=="__main__":main()
