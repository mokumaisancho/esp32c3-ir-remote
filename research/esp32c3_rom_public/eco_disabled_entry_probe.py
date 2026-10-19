#!/usr/bin/env python3
"""Check deliberately disabled ECO BLE ROM entry, actual revision-specific JAL,
and instruction-level call/register effects. No silicon execution claimed.
"""
import csv,hashlib,io,json,pathlib,re,subprocess,tarfile,tempfile,urllib.request
from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
from elftools.elf.elffile import ELFFile
from rom_opcode import jal
ROOT=pathlib.Path(__file__).resolve().parent;O=ROOT/"output"
OUT=O/"disabled_entries";OUT.mkdir(parents=True,exist_ok=True)
REV=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
ENTRY=0x40001d24;TARGET=0x4002a43e
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
LINK="components/esp_rom/esp32c3/ld/esp32c3.rom.eco7_bt_funcs.ld"
def require(cond,label):
 if not cond:raise RuntimeError("DISABLED_ENTRY_EVIDENCE_INVALID:"+label)
def get(url):
 return urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"rom-disabled-eco-entry/1"}),timeout=120).read()
def actual_bytes(elf,addr,n=4):
 sections=[s for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS" and int(s["sh_flags"])&4 and int(s["sh_addr"])<=addr and addr+n<=int(s["sh_addr"])+int(s["sh_size"])]
 require(len(sections)==1,"ADDRESS_NOT_UNIQUE_EXECUTABLE")
 sec=sections[0];i=addr-int(sec["sh_addr"]);return sec.data()[i:i+n]
def symbol(elf,name):
 entries=set()
 for s in elf.iter_sections():
  if s["sh_type"]=="SHT_SYMTAB":
   for x in s.iter_symbols():
    if x.name==name and x["st_info"]["type"]=="STT_FUNC":entries.add(int(x["st_value"]))
 return sorted(entries)
def main():
 originals=list(csv.DictReader((O/"idf_known"/"sources.csv").open(newline="")))
 linker=[]
 for record in originals:
  if record["path"]!=LINK:continue
  raw=get(record["source_url"])
  require(hashlib.sha256(raw).hexdigest()==record["sha256"],"PINNED_SOURCE_FILE_CHANGED")
  content=raw.decode("utf-8")
  comments=re.findall(r"/\*.*?\*/",content,flags=re.S)
  inactive=[x for x in comments if re.search(r"(?m)^\s*r_lld_scan_start_eco\s*=\s*0x40001d24\s*;",x)]
  active=re.sub(r"/\*.*?\*/","",content,flags=re.S)
  require(len(inactive)==1,"DISABLED_LINE_NOT_IN_ONE_COMMENT_BLOCK")
  require(not re.search(r"(?m)^\s*r_lld_scan_start_eco\s*=",active),"ENTRY_IS_ALREADY_ACTIVE")
  linker.append({"snapshot":record["snapshot"],"source":record["source_url"],"sha256":record["sha256"],
     "commented_entry":"r_lld_scan_start_eco = 0x40001d24;","active_linker":False,
     "disabled_comment_context":"ble functions disable"})
 require(len(linker)>=2,"INSUFFICIENT_OFFICIAL_LINKER_SNAPSHOTS")
 blob=get(URL);require(hashlib.sha256(blob).hexdigest()==SHA,"ROM_ARCHIVE_DIGEST")
 per={};dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 with tarfile.open(fileobj=io.BytesIO(blob),mode="r:gz") as t,tempfile.TemporaryDirectory() as tmp:
  for name in REV:
   found=[x for x in t.getmembers() if x.isfile() and pathlib.PurePosixPath(x.name).name==name]
   require(len(found)==1,"MISSING_REVISION")
   data=t.extractfile(found[0]).read();p=pathlib.Path(tmp)/name;p.write_bytes(data)
   elf=ELFFile(io.BytesIO(data));raw=actual_bytes(elf,ENTRY)
   cap=list(dec.disasm(raw,ENTRY))
   require(cap and cap[0].size>0,"CAPSTONE_ENTRY_CANNOT_DECODE")
   target=jal(raw,ENTRY)
   cmd=["riscv64-linux-gnu-objdump","-d","--start-address="+hex(ENTRY),"--stop-address="+hex(ENTRY+4),str(p)]
   disasm=subprocess.check_output(cmd,text=True,timeout=120)
   require(re.search(r"(?m)^\s*40001d24:\s+"+raw[:cap[0].size][::-1].hex()+r"\s+",disasm,re.I) is not None,
     "GNU_OBJDUMP_RAW_BYTES_DISAGREE")
   actual=symbol(elf,"r_lld_scan_start_eco")
   per[name]={"entry_word":raw.hex(),"native_disasm":disasm.strip(),"capstone_mnemonic":cap[0].mnemonic,
    "target":hex(target) if target is not None else None,
    "target_vendor_elf_function":"r_lld_scan_start_eco" if target is not None and target in actual else None,
    "name_address_in_elf":[hex(x) for x in actual]}
 require(per[REV[1]]["target"]==hex(TARGET),"REV101_NOT_TARGET_FUNCTION")
 require(per[REV[1]]["target_vendor_elf_function"]=="r_lld_scan_start_eco","TARGET_ELF_SYMBOL_NOT_EXACT")
 for n in (REV[0],REV[2]):
  require(per[n]["target"]!=hex(TARGET),"CROSS_REVISION_FALSE_COMPATIBILITY:"+n)
 f=json.loads((O/"candidate_full"/(REV[1]+".candidate_full.json")).read_text())["r_lld_scan_start_eco"]
 require(f["status"].startswith("FULL_BODY_VERIFIED"),"TARGET_BODY_NOT_FULL_DECODED")
 require(f["start"]==hex(TARGET),"TARGET_BODY_START_CHANGED")
 calls=[x for x in f["direct_transfers"] if "r_lld_scan_start" in x.get("exact_target_elf_names",[])]
 require(len(calls)==1 and calls[0]["target"]=="0x40029580","EXISTING_SCAN_FUNCTION_CALL_NOT_VERIFIED")
 inst={x["pc"]:x for x in f["instruction_listing"]}
 witnesses={
  "0x4002a4b6":("c.lui","a5, 0x10"),
  "0x4002a4b8":("lui","a4, 0x60031"),
  "0x4002a4bc":("c.addi","a5, 1"),
  "0x4002a4be":("sw","a5, 0x124(a4)"),
  "0x4002a4c2":("lw","a5, 0x364(a4)"),
  "0x4002a4c6":("andi","a5, a5, -0x200"),
  "0x4002a4ca":("ori","a5, a5, 1"),
  "0x4002a4ce":("sw","a5, 0x364(a4)"),
 }
 proof=[]
 for pc,(mnemonic,operands) in witnesses.items():
  x=inst.get(pc)
  require(x is not None and x["mnemonic"]==mnemonic and x["operands"]==operands,"EXPECTED_MACHINE_EFFECT_MISSING:"+pc)
  proof.append({"pc":pc,"word":x["word"],"mnemonic":mnemonic,"operands":operands})
 # Negative controls: changing the entry point/target must be detected.
 negatives=[
   (jal(bytes.fromhex(per[REV[1]]["entry_word"]),ENTRY+4)==TARGET),
   (per[REV[2]]["target"]==hex(TARGET)),
 ]
 require(not any(negatives),"NEGATIVE_CONTROLS_NOT_CAUGHT")
 report={"schema":"ROM_REV101_DISABLED_BLE_ENTRY_PROOF_V1","original_issue_id":"ESP32C3-ROM-001",
  "pinned_archive_sha256":SHA,"official_commented_linker_sources":linker,
  "linker_meaning":"Commented-out definition is NOT a supported ESP-IDF link symbol",
  "revision_entry_machine":per,"rev101_target_function":"r_lld_scan_start_eco",
  "rev101_existing_scan_call":{"pc":calls[0]["pc"],"target":calls[0]["target"]},
  "rev101_effect_sequence":proof,
  "static_effects":{"0x60031124":"write literal 0x00010001 on conditional path",
    "0x60031364":"(prior register value & 0xfffffe00) | 1 on conditional path"},
  "independent_native_word_verdict":"PASS_ALL_THREE",
  "negative_controls_caught":len(negatives),
  "novelty_verdict":"KNOWN_VENDOR_NAMED_BUT_DISABLED_IDF_LINKER_ENTRY; ACTUAL_EXECUTABLE_CALL_ONLY_REV101",
  "limitations":["A ROM entry observed in official ELF is not an OS-supported user API",
    "No physical ESP32-C3 rev101 execution or circuit effect tested",
    "ECO7 label and ROM rev101 are NOT assumed to be matching silicon revisions; addresses verified independently",
    "Unmatched indirect callbacks remain unresolved","Hardware effect of register values remains unverified"]}
 (OUT/"rev101_disabled_ble_entry.json").write_text(json.dumps(report,indent=2)+"\n")
 print("ROM_DISABLED_BLE_ENTRY_RESULT",json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
