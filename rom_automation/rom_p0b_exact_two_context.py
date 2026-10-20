#!/usr/bin/env python3
"""ROM001 P0-B two unresolved RF/MMIO reads, exact byte-sourced callsite context.

Goal is narrower than undocumented proof: answer which instructions consume
two exact ROM literal loads, with adjacent bytes checked independently against
pinned ELF revision, original vendor-28-header MMIO source and known symbols.
No register writes performed, no emulated hardware state or inferred bit fields.
"""
import argparse,bisect,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,REVS,require,sha
from rom_fast_graph import make_symbol_index
CASES=[
 {"rev":"esp32c3_rev0_rom.elf","function":"rom_phy_xpd_rf",
  "address":"0x600061c4","access_pc":"0x4003ba76"},
 {"rev":"esp32c3_rev101_rom.elf","function":"wdev_mac_wakeup",
  "address":"0x60033c00","access_pc":"0x40045474"}
]
def check_machine(actual,expected):
 require(bytes(actual)==bytes.fromhex(expected),"PINNED_ROM_MACHINE_BYTE_MISMATCH")

def derive_lui_pc(access_pc,source_bytes,pattern):
 require(pattern in ("LUI_ACCESS","LUI_ADDI_ACCESS"),"SOURCE_INSTRUCTION_PATTERN")
 byte_len=len(bytes.fromhex(source_bytes))
 require(byte_len==(8 if pattern=="LUI_ACCESS" else 12),"SOURCE_PATTERN_BYTE_COUNT_MISMATCH")
 return int(access_pc,16)+4-byte_len

def audit(blob,rev,case,vendor,graph):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 rows=[row for row in vendor["all_13_function_differences"] if row["function"]==case["function"]]
 require(len(rows)==1,"EXPECTED_SINGLE_VERIFIED_NAMED_ROM_FUNCTION")
 sites=[s for rec in rows[0]["revision_evidence"].get(rev,[]) for s in
        ([rec] if isinstance(rec,dict) else []) if
        s["address"]==case["address"] and s["access_pc"]==case["access_pc"]]
 require(len(sites)==1,"MMIO_READ_SITE_NOT_IN_PREVIOUS_13_CENSUS")
 site=sites[0];require(site["kind"]=="load","EXPECTED_READ_NOT_STORE")
 elf=ELFFile(io.BytesIO(blob)); sections,bounds,pairs,owners,entries,_=make_symbol_index(elf)
 named=[f for f in graph["function_byte_evidence"][rev].values() if case["function"] in f["aliases"]]
 require(len(named)==1,"FUNCTION_ALIASES_NOT_UNIQUE")
 func=named[0];start=int(func["entry"],16);end=start+func["size_bytes"]
 access=int(case["access_pc"],16)
 require(start<=access<end,"MMIO_READ_OUTSIDE_PINNED_FUNCTION")
 sec=next((x for x in sections if
   int(x["sh_addr"])<=start<end<=int(x["sh_addr"])+int(x["sh_size"])),None)
 require(sec is not None,"FUNCTION_NOT_IN_EXEC_SECTION")
 base=int(sec["sh_addr"]);data=sec.data()
 source=derive_lui_pc(site["access_pc"],site["raw_machine_bytes"],site["pattern"])
 require(start<=source<=access and access+4<=end,"SOURCE_SIGNATURE_OUTSIDE_ELF_FUNCTION")
 sample=data[source-base:source-base+len(site["raw_machine_bytes"])//2]
 check_machine(sample,site["raw_machine_bytes"])
 dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC);dec.skipdata=True
 seq=list(dec.disasm(data[start-base:end-base],start))
 addresses=[x.address for x in seq];i=bisect.bisect_left(addresses,access)
 require(i<len(seq) and seq[i].address==access,"ACCESS_PC_NOT_IN_INSTRUCTION_LIST")
 w=int.from_bytes(bytes(seq[i].bytes),"little")
 require(len(seq[i].bytes)==4 and w&0x7f==3,"NO_RAW_RV32_LOAD")
 rd=(w>>7)&31
 window=[{"pc":hex(x.address),"size":x.size,"mnemonic":x.mnemonic,
     "operands_for_display_only":x.op_str,"raw_machine_bytes":bytes(x.bytes).hex(),
     "not_an_independently_verified_hardware_effect":True}
     for x in seq[max(0,i-12):min(len(seq),i+20)]]
 return {"revision":rev,"function":case["function"],"function_entry":hex(start),
   "function_end_exclusive":hex(end),"address":case["address"],
   "machine_source_lui_pc":hex(source),"machine_access_pc":site["access_pc"],
   "matched_source_bytes":site["raw_machine_bytes"],
   "access_opcode":seq[i].mnemonic,"destination_register_index":rd,
   "nearby_machine_instruction_window":window,
   "field_definition_independently_verified":False,
   "runtime_chip_read_executed":False,
   "direct_first_bitmask_semantics_confirmed":False,
   "classification":"PINNED_MACHINE_CONTEXT_ONLY_NO_NEW_REGISTER_FUNCTION_DETERMINATION"}

def evaluate(rom,graph,vendor):
 require(sha(rom)==ROM_SHA,"ROM_SOURCE_SHA")
 require(graph["schema"]=="ESP32C3_ALL_ROM_FAST_GRAPH_V1" and
   graph["rom_source_sha256"]==ROM_SHA,"ROM_GRAPH_PROVENANCE")
 require(vendor["schema"]=="ROM001_P0B_VENDOR_EXACT_ALL_13_V1" and
   vendor["ROM_SHA256"]==ROM_SHA,"OFFICIAL_VENDOR_MMIO_SOURCE_PROVENANCE")
 result=[]
 with tarfile.open(rom,"r:gz") as t:
  for case in CASES:
   m=[x for x in t.getmembers() if x.isfile() and pathlib.PurePosixPath(x.name).name==case["rev"]]
   require(len(m)==1,"REVISION_MISSING")
   b=t.extractfile(m[0]).read()
   require(hashlib.sha256(b).hexdigest()==graph["all_revisions"][case["rev"]]["elf_sha256"],"ROM_REV_ELF_SHA")
   result.append(audit(b,case["rev"],case,vendor,graph))
 return {"schema":"ROM001_P0B_TWO_PINNED_MACHINE_CALLSITE_CONTEXT_V1",
    "original_issue_id":"ESP32C3-ROM-001","ROM_sha256":ROM_SHA,
    "two_reviewed_callsite_windows":result,
    "new_function_proven":0,"hardware_observation":0,
    "next_evidence_required":"Independent Espressif bitfield reference or approved on-device read-only sampling on verified C3 rev. Never label inferred bits as documented."}

def main():
 p=argparse.ArgumentParser()
 for x in ("rom","graph","vendor","out"):p.add_argument("--"+x,required=True,type=pathlib.Path)
 a=p.parse_args()
 r=evaluate(a.rom,json.loads(a.graph.read_text()),json.loads(a.vendor.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_P0B_EXACT_TWO",json.dumps([{
   "rev":x["revision"],"function":x["function"],"addr":x["address"],
   "read_pc":x["machine_access_pc"],"reg":x["destination_register_index"],
   "instruction_context":len(x["nearby_machine_instruction_window"])}
   for x in r["two_reviewed_callsite_windows"]],sort_keys=True))
if __name__=="__main__":main()
