#!/usr/bin/env python3
"""Static branch-specific ISA proof of vendor-named, commented-out BLE scan ECO.
This is not a silicon test and does not enable a disabled linker alias.
"""
import json,pathlib
ROOT=pathlib.Path(__file__).resolve().parent;O=ROOT/"output"
ENTRY=0x4002a43e
TRACE={
 "0x4002a474":("c.jalr","a5"),"0x4002a476":("c.beqz","a0, 0x1e"),
 "0x4002a498":("jal","-0xf18"),"0x4002a4a0":("c.bnez","a0, 0x94"),
 "0x4002a4b0":("lbu","a5, 1(a0)"),"0x4002a4b4":("c.beqz","a5, 0x96"),
 "0x4002a4b6":("c.lui","a5, 0x10"),"0x4002a4bc":("c.addi","a5, 1"),
 "0x4002a4be":("sw","a5, 0x124(a4)"),"0x4002a4c2":("lw","a5, 0x364(a4)"),
 "0x4002a4c6":("andi","a5, a5, -0x200"),"0x4002a4ca":("ori","a5, a5, 1"),
 "0x4002a4ce":("sw","a5, 0x364(a4)"),
 "0x4002a520":("andi","s1, s1, -0x21"),"0x4002a52a":("sh","s1, 0(a0)"),
 "0x4002a52e":("c.addi","s0, 4"),"0x4002a530":("bne","s0, s8, -0x42"),
 "0x4002a544":("c.li","a0, 0"),"0x4002a546":("c.jalr","a5"),
 "0x4002a558":("lhu","a5, 0x14(a0)"),"0x4002a55c":("c.beqz","a5, -0x8a"),
 "0x4002a566":("sw","a5, 0x124(a4)"),
 "0x4002a574":("lhu","s1, 0x14(a0)"),"0x4002a578":("andi","a5, s1, -0x200"),
 "0x4002a57c":("c.beqz","a5, 0x1a"),
 "0x4002a59a":("lw","a5, 0x364(a4)"),"0x4002a59e":("andi","a5, a5, -0x200"),
 "0x4002a5a2":("c.or","a5, s1"),"0x4002a5a4":("c.j","-0xd6")
}
def check(verified):
 for pc,(mn,ops) in TRACE.items():
  row=verified.get(pc)
  if row is None or (row["mnemonic"],row["operands"])!=(mn,ops):
   raise RuntimeError("BLE_ECO_ISA_WITNESS_DIVERGED:"+pc)
def main():
 f=json.loads((O/"candidate_full"/"esp32c3_rev101_rom.elf.candidate_full.json").read_text())["r_lld_scan_start_eco"]
 if f["start"]!=hex(ENTRY) or not f["status"].startswith("FULL_BODY_VERIFIED") or f["bytes"]!=360:
  raise RuntimeError("BLE_ECO_FUNCTION_NOT_EXACT_AND_INDEPENDENTLY_VERIFIED")
 words={x["pc"]:x for x in f["instruction_listing"]};check(words)
 jump=[x for x in f["direct_transfers"] if x["pc"]=="0x4002a498"]
 if len(jump)!=1 or jump[0]["target"]!="0x40029580" or "r_lld_scan_start" not in jump[0]["exact_target_elf_names"]:
  raise RuntimeError("BLE_ECO_BASE_SCANNING_CALL_UNVERIFIED")
 fixed=json.loads((O/"disabled_entries"/"rev101_disabled_ble_entry.json").read_text())
 if fixed["revision_entry_machine"]["esp32c_rev101_rom.elf"]["target"]!=hex(ENTRY):
  raise RuntimeError("BLE_ECO_FIXED_ENTRY_NOT_VERIFIED")
 def mutation():
  changed=dict(words);changed["0x4002a4ca"]={**words["0x4002a4ca"],"operands":"a5, a5, 2"}
  try:check(changed)
  except RuntimeError:return True
  return False
 if not mutation():raise RuntimeError("MUTANT_NOT_DETECTED")
 result={"schema":"ROM_BLE_REV101_ECO_BRANCH_SEMANTICS_V1","issue":"ESP32C3-ROM-001",
  "source_sha256":f["sha256"],"body_address":f["start"],"body_bytes":f["bytes"],
  "verified_isa_witnesses":{pc:words[pc] for pc in TRACE},"mutation_detected":True,
  "branch_semantics":{
   "pre_hook":"At 0x4002a474 calls indirect hook; nonzero returned a0 leads early status return, zero leads to core scan",
   "core_call":"At 0x4002a498 calls named r_lld_scan_start at 0x40029580; failure bypasses special register and list changes",
   "fixed_branch":"When callback byte at +1 nonzero: MMIO[0x60031124]=0x10001; MMIO[0x60031364]=(old & 0xfffffe00)|1",
   "computed_branch":"When callback byte at +1 zero and another callback result halfword at +0x14 nonzero: MMIO[0x60031124]=0x10001; check high halfword bits with indirect callback; MMIO[0x60031364]=(old & 0xfffffe00)|halfword",
   "pair_iterator":"For at most two entries, indirect buffer getter resolves an offset from a descriptor byte multiplied by 0x5a and clears bit5 in a 16-bit word",
   "post_hook":"Indirect hook invoked with a0=0 before return after initial success path"},
  "bytecode_limits":["Not all indirect callback targets resolved","No silicon BLE radio effect validated","Official linker definition is commented-out, not a supported callable API","rev0 and rev3 have no function symbol with this name"],
  "novelty":"NOT_CERTIFIED"}
 p=O/"semantics";p.mkdir(exist_ok=True)
 (p/"ble_scan_rev101_branch_mechanism.json").write_text(json.dumps(result,indent=2)+"\n")
 print("BLE_REV101_ECO_BRANCH_RCA",json.dumps({k:v for k,v in result.items() if k!="verified_isa_witnesses"},sort_keys=True))
if __name__=="__main__":main()
