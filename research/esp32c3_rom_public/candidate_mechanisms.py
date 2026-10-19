#!/usr/bin/env python3
"""Instruction-exact functional effects for selected candidate ROM functions.

What is proven: machine-code register/memory operations.
What is NOT proven: runtime dispatch, circuit effects, undocumentation, novelty.
"""
import copy,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parent;OUT=ROOT/"output"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
# Each sequence is an exact decoded ISA witness, not a guessed signature.
CASE={
"hal_enable_mac": {
  "mnemonics": [
   "lui",
   "lw",
   "andi",
   "sw",
   "sw",
   "lui",
   "sw",
   "c.jr"
  ],
  "operands": [
   "a5, 0x60034",
   "a4, -0x400(a5)",
   "a4, a4, -0xf1",
   "a4, -0x400(a5)",
   "a0, -0x3cc(a5)",
   "a5, 0x60033",
   "a1, 0x88(a5)",
   "ra"
  ],
  "static_effect": "mem32[0x60033c00] &= ~0xf0; mem32[0x60033c34]=a0; mem32[0x60033088]=a1",
  "external_prior": "Known vendor ROM ELF function; 0x60033088 address described in 2025 Wi-Fi study"
 },
 "hal_disable_mac": {
  "mnemonics": [
   "lui",
   "lw",
   "ori",
   "sw",
   "lw",
   "sw",
   "sw",
   "sw",
   "c.jr"
  ],
  "operands": [
   "a5, 0x60034",
   "a4, -0x400(a5)",
   "a4, a4, 0xf0",
   "a4, -0x400(a5)",
   "a0, -0x3cc(a5)",
   "zero, -0x3cc(a5)",
   "zero, -0x3c8(a5)",
   "zero, -0x3dc(a5)",
   "ra"
  ],
  "static_effect": "mem32[0x60033c00] |= 0xf0; return old mem32[0x60033c34]; write 0 to 0x60033c34,0x60033c38,0x60033c24",
  "external_prior": "Static vendor ROM implementation; verify actual MAC behavior on silicon"
 },
 "hal_clear_rx_beacon_pti": {
  "mnemonics": [
   "lui",
   "lw",
   "ori",
   "sw",
   "c.jr"
  ],
  "operands": [
   "a4, 0x60035",
   "a5, 0x88(a4)",
   "a5, a5, 1",
   "a5, 0x88(a4)",
   "ra"
  ],
  "static_effect": "mem32[0x60035088] |= 1",
  "external_prior": "Register address label not independently certified"
 },
 "hal_disable_sta_beacon_filter": {
  "mnemonics": [
   "lui",
   "lw",
   "lui",
   "c.andi",
   "sw",
   "lw",
   "c.lui",
   "c.addi",
   "c.and",
   "sw",
   "c.jr"
  ],
  "operands": [
   "a4, 0x60033",
   "a5, 0xa0(a4)",
   "a3, 0x60034",
   "a5, -8",
   "a5, 0xa0(a4)",
   "a5, -0x3cc(a3)",
   "a4, 0xffff8",
   "a4, -1",
   "a5, a4",
   "a5, -0x3cc(a3)",
   "ra"
  ],
  "static_effect": "mem32[0x600330a0] &= ~7; mem32[0x60033c34] &= ~0x8000",
  "external_prior": "Name from vendor ELF; exact register bit effect inferred from ISA"
 },
 "hal_enable_sta_beacon_filter": {
  "mnemonics": [
   "lui",
   "lw",
   "c.lui",
   "c.addi",
   "c.and",
   "sw",
   "lw",
   "c.lui",
   "lui",
   "c.or",
   "sw",
   "lw",
   "ori",
   "sw",
   "c.jr"
  ],
  "operands": [
   "a5, 0x60034",
   "a4, -0x3cc(a5)",
   "a3, 0xffff8",
   "a3, -1",
   "a4, a3",
   "a4, -0x3cc(a5)",
   "a4, -0x3cc(a5)",
   "a2, 8",
   "a3, 0x60033",
   "a4, a2",
   "a4, -0x3cc(a5)",
   "a5, 0xa0(a3)",
   "a5, a5, 7",
   "a5, 0xa0(a3)",
   "ra"
  ],
  "static_effect": "TWO ordered writes: clear bit15 at 0x60033c34 THEN set bit15 at same MMIO; mem32[0x600330a0] |= 7",
  "external_prior": "Ghidra pseudo C collapses intermediate MMIO store; original ISA has two stores. Potential edge side-effect is UNVERIFIED"
 },
 "hal_mac_rx_get_last_dscr": {
  "mnemonics": [
   "lui",
   "lw",
   "lui",
   "lw",
   "lui",
   "c.and",
   "c.or",
   "c.jr"
  ],
  "operands": [
   "a5, 0x60033",
   "a0, 0x90(a5)",
   "a5, 0x60034",
   "a5, -0x39c(a5)",
   "a4, 0xfff00",
   "a5, a4",
   "a0, a5",
   "ra"
  ],
  "static_effect": "return mem32[0x60033090] | (mem32[0x60033c64] & 0xfff00000)",
  "external_prior": "Internal vendor ELF names; descriptor address meaning not independently certified"
 },
 "hal_mac_rx_read_rxdscrlast": {
  "mnemonics": [
   "lui",
   "lw",
   "c.jr"
  ],
  "operands": [
   "a5, 0x60033",
   "a0, 0x90(a5)",
   "ra"
  ],
  "static_effect": "return mem32[0x60033090]",
  "external_prior": "Internal vendor ELF name; hardware semantics unverified"
 },
 "hal_mac_rx_read_rxdscrnext": {
  "mnemonics": [
   "lui",
   "lw",
   "c.jr"
  ],
  "operands": [
   "a5, 0x60033",
   "a0, 0x8c(a5)",
   "ra"
  ],
  "static_effect": "return mem32[0x6003308c]",
  "external_prior": "Internal vendor ELF name; hardware semantics unverified"
 },
 "hal_pwr_interrupt_clr_event": {
  "mnemonics": [
   "lui",
   "sw",
   "c.jr"
  ],
  "operands": [
   "a5, 0x60035",
   "a0, 0x11c(a5)",
   "ra"
  ],
  "static_effect": "mem32[0x6003511c] = a0",
  "external_prior": "Internal vendor ELF name, not a certified interrupt peripheral label"
 },
 "hal_pwr_interrupt_get_event": {
  "mnemonics": [
   "lui",
   "lw",
   "c.jr"
  ],
  "operands": [
   "a5, 0x60035",
   "a0, 0x118(a5)",
   "ra"
  ],
  "static_effect": "return mem32[0x60035118]",
  "external_prior": "Internal vendor ELF name, not a certified interrupt peripheral label"
 },
 "spi_slave_rom_check_conn": {
  "mnemonics": [
   "lui",
   "lw",
   "addi",
   "seqz",
   "c.jr"
  ],
  "operands": [
   "a5, 0x60024",
   "a0, 0xa4(a5)",
   "a0, a0, -0xa5",
   "a0, a0",
   "ra"
  ],
  "static_effect": "return mem32[0x600240a4] == 0xa5",
  "external_prior": "ROM SPI2 peripheral base is officially known, but register 0xa4 magic handshake function not independently documented"
 },
 "hal_mac_rx_enable":{
  "mnemonics":["lui","lw","lui","c.or","sw","c.jr"],
  "operands":["a4, 0x60033","a5, 0x84(a4)","a3, 0x80000","a5, a3","a5, 0x84(a4)","ra"],
  "static_effect":"mem32[0x60033084] |= 0x80000000",
  "external_prior":"2025 Wi-Fi reverse engineering paper identifies address 0x60033084 as RX enable/disable; bit mechanism from actual ROM machine instructions"},
 "hal_mac_rx_disable":{
  "mnemonics":["lui","lw","lui","not","c.and","sw","c.jr"],
  "operands":["a3, 0x60033","a5, 0x84(a3)","a4, 0x80000","a4, a4","a5, a4","a5, 0x84(a3)","ra"],
  "static_effect":"mem32[0x60033084] &= ~0x80000000",
  "external_prior":"same published 2025 0x60033084"},
 "hal_mac_rx_set_base":{
  "mnemonics":["lui","sw","c.jr"],
  "operands":["a5, 0x60033","a0, 0x88(a5)","ra"],
  "static_effect":"mem32[0x60033088] = a0",
  "external_prior":"2025 published 0x60033088 Wi-Fi RX DMA list base"},
 "hal_mac_interrupt_get_event":{
  "mnemonics":["lui","lw","c.jr"],
  "operands":["a5, 0x60034","a0, -0x3c4(a5)","ra"],
  "static_effect":"a0 = mem32[0x60033c3c]",
  "external_prior":"2025 published 0x60033c3c Wi-Fi interrupt reason"},
 "hal_mac_interrupt_clr_event":{
  "mnemonics":["lui","sw","c.jr"],
  "operands":["a5, 0x60034","a0, -0x3c0(a5)","ra"],
  "static_effect":"mem32[0x60033c40] = a0",
  "external_prior":"2025 published 0x60033c40 Wi-Fi interrupt clear"},
 "hal_beacon_ie_crc_get":{
  "mnemonics":["lui","lw","c.sw","c.jr"],
  "operands":["a5, 0x60033","a5, 0x2b0(a5)","a5, 0(a0)","ra"],
  "static_effect":"mem32[a0] = mem32[0x600332b0]",
  "external_prior":"no independently verified register label; function name is vendor ELF hypothesis"},
 "hal_beacon_ie_crc_set":{
  "mnemonics":["lui","sw","c.jr"],
  "operands":["a5, 0x60033","a0, 0x2b4(a5)","ra"],
  "static_effect":"mem32[0x600332b4] = a0",
  "external_prior":"no independently verified register label; function name is vendor ELF hypothesis"},
 "ets_efuse_ecc_en":{
  "mnemonics":["lui","lw","c.srli","c.andi","c.jr"],
  "operands":["a5, 0x60009","a0, -0x7c4(a5)","a0, 0xc","a0, 1","ra"],
  "static_effect":"a0 = (mem32[0x6000883c] >> 12) & 1",
  "external_prior":"Official ESP-IDF esp32c3 efuse_reg.h: EFUSE_RD_REPEAT_DATA3_REG base+0x3c; EFUSE_FLASH_ECC_EN bit12",
 }}
def check(sequence,case):
 return [(x["mnemonic"],x["operands"]) for x in sequence]==list(zip(case["mnemonics"],case["operands"]))
def negatives():
 ex=[{"mnemonic":m,"operands":op} for m,op in zip(CASE["hal_mac_rx_set_base"]["mnemonics"],CASE["hal_mac_rx_set_base"]["operands"])]
 assert check(ex,CASE["hal_mac_rx_set_base"])
 changed=copy.deepcopy(ex);changed[1]["operands"]="a0, 0x8c(a5)"
 assert not check(changed,CASE["hal_mac_rx_set_base"])
 changed=copy.deepcopy(ex);changed[1]["mnemonic"]="lw"
 assert not check(changed,CASE["hal_mac_rx_set_base"])
 return 2
def main():
 n=negatives()
 traces={r:json.loads((OUT/"candidate_full"/(r+".candidate_full.json")).read_text()) for r in REVS}
 results={}
 for name,case in CASE.items():
  witnessed={}
  for rev,allfunc in traces.items():
   fn=allfunc[name]
   if fn["status"]=="ABSENT_SYMBOL":continue
   if not fn["status"].startswith("FULL_BODY_VERIFIED"):raise RuntimeError("FUNCTION_NOT_VALIDATED:"+name+rev)
   if not check(fn["instruction_listing"],case):raise RuntimeError("MECHANISM_OPCODE_MISMATCH:"+name+rev)
   witnessed[rev]={"function_entry":fn["start"],"sha256":fn["sha256"],"instructions":fn["instruction_listing"]}
  if not witnessed:raise RuntimeError("NO_ELF_FUNCTION_WITNESS:"+name)
  results[name]={"code_only_effect":case["static_effect"],"prior_comparison":case["external_prior"],
   "revisions":witnessed,"status":"EXACT_ISA_SEQUENCE_MATCH_NOT_RUNTIME_PROOF"}
 report={"schema":"ROM_INSTRUCTION_EFFECT_WITNESSES_V1","case_count":len(results),
  "negative_mutations_caught":n,"cases":results,
  "limitations":["Register effects under CPU ISA are proven from disassembly, hardware behaviors require silicon measurements",
   "Attribution of peripheral names from published paper is corroboration, not proof of novelty",
   "No claims about execution in normal firmware control flow"]}
 p=OUT/"candidate_full"/"mechanism_witnesses.json";p.write_text(json.dumps(report,indent=2)+"\n")
 print("ROM_MECHANISM_WITNESSES",json.dumps({"cases":len(results),"negative_controls":n,
  "names":sorted(results)},sort_keys=True))
if __name__=="__main__":main()
