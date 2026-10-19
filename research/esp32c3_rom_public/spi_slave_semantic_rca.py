#!/usr/bin/env python3
"""Verify SPI ROM download mailbox, DMA lengths, security guards, and poll loops.
Inputs: full machine traces independently validated by GNU and Capstone.
Does not execute an SPI device, bypass security, or prove a novel API.
"""
import json,pathlib
R=pathlib.Path(__file__).resolve().parent;OUT=R/"output"
REV=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
EXPECTED={
 0x18:("lui","a5, 0x60024"),0x1c:("lw","a4, 0xa4(a5)"),
 0x20:("addi","a5, zero, 0x55"),0x24:("beq","a4, a5, 0x62"),
 0x114:("lw","a5, 0x9c(a4)"),0x118:("c.srli","a5, 2"),
 0x11a:("and","a5, a5, s3"),0x11e:("c.bnez","a5, -0xa"),
 0x1b0:("lw","a5, 0xa0(a3)"),0x1b4:("c.srli","a5, 2"),
 0x1b6:("c.and","a5, a4"),0x1b8:("c.bnez","a5, -8"),
}
def require(ok,message):
 if not ok:raise RuntimeError("SPI_DOWNLOAD_FAILED:"+message)
def check_trace(name,func):
 require(func.get("status","").startswith("FULL_BODY_VERIFIED"),"BODY_NOT_VERIFIED:"+name)
 require(func["bytes"]==500,"SIZE_DIFFERENCE:"+name)
 start=int(func["start"],16)
 byoff={int(x["pc"],16)-start:x for x in func["instruction_listing"]}
 for off,expected in EXPECTED.items():
  found=byoff.get(off)
  require(found and (found["mnemonic"],found["operands"])==expected,"INSTRUCTION_MISMATCH:"+name+":"+hex(off))
 for pc_off,rel in ((0x11e,-10),(0x1b8,-8)):
  ins=byoff[pc_off]
  require(int(ins["operands"].split(", ")[-1],0)==rel,"BAD_POLL_BRANCH:"+name)
  require(pc_off+rel in byoff and byoff[pc_off+rel]["mnemonic"]=="lw","POLL_MUST_RELOAD_MMIO:"+name)
 at=func["instruction_listing"]
 efuse=[x for x in func["direct_transfers"] if "ets_efuse_download_modes_disabled" in x.get("exact_target_elf_names",[])]
 targets={x for row in func["direct_transfers"] for x in row.get("exact_target_elf_names",[])}
 expected_calls=("spi_slave_rom_init","spi_slave_rom_rxdma_load","spi_slave_rom_txdma_load",
   "MemDwnLdStartMsgProc","MemDwnLdStopReqMsgProc","MemPacketSendReqMsgProc",
   "UartRegWriteProc","UartRegReadProc")
 require(len(efuse)==2,"EFUSE_GUARDS_NOT_TWICE:"+name)
 require(set(expected_calls)<=targets,"COMMAND_DISPATCH_INCOMPLETE:"+name)
 # A Ghidra variable reused across iterations must not replace an actual LW.
 for off in (0x114,0x1b0):
  require(byoff[off]["mnemonic"]=="lw","POLL_RELOAD_MISSING:"+name)
 # Exact firmware security gate and W3 terminal marker are reflected in machine ISA.
 require(any(x["mnemonic"]=="sw" and x["operands"]=="a4, 0xa4(a5)" for x in at),"W3_COMPLETION_MARKER_MISSING")
 return {"revision":name,"elf_entry":func["start"],"machine_sha256":func["sha256"],
   "verified_bytes":func["bytes"],"security_checks":efuse,
   "verified_dispatch_calls":sorted(set(expected_calls)&targets),
   "rx_poll":[byoff[x] for x in (0x114,0x118,0x11a,0x11e)],
   "tx_poll":[byoff[x] for x in (0x1b0,0x1b4,0x1b6,0x1b8)],
   "registers":{"0x6002409c":"SPI_W1_REG(2)","0x600240a0":"SPI_W2_REG(2)",
      "0x600240a4":"SPI_W3_REG(2)"},
   "poll_semantics":"Read W1/W2 repeatedly, shift right 2 and mask with 0x0fffffff; stay while bits[29:2] are nonzero",
   "ghidra_discrepancy":"Ghidra C prints tautologically-true loop predicates; each actual loop has a fresh LW from peripheral register"}
def main():
 rows=[]
 for rev in REV:
  func=json.loads((OUT/"candidate_full"/(rev+".candidate_full.json")).read_text())["spi_slave_download"]
  rows.append(check_trace(rev,func))
 bad=json.loads(json.dumps(json.loads((OUT/"candidate_full"/(REV[2]+".candidate_full.json")).read_text())["spi_slave_download"]))
 item=next(x for x in bad["instruction_listing"] if int(x["pc"],16)-int(bad["start"],16)==0x114)
 item["mnemonic"]="addi"
 try:check_trace("MUTATED",bad)
 except RuntimeError:pass
 else:raise RuntimeError("NEGATIVE_MUTATION_NOT_CAUGHT")
 record={"schema":"ESP32C3_SPI_DOWNLOAD_BRANCH_SEMANTICS_V1","original_issue_id":"ESP32C3-ROM-001",
    "revision_count":len(rows),"pass":True,"negative_mutations_detected":1,"evidence":rows,
    "official_register_header":"https://github.com/espressif/esp-idf/blob/1c42e514c90ae621af33bde3b6ad3dac22edcbfd/components/soc/esp32c3/register/soc/spi_reg.h",
    "official_base_header":"https://github.com/espressif/esp-idf/blob/1c42e514c90ae621af33bde3b6ad3dac22edcbfd/components/soc/esp32c3/register/soc/reg_base.h",
    "security":"Firmware checks ets_efuse_download_modes_disabled at two sites; no bypass claimed or tested",
    "novelty":"Existing ROM SPI download function; exact mailbox flow is analyzed, but no new API proven",
    "limitations":["No physical SPI peripheral or status clear observed","Cannot infer handshake actors from static CPU instructions",
      "Decompiler C does not capture peripheral changes between volatile reads"]}
 p=OUT/"semantics";p.mkdir(exist_ok=True)
 (p/"spi_slave_download_mechanism.json").write_text(json.dumps(record,indent=2)+"\n")
 print("SPI_DOWNLOAD_SEMANTIC_RCA",json.dumps({k:v for k,v in record.items() if k!="evidence"},sort_keys=True))
 for x in rows:print("SPI_RX_TX_POLL_WITNESS",x["revision"],x["elf_entry"],
  [(z["pc"],z["mnemonic"],z["operands"]) for z in x["rx_poll"]+x["tx_poll"]])
if __name__=="__main__":main()
