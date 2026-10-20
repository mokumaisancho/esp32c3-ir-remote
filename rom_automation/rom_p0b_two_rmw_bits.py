#!/usr/bin/env python3
"""ROM-001: conservative *machine-byte* RMW interpretation for two pinned MMIO sites.

This is exact local instruction semantics, not hardware bitfield meaning.
All seven/three instructions must occur at the pinned PCs; unmodeled
intervening instructions may not write tracked GPRs. Changed bytes FAIL.
"""
import argparse,json,pathlib
from decision_gate import ROM_SHA,require
from rom_rvc_register_effects import rvc_effect,signed

CASE0=[0x4003ba76,0x4003ba7a,0x4003ba7c,0x4003ba7e,
       0x4003ba80,0x4003ba82,0x4003ba86,0x4003ba88]
CASE1=[0x40045474,0x40045478,0x4004547c]

def decode32(raw):
 require(len(raw)==4,"EXPECTED_32BIT_INSTRUCTION")
 w=int.from_bytes(raw,"little");opc=w&127;rd=(w>>7)&31;rs1=(w>>15)&31;funct3=(w>>12)&7
 if opc==3 and funct3==2:return {"op":"lw","rd":rd,"rs1":rs1,"imm":signed((w>>20)&4095,12)}
 if opc==0x23 and funct3==2:
  return {"op":"sw","rs2":(w>>20)&31,"rs1":rs1,
    "imm":signed((((w>>25)&127)<<5)|((w>>7)&31),12)}
 if opc==0x13 and funct3 in (0,6):
  return {"op":"addi" if funct3==0 else "ori","rd":rd,"rs1":rs1,
    "imm":signed((w>>20)&4095,12)}
 return {"op":"unsupported"}

def decode_c_alu(raw):
 require(len(raw)==2,"EXPECTED_C_ALU_16BIT")
 w=int.from_bytes(raw,"little")
 if (w&3)!=1 or ((w>>13)&7)!=4 or ((w>>10)&3)!=3 or ((w>>12)&1):
  return {"op":"unsupported"}
 sub=(w>>5)&3
 return {"op":"c.or" if sub==2 else "c.and" if sub==3 else "unsupported",
    "rd":8+((w>>7)&7),"rs2":8+((w>>2)&7)}

def at(window,pc):
 matches=[x for x in window if int(x["pc"],16)==pc]
 require(len(matches)==1,"MISSING_EXACT_INSTRUCTION_PC")
 return bytes.fromhex(matches[0]["raw_machine_bytes"])

def verify_sequence(window,pcs):
 xs=[at(window,pc) for pc in pcs]
 require(all(p+len(x)==q for p,x,q in zip(pcs,xs,pcs[1:])),
         "GAPPED_OR_CONTROL_FLOW_INSERTED_IN_RMW_SEQUENCE")
 return xs

def evaluate_one(row):
 address=int(row["address"],16)
 if address==0x600061c4:
  require(row["revision"]=="esp32c3_rev0_rom.elf","REV0_MISMATCH")
  w=verify_sequence(row["nearby_machine_instruction_window"],CASE0)
  load=decode32(w[0]);require(load["op"]=="lw" and load["rd"]==15,"RF_LW_SHAPE")
  first=rvc_effect(w[1]);require(first["kind"]=="ASSIGN_IMM" and first["rd"]==14,"RF_MASK_CONST_ORIGIN")
  preserve=rvc_effect(w[2]);require(preserve["kind"]=="WRITE_UNKNOWN" and preserve["rd"]==1,
    "RF_ALLOWED_LWSP_ONLY_RA")
  mix1=decode_c_alu(w[3]);require(mix1=={"op":"c.and","rd":15,"rs2":14},"RF_AND_GPR_DATAFLOW")
  second=rvc_effect(w[4]);require(second["kind"]=="ASSIGN_IMM" and second["rd"]==14,"RF_CONSTANT_BUILDER")
  add=decode32(w[5]);require(add["op"]=="addi" and add["rd"]==add["rs1"]==14,
    "RF_ADDI_SOURCE_GPR")
  mix2=decode_c_alu(w[6]);require(mix2=={"op":"c.or","rd":15,"rs2":14},"RF_OR_GPR_DATAFLOW")
  store=decode32(w[7])
  require(store["op"]=="sw" and store["rs2"]==load["rd"] and store["rs1"]==load["rs1"] and
    store["imm"]==load["imm"],"RF_WRITEBACK_MUST_SAME_ADDRESS")
  keep=first["value"];set_bits=(second["value"]+add["imm"])&0xffffffff
  require(keep&set_bits==0,"OVERLAPPING_REPLACE_MASK_NOT_EXPECTED")
  return {"revision":row["revision"],"address":row["address"],
    "read_machine_pc":row["machine_access_pc"],"write_machine_pc":hex(CASE0[-1]),
    "operation":"(OLD & MASK) | CONST","keep_mask":hex(keep),"constant_or":hex(set_bits),
    "symbolic_result":"(OLD & "+hex(keep)+") | "+hex(set_bits),
    "witnesses":[{"pc":hex(pc),"raw_bytes":b.hex()} for pc,b in zip(CASE0,w)],
    "read_modify_write_static_instruction_semantics_verified":True,
    "register_field_meaning_independently_verified":False}
 if address==0x60033c00:
  require(row["revision"]=="esp32c3_rev101_rom.elf","REV101_MISMATCH")
  w=verify_sequence(row["nearby_machine_instruction_window"],CASE1)
  load=decode32(w[0]);imm=decode32(w[1]);store=decode32(w[2])
  require(load["op"]=="lw" and imm["op"]=="ori" and
    load["rd"]==imm["rd"]==imm["rs1"]==store.get("rs2") and
    store["op"]=="sw" and store["rs1"]==load["rs1"] and
    store["imm"]==load["imm"],"WIFI_RMW_REGISTER_OR_ADDRESS_MISMATCH")
  return {"revision":row["revision"],"address":row["address"],
    "read_machine_pc":row["machine_access_pc"],"write_machine_pc":hex(CASE1[-1]),
    "operation":"OLD | CONST","constant_or":hex(imm["imm"]&0xffffffff),
    "symbolic_result":"OLD | "+hex(imm["imm"]&0xffffffff),
    "witnesses":[{"pc":hex(pc),"raw_bytes":b.hex()} for pc,b in zip(CASE1,w)],
    "read_modify_write_static_instruction_semantics_verified":True,
    "register_field_meaning_independently_verified":False}
 raise RuntimeError("NOT_ONE_OF_TWO_PINNED_MMIO_LOCATIONS")

def evaluate(source):
 require(source["schema"]=="ROM001_P0B_TWO_PINNED_MACHINE_CALLSITE_CONTEXT_V1" and
   source["ROM_sha256"]==ROM_SHA,"PINNED_MACHINE_WINDOW_SOURCE")
 rows=source["two_reviewed_callsite_windows"]
 require(len(rows)==2 and {x["address"] for x in rows}==
   {"0x600061c4","0x60033c00"},"TWO_CASE_ID_DRIFT")
 return {"schema":"ROM001_P0B_TWO_EXACT_RMW_BIT_EXPRESSIONS_V1",
  "original_issue_id":"ESP32C3-ROM-001",
  "source_ROM_SHA256":ROM_SHA,
  "cases":[evaluate_one(x) for x in rows],
  "new_hardware_function_software_independently_verified":False,
  "device_experiment_count":0,
  "important_limitations":["Static exact machine arithmetic is NOT independently observed RF/WiFi silicon register behavior.",
   "Local code is conditional on real runtime path and not guaranteed to execute.",
   "Exact internal register bitfield name or vendor semantics still unverified."]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--context",type=pathlib.Path,required=True)
 p.add_argument("--out",type=pathlib.Path,required=True)
 a=p.parse_args();r=evaluate(json.loads(a.context.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_P0B_TWO_RMW",json.dumps([{k:v[k] for k in ("address","symbolic_result",
   "read_modify_write_static_instruction_semantics_verified")}
   for v in r["cases"]],sort_keys=True))
if __name__=="__main__":main()
