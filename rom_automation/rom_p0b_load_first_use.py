#!/usr/bin/env python3
"""ROM-001 P0-B: fail-closed bounded syntactic consumer of exact MMIO load result.

Tracks only the first linear use of rd within a short validated opcode window.
Any branch, indirect call, unknown compressed byte or potential register alias
ends analysis. Not a CFG path, no hardware behavior inference.
"""
import argparse,json,pathlib
from decision_gate import ROM_SHA,require
from rom_rvc_register_effects import rvc_effect
from rom_p0b_two_rmw_bits import decode_c_alu

def decode_consumer(raw,register):
 b=bytes.fromhex(raw)
 if len(b)==2:
  # Reuse independently tested c.and / c.or decoder from the exact ROM
  # read-modify-write proof. These ops READ rd before writing it.
  alu=decode_c_alu(b)
  if alu["op"] in ("c.and","c.or"):
   if alu["rd"]==register:
    return {"status":"READ_AND_WRITE_FOR_RVC_ALU","opcode":alu["op"],
            "reads_old_value":True,"source_reg":alu["rs2"]}
   if alu["rs2"]==register:
    return {"status":"READ_FOR_RVC_ALU","opcode":alu["op"],
            "reads_old_value":True,"destination_reg":alu["rd"]}
   return {"status":"NO_TARGET_REG_EFFECT","opcode":alu["op"]}
  x=rvc_effect(b);k=x["kind"]
  if k=="UNKNOWN" or k=="CONTROL":
   return {"status":"UNKNOWN_OR_CONTROL","detail":x}
  if k=="PRESERVE":
   return {"status":"UNKNOWN_MEMORY_CONSUMPTION" if x.get("may_write_memory")
          else "NO_REG_EFFECT","detail":x}
  if x.get("rd")==register:
   return {"status":"READ_AND_WRITE" if k=="ADD_IMM" else "OVERWRITES",
           "detail":x}
  return {"status":"NO_TARGET_REG_EFFECT","detail":x}
 if len(b)!=4:return {"status":"BAD_INSTRUCTION_LENGTH"}
 w=int.from_bytes(b,"little");op=w&127;rd=(w>>7)&31
 rs1=(w>>15)&31;rs2=(w>>20)&31;funct3=(w>>12)&7
 if op in (0x63,0x67,0x6f,0x73,0x0f):
  # Branch/control barrier; branch may use read register.
  uses=(op==0x63 and register in (rs1,rs2)) or (op==0x67 and register==rs1)
  return {"status":"CONTROL_USING_LOADED_REG" if uses else "CONTROL_BARRIER",
    "raw_opcode":hex(op)}
 if op==0x23: 
  role="BASE" if rs1==register else "STORED_VALUE" if rs2==register else "NONE"
  return {"status":"STORE_USING_LOADED_REG" if role!="NONE" else "NO_TARGET_REG_EFFECT",
          "usage_role":role,"funct3":funct3}
 if op in (0x13,0x03):
  if rs1==register:
   return {"status":"READ_FOR_ALU" if op==0x13 else "READ_FOR_MEMORY_ADDRESS",
    "funct3":funct3,"immediate":((w>>20)^0x800)-0x800}
  if rd==register:return {"status":"OVERWRITES","funct3":funct3}
  return {"status":"NO_TARGET_REG_EFFECT"}
 if op in (0x33,0x2f):
  if rs1==register or rs2==register:
   return {"status":"READ_FOR_REG_ARITH_OR_ATOMIC","funct3":funct3}
  if rd==register:return {"status":"OVERWRITES"}
  return {"status":"NO_TARGET_REG_EFFECT"}
 if op in (0x37,0x17):
  return {"status":"OVERWRITES" if rd==register else "NO_TARGET_REG_EFFECT"}
 return {"status":"UNKNOWN_OPCODE","raw_opcode":hex(op)}

def analyze(report):
 require(report.get("schema")=="ROM001_P0B_TWO_PINNED_MACHINE_CALLSITE_CONTEXT_V1"
         and report.get("ROM_sha256")==ROM_SHA,"INPUT_SOURCE_MISMATCH")
 rows=report["two_reviewed_callsite_windows"]
 require(len(rows)==2,"TWO_MACHINE_SITES_REQUIRED")
 results=[]
 for item in rows:
  reg=item["destination_register_index"]
  require(1<=reg<=31,"BAD_MMIO_LOAD_DESTINATION")
  read_pc=int(item["machine_access_pc"],16)
  seen=[];started=False;prev_end=read_pc+4
  for x in item["nearby_machine_instruction_window"]:
   pc=int(x["pc"],16)
   if pc<=read_pc:continue
   if pc!=prev_end:
    seen.append({"pc":hex(pc),"classification":"DISCONTIGUOUS_DECODE_STOP"});break
   decision=decode_consumer(x["raw_machine_bytes"],reg)
   seen.append({"pc":hex(pc),"machine_bytes":x["raw_machine_bytes"],
      "instruction_mnemonic_for_display":x["mnemonic"],**decision})
   prev_end=pc+x["size"]
   if decision["status"] not in ("NO_REG_EFFECT","NO_TARGET_REG_EFFECT"):break
   if len(seen)>=12:break
  first=seen[-1] if seen else None
  results.append({"revision":item["revision"],"function":item["function"],
   "rom_read_address":item["address"],"rom_load_pc":item["machine_access_pc"],
   "loaded_register":reg,"number_of_linear_steps_checked":len(seen),
   "first_nontrivial_or_unknown":first,"linear_machine_provenance":seen,
   "branch_execution_confirmed":False,"bitfield_semantics_confirmed":False,
   "new_hardware_feature_proven":False})
 return {"schema":"ROM001_P0B_TWO_MMIO_LOAD_FIRST_SYNTAX_USE_V1",
  "original_issue_id":"ESP32C3-ROM-001","ROM_SHA256":ROM_SHA,
  "per_read_context":results,
  "uncertainties":["Bounded linear-next instruction sequence, not reachability-proven CFG.",
  "A syntactic use of loaded bits is not the hardware function of the address.",
  "Memory dependencies, vector control and unknown ISA ops stop analysis."],
  "independent_chip_behavior_proven":0}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--context",required=True,type=pathlib.Path)
 p.add_argument("--out",required=True,type=pathlib.Path)
 a=p.parse_args();r=analyze(json.loads(a.context.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
 print("ROM_P0B_TWO_LOAD_USE",json.dumps([{
  "function":x["function"],"reg":x["loaded_register"],
  "first_kind":x["first_nontrivial_or_unknown"]["status"] if x["first_nontrivial_or_unknown"] else "NO_FOLLOWING_CODE",
  "steps":x["number_of_linear_steps_checked"]}
  for x in r["per_read_context"]],sort_keys=True))
if __name__=="__main__":main()
