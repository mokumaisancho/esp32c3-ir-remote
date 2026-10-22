#!/usr/bin/env python3
"""ROM-002: deterministic passive two-site C3 ROM RMW trace oracle.

Takes *already observed or synthetic* LOAD/STORE event pairs. It neither runs
the firmware nor attests where events came from, and it never accesses hardware.
The revision-specific expected RMW formulas come from separately pinned ROM
machine-byte proofs in rom_p0b_two_rmw_bits.py.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

SCHEMA="ROM002_MMIO_PAIR_TRACE_V1"
OUT_SCHEMA="ROM002_MMIO_TRACE_VERDICT_V1"
MASK=0xffffffff
MODELS={
 "rev0_fe": {
  "revision":"esp32c3_rev0_rom.elf",
  "function":"rom_phy_xpd_rf",
  "address":0x600061c4,
  "read_pc":0x4003ba76,
  "write_pc":0x4003ba88,
  "formula":"(OLD & 0xffff0000) | 0x00005555",
  "machine_proof":"rom_automation/rom_p0b_two_rmw_bits.py",
 },
 "rev101_wifi":{
  "revision":"esp32c3_rev101_rom.elf",
  "function":"wdev_mac_wakeup",
  "address":0x60033c00,
  "read_pc":0x40045474,
  "write_pc":0x4004547c,
  "formula":"OLD | 0x000000f0",
  "machine_proof":"rom_automation/rom_p0b_two_rmw_bits.py",
 }
}
HEX=re.compile(r"0x(?:0|[0-9a-fA-F]+)\Z")
ALLOWED_ORIGINS={"synthetic","emulator","silicon","other"}

def u32(value,field):
 """Accept canonical string-encoded addresses or 32-bit unsigned value samples."""
 if not isinstance(value,str) or not HEX.fullmatch(value):
  raise ValueError("MALFORMED_HEX:"+field)
 n=int(value,16)
 if n>MASK:raise ValueError("NOT_32_BIT:"+field)
 return n

def keys(obj,required,scope):
 if type(obj) is not dict or set(obj)!=set(required):
  raise ValueError("UNEXPECTED_FIELDS:"+scope)

def computed(case,old):
 if case=="rev0_fe":return ((old & 0xffff0000)|0x5555)&MASK
 if case=="rev101_wifi":return (old|0xf0)&MASK
 raise ValueError("UNKNOWN_CASE")

def classify(sample):
 keys(sample,("sample_id","case","events"),"SAMPLE")
 case=sample["case"]
 if type(case) is not str or case not in MODELS:
  raise ValueError("UNKNOWN_CASE")
 if type(sample["sample_id"]) is not str or not re.fullmatch(r"[A-Za-z0-9._-]{1,80}",sample["sample_id"]):
  raise ValueError("INVALID_SAMPLE_ID")
 cfg=MODELS[case]
 events=sample["events"]
 if type(events) is not list or len(events)!=2:
  raise ValueError("EXACTLY_ONE_READ_AND_WRITE_REQUIRED")
 expected_seq=(("read",cfg["read_pc"]),("write",cfg["write_pc"]))
 decoded=[]
 for i,event in enumerate(events):
  keys(event,("op","pc","address","value"),"EVENT")
  if event["op"]!=expected_seq[i][0]:
   raise ValueError("INVALID_EVENT_ORDER:"+sample["sample_id"])
  pc=u32(event["pc"],"pc")
  addr=u32(event["address"],"address")
  value=u32(event["value"],"value")
  if pc!=expected_seq[i][1]:raise ValueError("REVISION_OR_PC_MISMATCH:"+sample["sample_id"])
  if addr!=cfg["address"]:raise ValueError("ADDRESS_MISMATCH:"+sample["sample_id"])
  decoded.append(value)
 before,actual=decoded
 expected=computed(case,before)
 return {
  "sample_id":sample["sample_id"],"case":case,
  "revision":cfg["revision"],"function":cfg["function"],
  "register_address":hex(cfg["address"]),
  "read_pc":hex(cfg["read_pc"]),"write_pc":hex(cfg["write_pc"]),
  "old_value":hex(before),"expected_write":hex(expected),
  "actual_write":hex(actual),
  "matches_static_machine_model":actual==expected,
  "verdict":"TRACE_CONSISTENT_WITH_ROM_RMW" if actual==expected else "TRACE_CONTRADICTS_ROM_RMW",
  "formula":cfg["formula"],
  "physical_register_meaning_proven":False,
  "runtime_execution_source_attested":False,
 }

def audit(payload):
 keys(payload,("schema","source_kind","samples"),"ROOT")
 if payload["schema"]!=SCHEMA:raise ValueError("TRACE_SCHEMA_DRIFT")
 origin=payload["source_kind"]
 if type(origin) is not str or origin not in ALLOWED_ORIGINS:
  raise ValueError("UNKNOWN_ORIGIN_LABEL")
 rows=payload["samples"]
 if type(rows) is not list or not rows or len(rows)>100000:
  raise ValueError("SAMPLE_COUNT_OUT_OF_RANGE")
 matches=[];ids=set()
 for row in rows:
  r=classify(row)
  if r["sample_id"] in ids:raise ValueError("DUPLICATE_SAMPLE_ID")
  ids.add(r["sample_id"]);matches.append(r)
 mismatch=[x["sample_id"] for x in matches if not x["matches_static_machine_model"]]
 return {
  "schema":OUT_SCHEMA,"issue":"ROM-002",
  "input_source_kind_claimed":origin,"input_source_kind_independently_attested":False,
  "total_pairs":len(matches),"consistent_pairs":len(matches)-len(mismatch),
  "contradictory_pairs":len(mismatch),"contradictory_sample_ids":mismatch,
  "all_pairs_consistent_with_static_model":not bool(mismatch),
  "hardware_behavior_verified":False,"actual_emulator_execution_verified":False,
  "new_silicon_API_verified":False,
  "event_pair_results":matches,
  "limitations":[
   "Input source_kind is untrusted user-supplied metadata, not a verified device or emulator receipt.",
   "Passing input samples may be synthetic; no emulator firmware was booted by this tool.",
   "Checks only exact observed read-write pairs at pinned two ROM PCs, not the full containing function or all possible side effects.",
   "Does not establish meanings of RF or Wi-Fi bitfields, nor safe authorization to write them.",
   "ROM version and PC address must match selected model; third-party software may insert probes not represented here."
  ]
 }

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--trace",type=pathlib.Path,required=True)
 p.add_argument("--output",type=pathlib.Path,required=True)
 p.add_argument("--strict",action="store_true",help="Non-zero exit when a trace contradicts the static model")
 a=p.parse_args()
 raw=a.trace.read_bytes()
 result=audit(json.loads(raw))
 result["input_sha256"]=hashlib.sha256(raw).hexdigest()
 a.output.parent.mkdir(parents=True,exist_ok=True)
 a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
 print("ROM002_TRACE_VERDICT",json.dumps({
  "pairs":result["total_pairs"],
  "consistent":result["consistent_pairs"],
  "contradictions":result["contradictory_pairs"],
  "origin_attested":False,
  "hardware_verified":False
 },sort_keys=True))
 if a.strict and result["contradictory_pairs"]:
  return 2
 return 0

if __name__=="__main__":
 try:sys.exit(main())
 except (ValueError,KeyError,TypeError,json.JSONDecodeError) as error:
  print("ROM002_INVALID_INPUT",str(error),file=sys.stderr)
  sys.exit(3)
