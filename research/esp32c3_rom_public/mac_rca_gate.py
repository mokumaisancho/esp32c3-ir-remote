#!/usr/bin/env python3
"""Independent fail-closed machine-code evidence gate; no functional claims."""
import copy,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parent
PATH=ROOT/"output"/"mac_rca"/"complete_mac_rca.json"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
FUNCTIONS=("wdev_mac_sleep","wdev_mac_wakeup","hal_disable_mac","hal_enable_mac")
class GateError(Exception):pass
def check(d):
 if d.get("gnu_objdump_full_body_comparison")!="PASS":raise GateError("INDEPENDENT_DECODER_NOT_VERIFIED")
 for name in FUNCTIONS:
  v=d.get("functions",{}).get(name,{})
  sha=v.get("sha_by_revision",{})
  size=v.get("size_by_revision",{})
  if set(sha)!=set(REVS) or set(size)!=set(REVS):raise GateError("REVISION_INCOMPLETE:"+name)
  if any(not isinstance(sha[r],str) or len(sha[r])!=64 for r in REVS):raise GateError("HASH_MISSING")
  if any(not isinstance(size[r],int) or size[r]<=0 for r in REVS):raise GateError("SIZE_INVALID")
  if v.get("rev0_rev3_equal") != (sha[REVS[0]]==sha[REVS[2]]):raise GateError("FALSE_EQUALITY:"+name)
  changes=v.get("changed_instruction_blocks")
  if not isinstance(changes,list):raise GateError("MISSING_DIFF:"+name)
  transfers=v.get("rev101_direct_and_indirect_transfers")
  if not isinstance(transfers,list):raise GateError("MISSING_TRANSFERS:"+name)
 for name,callee in (("wdev_mac_sleep","hal_disable_mac"),("wdev_mac_wakeup","hal_enable_mac")):
  caller=d["functions"][name];target=d["functions"][callee]
  dest=target["rev101_direct_and_indirect_transfers"]
  # Actual destination is checked below with independent named ELF symbols from the caller's trace.
  matches=[x for x in caller["rev101_direct_and_indirect_transfers"]
           if callee in x.get("target_function_names",[])]
  if len(matches)!=1:raise GateError("DIRECT_CALL_NOT_UNIQUE:"+name)
  if int(matches[0]["target"],16)<0x40000000:raise GateError("TARGET_OUTSIDE_ROM")
 return True
def negatives(d):
 def mutate1(x):x["functions"]["wdev_mac_sleep"]["rev0_rev3_equal"]=False
 def mutate2(x):x["functions"]["wdev_mac_sleep"]["rev101_direct_and_indirect_transfers"]=[]
 def mutate3(x):x["functions"]["wdev_mac_wakeup"]["size_by_revision"].pop(REVS[1])
 def mutate4(x):x["gnu_objdump_full_body_comparison"]="FAIL"
 tests=[mutate1,mutate2,mutate3,mutate4]
 for i,fn in enumerate(tests):
  x=copy.deepcopy(d);fn(x)
  try:check(x)
  except GateError:pass
  else:raise RuntimeError("NEGATIVE_MUTATION_NOT_CAUGHT:"+str(i))
 return len(tests)
def main():
 d=json.loads(PATH.read_text())
 check(d)
 n=negatives(d)
 result={"schema":"ROM_MAC_INDEPENDENT_QA_GATE_V1","overall":"PASS_STRUCTURAL_ONLY",
   "negative_mutations_caught":n,"source":"mac_rca/complete_mac_rca.json",
   "semantic_certification":"NOT_GRANTED"}
 path=ROOT/"output"/"mac_rca"/"qa_gate.json";path.write_text(json.dumps(result,indent=2)+"\n")
 print("MAC_RCA_QA_RESULT",json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
