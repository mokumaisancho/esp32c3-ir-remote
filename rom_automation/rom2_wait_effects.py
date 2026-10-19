#!/usr/bin/env python3
"""ROM-001: raw RV32IC busy-wait proof with verified external tail-call boundary.

Only esp32c3_rev101_rom.elf includes this original-88 function. Compare raw
instruction-byte executor with separate Ghidra reference and bounded cases.
"""
import argparse,copy,hashlib,json,pathlib,zipfile
from decision_gate import REVS,MACHINE_SHA,GHIDRA_SHA,require,sha
from rom_candidate_cfg import control_target,signed

NAMES=("rom2_wait_hw_freq_busy",)
REV="esp32c3_rev101_rom.elf"
BUSY_REGISTER=0x6000e168
EXPECTED_TAIL=0x40047e8e
REGISTER_INDEX={"zero":0,"a0":10,"a3":13,"a4":14,"a5":15}
MASK=0xffffffff

def execute_bytes(rows,busy_read_sequence,maximum_steps=15000):
 bypc={int(i["pc"],16):i for i in rows}
 require(len(bypc)==len(rows)==10,"ROM2_BYTE_LIST_LENGTH")
 pc=min(bypc);r=[0]*32;reads=0;edges=set()
 sequence=list(busy_read_sequence)
 for step in range(maximum_steps):
  require(pc in bypc,"ROM2_PC_ESCAPED:"+hex(pc))
  ins=bypc[pc];raw=bytes.fromhex(ins["word"]);bits=int.from_bytes(raw,"little")
  length=len(raw);op=ins["mnemonic"];nxt=pc+length
  # Every execute and branch immediate is independently decoded from BYTES.
  if op=="c.li":
   rd=bits>>7&31
   imm=signed(((bits>>12&1)<<5)|((bits>>2)&31),6)
   r[rd]=imm&MASK
  elif op=="lui":
   rd=bits>>7&31
   r[rd]=bits&0xfffff000
  elif op=="lw":
   rd=bits>>7&31;rs1=bits>>15&31
   imm=signed(bits>>20,12);address=(r[rs1]+imm)&MASK
   require(address==BUSY_REGISTER,"ROM2_UNEXPECTED_MMIO:"+hex(address))
   require(reads<len(sequence),"ROM2_MMIO_STREAM_EXHAUSTED")
   r[rd]=sequence[reads]&MASK;reads+=1
  elif op=="addi":
   rd=bits>>7&31;rs1=bits>>15&31
   r[rd]=(r[rs1]+signed(bits>>20,12))&MASK
  elif op in ("bltz","c.beqz"):
   kind,target=control_target(ins,pc)
   require(kind=="BRANCH","ROM2_BRANCH_ENCODING")
   if op=="bltz":
    rs1=bits>>15&31
    condition=signed(r[rs1],32)<0
   else:
    rs1=((bits>>7)&7)+8
    condition=r[rs1]==0
   edges.add((hex(pc),condition))
   if condition:nxt=target
  elif op in ("c.j","j"):
   kind,target=control_target(ins,pc)
   require(kind=="JUMP","ROM2_JUMP_ENCODING")
   if target not in bypc:
    require(target==EXPECTED_TAIL,"UNEXPECTED_TAIL_TARGET:"+hex(target))
    require(op=="j" and r[10]==50,"TAIL_DELAY_ARGUMENT_NOT_50")
    return {"event":"EXTERNAL_TAIL_CALL_UNVERIFIED","tail_target":hex(target),
     "tail_argument":r[10],"busy_reads":reads,"branch_edges":sorted(edges),
     "steps":step+1,"silicon_verified":False}
   nxt=target
  elif op=="c.jr":
   kind,_=control_target(ins,pc)
   require(kind=="RETURN","ROM2_NOT_RETURN")
   return {"event":"RETURN_WITHOUT_EXTERNAL_CALL","tail_target":None,
    "tail_argument":None,"busy_reads":reads,"branch_edges":sorted(edges),
    "steps":step+1,"silicon_verified":False}
  else:raise RuntimeError("ROM2_UNSUPPORTED_OPCODE:"+op)
  pc=nxt
 raise RuntimeError("ROM2_BOUNDED_STEP_LIMIT")

def reference(scans):
 """Hand-authored expectation based on separate Ghidra pseudocode, not oracle."""
 require(bool(scans),"EMPTY_SCANS")
 first_nonbusy=next((i for i,x in enumerate(scans) if (x&0x80000000)==0),None)
 require(first_nonbusy is not None,"UNBOUNDED_BUSY_SCENARIO")
 return {
  "event":"RETURN_WITHOUT_EXTERNAL_CALL" if first_nonbusy==0 else "EXTERNAL_TAIL_CALL_UNVERIFIED",
  "tail_target":None if first_nonbusy==0 else hex(EXPECTED_TAIL),
  "tail_argument":None if first_nonbusy==0 else 50,
  "busy_reads":first_nonbusy+1
 }

def cases():
 for n in (0,1,2,3,5,8,13,32,99,127,255,999,1000):
  yield n,([0x80000000]*n)+[0x7fffffff]
 for n in (0,1,2,3,7,17,127):
  yield n,([0xffffffff]*n)+[0]
 # no reference oracle for volatile MMIO during a single read; restricted snapshots

def compare(rows,scans):
 o=execute_bytes(rows,scans)
 expected=reference(scans)
 for k,v in expected.items():
  require(o[k]==v,"ROM2_RAW_ISA_DIFF:"+k)
 return o

def mutation_tests(rows):
 # Mutate genuine 4-byte encoded immediate, NOT mnemonic operand text.
 def altered(source,matching,bit):
  seq=copy.deepcopy(source)
  f=[x for x in seq if x["mnemonic"]==matching]
  require(len(f)==1,"ROM2_MUTATION_NOT_UNIQUE:"+matching)
  raw=bytearray(bytes.fromhex(f[0]["word"]));raw[2]^=bit
  f[0]["word"]=raw.hex()
  return seq
 detected=0
 for op in ("addi","j"):
  changed=altered(rows,op,1)
  try:compare(changed,[0x80000000,0])
  except RuntimeError as ex:
   require("TAIL_DELAY_ARGUMENT_NOT_50" in str(ex) or
           "UNEXPECTED_TAIL_TARGET" in str(ex),"MUTATION_WRONG_FAILURE")
   detected+=1
  else:raise RuntimeError("BINARY_MUTATION_UNDETECTED:"+op)
 return detected

def evaluate(machine,ghidra):
 require(sha(machine)==MACHINE_SHA,"MACHINE_SOURCE_HASH")
 require(sha(ghidra)==GHIDRA_SHA,"GHIDRA_SOURCE_HASH")
 with zipfile.ZipFile(machine) as zm,zipfile.ZipFile(ghidra) as zg:
  body={r:json.loads(zm.read("output/candidate_full/"+r+".candidate_full.json"))[NAMES[0]] for r in REVS}
  pseudocode={x["name"]:x for x in json.loads(zg.read("output/ghidra/"+REV+".decompiled.json"))}
 require(body[REVS[0]]["status"]=="ABSENT_SYMBOL" and
         body[REVS[2]]["status"]=="ABSENT_SYMBOL","ROM2_REVISION_PRESENCE_DRIFT")
 b=body[REV]
 require(b["status"].startswith("FULL_BODY_VERIFIED"),"ROM2_BODY_NOT_VERIFIED")
 f=pseudocode[NAMES[0]]
 require(f["decompiler_status"]=="DECOMPILED","ROM2_GHIDRA_NOT_DECOMPILED")
 require(int(f["requested_address"],16)==int(b["start"],16),"ROM2_REV_ENTRY_MISMATCH")
 for tok in ("6000e168","ets_delay_us(0x32)","while"):
  require(tok in f["pseudocode"],"ROM2_GHIDRA_SEMANTIC_MISSING:"+tok)
 rows=b["instruction_listing"];coverage=set();vectors=0
 for n,scans in cases():
  actual=compare(rows,scans);coverage.update(map(tuple,actual["branch_edges"]));vectors+=1
 for pc in ("0x4003e4f2","0x4003e4f6"):
  require((pc,True) in coverage and (pc,False) in coverage,"ROM2_BRANCH_SIDE_MISSING:"+pc)
 require(mutation_tests(rows)==2,"ROM2_BINARY_MUTATIONS_NOT_CAUGHT")
 try:execute_bytes(rows,[0x80000000]*3500)
 except RuntimeError as err:
  require("ROM2_BOUNDED_STEP_LIMIT" in str(err),"ROM2_UNBOUNDED_WRONG_FAILURE")
 else:raise RuntimeError("ROM2_INFINITE_BUSY_INCORRECTLY_TERMINATED")
 return {
  "schema":"ESP32C3_ROM2_RAWBYTE_BOUNDED_POLL_V1",
  "original_issue_id":"ESP32C3-ROM-001",
  "name":NAMES[0],"revision_bodies":1,"vectors":vectors,
  "negative_raw_machine_byte_mutations":2,"unbounded_busy_limit_detected":True,
  "conditional_branch_edges_covered":4,"external_tail_target":hex(EXPECTED_TAIL),
  "external_delay_callee_verified":False,
  "no_silicon_execution":True,"independent_semantic_review_approved":False,
  "no_novel_API_claim":True,
  "machine_sha256":MACHINE_SHA,"ghidra_sha256":GHIDRA_SHA,
  "revision_specific_code_sha256":b["sha256"],
  "ghidra_pseudocode_sha256":hashlib.sha256(f["pseudocode"].encode()).hexdigest(),
  "limitations":["Actual MMIO busy bit dynamics unmeasured; simulation terminates by provided mock stream.",
   "External delay tail-call is decoded as 0x40047e8e; callee behavior not executed.",
   "Raw byte mutation is genuine input change, but expected result still informed by same ROM decompilation.",
   "No authorized physical silicon or independent reviewer involved."]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--machine",required=True,type=pathlib.Path)
 p.add_argument("--ghidra",required=True,type=pathlib.Path)
 p.add_argument("--out",required=True,type=pathlib.Path)
 a=p.parse_args();r=evaluate(a.machine,a.ghidra)
 a.out.parent.mkdir(exist_ok=True,parents=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM2_BOUNDED_BYTE_SEMANTICS",json.dumps({"revisions":1,"vectors":r["vectors"],
  "negative_raw_byte_mutations":r["negative_raw_machine_byte_mutations"],
  "tail":r["external_tail_target"],"silicon":False},sort_keys=True))
if __name__=="__main__":main()
