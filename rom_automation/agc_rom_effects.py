#!/usr/bin/env python3
"""ROM-001 AGC per-revision MMIO effect witness: static only, no silicon write."""
import argparse,copy,hashlib,json,pathlib,random
from decision_gate import REVS,require,sha
from bounded_isa_effects import MASK,evidence,replay

NAMES=("rom_agc_reg_init",)
ADDRESSES=(0x6001c004,0x6001c02c,0x6001c0c4,0x6001c14c,0x6001c018,
 0x6001c104,0x6001c13c,0x6001c0a4,0x6001c038,0x6001c088,0x6001c024,
 0x6001c0a0,0x6001c094,0x6001c158,0x6001c05c,0x6001c118,0x6001c064,
 0x6001c114,0x6001c020,0x6001c01c,0x6001c0d0,0x6001c134)

def independent_register_equations(rev,old,a0,a1):
 """Manually specified net MMIO effects from pinned Ghidra C, NOT a silicon oracle.
 Ordered transient writes are NOT independently certified by Ghidra.
 """
 m=dict(old)
 def update(a,mask=MASK,add=0):m[a]=(m[a]&mask|add)&MASK
 def assign(a,val):m[a]=val&MASK
 if rev==REVS[0]:
  update(0x6001c004,0xfffeffff)
  assign(0x6001c02c,((a0&0xcd007f)<<8)|(m[0x6001c02c]&0x7f80ff)|0x32000000)
  for a,mask,val in (
   (0x6001c0c4,0xe7ffffff,0),(0x6001c14c,0xfffe00ff,0),
   (0x6001c018,0xfffffff8,4),(0x6001c104,0xffff7e00,0x1c8),
   (0x6001c13c,0xfe03ffff,0x1300000),(0x6001c038,0xffff7fff,0),
   (0x6001c088,0xffffff00,5),(0x6001c024,0xfffc01ff,0x34c00),
   (0x6001c0a0,0xfffffe00,0x1a6),(0x6001c094,0xedfffe03,0x131),
   (0x6001c158,0xfffffeff,0),(0x6001c05c,0xefffffff,0),
   (0x6001c118,0xffff00ff,0xcc00),(0x6001c020,0xfffffe00,0x1ea),
   (0x6001c01c,0xff00ffff,0x200000),(0x6001c0d0,0xfe01ffff,0xa00000)
  ):update(a,mask,val)
  assign(0x6001c0a4,((a1&0x7f)<<15)|(m[0x6001c0a4]&0xffc04000)|0x2346)
  assign(0x6001c064,0x3032030);assign(0x6001c114,0x3032030)
 elif rev in REVS[1:]:
  if rev==REVS[1]:
   assign(0x6001c13c,(((a0-3)*0x40000)&0x1fc0000)|(m[0x6001c13c]&0xfe03ffff))
   assign(0x6001c094,(((a0-3)*4)&0x1fc)|(m[0x6001c094]&0xfffffe03))
  else:
   update(0x6001c13c,0xfe03ffff,0x1300000)
   update(0x6001c094,0xfffffe03,0x124)
  assign(0x6001c0a4,(a1<<15)|0x2346)
  assign(0x6001c02c,((a0&0xcd007f)<<8)|(m[0x6001c02c]&0x7f80ff)|0x32000000)
  update(0x6001c05c,0xfff80000,3000)
  if rev==REVS[1]:update(0x6001c134,0xfffff00f,0xa60)
 else:raise RuntimeError("UNKNOWN_REV")
 return m

def vector(seed):
 rng=random.Random(seed);memory={a:rng.getrandbits(32) for a in ADDRESSES}
 values=(0,1,2,3,0xff,0xffffffff,rng.getrandbits(32))
 other=(0,1,2,3,0x80,0xffffffff,rng.getrandbits(32))
 return memory,values[seed%len(values)],other[seed%len(other)]

def case(rev,rows,seed):
 mem,a0,a1=vector(seed)
 got=replay(rows,mem,a0=a0,a1=a1)
 expected=independent_register_equations(rev,mem,a0,a1)
 require(got["memory"]==expected,"AGC_NET_EFFECT_DIFF:"+rev+":"+str(seed))
 require(not got["edges"],"AGC_UNEXPECTED_BRANCH")
 return got

def negative_test(rev,rows):
 # A syntactic-operand mutation checks sensitivity of the textual ISA replay.
 # This is not binary opcode mutation or an independent physical oracle.
 changed=copy.deepcopy(rows)
 specs={
  REVS[0]:("c.sw","a4, 4(a5)","a4, 8(a5)"),
  REVS[1]:("addi","a4, a0, -3","a4, a0, -4"),
  REVS[2]:("ori","a4, a4, 0x124","a4, a4, 0x125")}
 op,old,new=specs[rev]
 items=[x for x in changed if x["mnemonic"]==op and x["operands"]==old]
 require(len(items)==1,"AGC_MUTATION_NOT_UNIQUE")
 items[0]["operands"]=new
 for seed in (0,1,2,3,4,5,6):
  try:case(rev,changed,seed)
  except RuntimeError as error:
   require("AGC_NET_EFFECT_DIFF" in str(error),"AGC_MUTATION_WRONG_FAILURE")
   return True
 raise RuntimeError("AGC_MUTATION_ESCAPED:"+rev)

def evaluate(machine,ghidra):
 bodies,dec=evidence(machine,ghidra)
 result={};tested=0;negative=0
 for rev in REVS:
  b=bodies[rev][NAMES[0]]
  require(b["status"].startswith("FULL_BODY_VERIFIED"),"AGC_BODY_NOT_VERIFIED")
  f=dec[rev][NAMES[0]]
  require(f["decompiler_status"]=="DECOMPILED","AGC_GHIDRA_FAILED")
  require(int(f["requested_address"],16)==int(b["start"],16),"AGC_ELF_ENTRY_MISMATCH")
  for token in ("6001c02c","6001c0a4","param_1","param_2"):
   require(token in f["pseudocode"],"AGC_GHIDRA_SPEC_MISSING:"+token)
  rows=b["instruction_listing"]
  for seed in range(100):case(rev,rows,seed)
  require(negative_test(rev,rows),"AGC_NEGATIVE_NOT_DETECTED")
  tested+=100;negative+=1
  first=case(rev,rows,0)
  result[rev]={"function_entry":b["start"],"body_sha256":b["sha256"],
   "ghidra_sha256":hashlib.sha256(f["pseudocode"].encode()).hexdigest(),
   "vectors":100,"body_instructions":len(rows),"ordered_machine_store_count":len(first["writes"]),
   "negative_operand_mutation_caught":True,"net_register_equations_compared":True,
   "ordered_intermediate_writes_independent_oracle":False}
 return {"schema":"ROM_AGC_STATIC_NET_EFFECT_V1","original_issue_id":"ESP32C3-ROM-001",
  "name":NAMES[0],"vectors":tested,"revisions":result,
  "negative_operand_mutations":negative,"physical_silicon_verified":False,
  "independent_review_approved":False,"novel_api_verified":False,
  "limitations":["Tests executable mnemonic streams against separately derived net Ghidra effects, not external hardware truth.",
   "Intermediate bus writes are observed by emulator but Ghidra source collapses some writes.",
   "No real registers accessed; no independent semantic sign-off."]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--machine",required=True,type=pathlib.Path)
 p.add_argument("--ghidra",required=True,type=pathlib.Path)
 p.add_argument("--out",required=True,type=pathlib.Path)
 a=p.parse_args();r=evaluate(a.machine,a.ghidra)
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_AGC_STATIC_NET_EFFECT",json.dumps({"name":r["name"],"vectors":r["vectors"],
    "revisions":len(r["revisions"]),"negative_mutations":r["negative_operand_mutations"],
    "silicon":False},sort_keys=True))
if __name__=="__main__":main()
