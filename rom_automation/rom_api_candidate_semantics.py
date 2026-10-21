#!/usr/bin/env python3
"""Deterministic RV32IMC instruction-vs-formula falsification for ROM-001.

Run ONLY on pinned offline ELF disassembly; no silicon interaction and no novelty certification.
"""
import argparse,hashlib,json,pathlib,random
MASK=0xffffffff
def signed(v,bits=32):
 v &= (1<<bits)-1
 return v if v<(1<<(bits-1)) else v-(1<<bits)
def quotient(a,b):
 if b==0:raise ValueError("DIVIDE_BY_ZERO")
 return (abs(a)//abs(b))*(-1 if (a<0)!=(b<0) else 1)
def execute(program,a0,a1,a2):
 pcs={int(i["pc"],16):i for i in program}
 if len(pcs)!=16:raise ValueError("DRIFT_INSTRUCTION_COUNT")
 regs={"a0":a0&MASK,"a1":a1&MASK,"a2":a2&MASK,"zero":0}
 pc=min(pcs);trace=[]
 for _ in range(24):
  if pc not in pcs:raise ValueError("INVALID_BRANCH:"+hex(pc))
  ins=pcs[pc];op=ins["mnemonic"];v=[x.strip() for x in ins["operands"].split(",")]
  trace.append(hex(pc));nxt=pc+len(bytes.fromhex(ins["hex"]))
  if op=="c.sub":regs[v[0]]=(regs[v[0]]-regs[v[1]])&MASK
  elif op=="c.slli":regs[v[0]]=(regs[v[0]]<<int(v[1],0))&MASK
  elif op=="c.srai":regs[v[0]]=(signed(regs[v[0]])>>int(v[1],0))&MASK
  elif op=="c.li":regs[v[0]]=int(v[1],0)&MASK
  elif op=="div":regs[v[0]]=quotient(signed(regs[v[1]]),signed(regs[v[2]]))&MASK
  elif op in ("c.beqz","blez","bgtz"):
   test=regs[v[0]]==0 if op=="c.beqz" else (signed(regs[v[0]])<=0 if op=="blez" else signed(regs[v[0]])>0)
   if test:nxt=pc+int(v[1],0)
  elif op=="c.j":nxt=pc+int(v[0],0)
  elif op=="c.jr":
   if v!=["ra"]:raise ValueError("UNSUPPORTED_INDIRECT_JUMP")
   return signed(regs["a0"]),trace
  else:raise ValueError("UNKNOWN_OPCODE:"+op)
  pc=nxt
 raise ValueError("PATH_LIMIT")
def formula(a0,a1,a2):
 d=signed(a0-a1,16)
 div=(6 if d>0 else 4) if a2==0 else (4 if d>0 else 5)
 return signed(quotient(d,div),8)
def audit(d):
 if d.get("schema")!="ROM001_NEW_API_FUNCTION_DOSSIERS_V1":raise ValueError("INPUT_SCHEMA")
 f=d["new_api_candidates"]["rom2_temp_to_power1"]
 if (f["revision"],f["entry"],f["size_bytes"],f["function_sha256"])!=(
   "esp32c3_rev101_rom.elf","0x4003e9fe",38,
   "af3082b062898053b7b87d13db160876549cc293e225cac8177410715a2422a5"):
  raise ValueError("MACHINE_PROVENANCE_DRIFT")
 ins=f["instructions"]
 if len(ins)!=16 or sum(len(bytes.fromhex(x["hex"])) for x in ins)!=38:raise ValueError("BYTE_COVERAGE")
 boundary=[-65536,-32769,-32768,-257,-256,-255,-128,-127,-25,-20,-13,-12,-11,-10,-9,-8,-7,-6,-5,-4,-3,-2,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,20,25,127,128,255,256,257,32767,32768,65535,65536]
 inputs=[(a,b,c) for a in boundary for b in (-32768,-1,0,32767) for c in (0,1,-1)]
 rng=random.Random(20261021)
 inputs += [(rng.randint(-100000,100000),rng.randint(-100000,100000),rng.choice([0,0,1,-1,7])) for _ in range(10000)]
 mismatch=[];covered=set()
 for a,b,c in inputs:
  got,trace=execute(ins,a,b,c);expected=formula(a,b,c);covered.update(trace)
  if got!=expected:
   mismatch.append({"input":[a,b,c],"actual":got,"expected":expected,"pc_trace":trace})
   if len(mismatch)>=10:break
 return {"schema":"ROM001_REV101_TEMP_TO_POWER1_STATIC_FORMULA_V1",
         "issue":"ESP32C3-ROM-001","function":"rom2_temp_to_power1",
         "entry":f["entry"],"machine_sha256":f["function_sha256"],
         "test_count":len(inputs) if not mismatch else None,
         "mismatches":mismatch,"visited_instruction_count":len(covered),
         "visited_pcs":sorted(covered),
         "formula":"signed8(trunc_zero(signed16(a0-a1)/divisor))",
         "divisor":{"a2==0":{"delta>0":6,"delta<=0":4},"a2!=0":{"delta>0":4,"delta<=0":5}},
         "tested_static_equivalence":not mismatch,
         "global_novelty_proven":False,"silicon_abi_and_callable_proven":False,
         "note":"Differentially compared local independent ISA executor to algebraic hypothesis; not a real-silicon observation."}
def main():
 p=argparse.ArgumentParser();p.add_argument("--dossier",required=True,type=pathlib.Path);p.add_argument("--out",required=True,type=pathlib.Path);a=p.parse_args()
 raw=a.dossier.read_bytes();r=audit(json.loads(raw))
 r["dossier_sha256"]=hashlib.sha256(raw).hexdigest()
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
 print("ROM001_DIFFERENTIAL",json.dumps({"tests":r["test_count"],"mismatches":len(r["mismatches"]),"visited":r["visited_instruction_count"],"formula":r["formula"],"divisor":r["divisor"]}))
 if r["mismatches"]:raise SystemExit(2)
if __name__=="__main__":main()
