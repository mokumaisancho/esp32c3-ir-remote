#!/usr/bin/env python3
"""ESP32C3-ROM-001: deterministic SPI slave init net-effect differential POC.

Pinned Ghidra C assignment interpreter vs separately decoded ROM ISA replay.
Only final modeled register values are corroborated; real bus writes remain unknown.
"""
import argparse,ast,copy,hashlib,json,pathlib,random,re
from decision_gate import REVS,require
from bounded_isa_effects import MASK,evidence,replay

NAMES=("spi_slave_rom_init_hw",)
BASE=0x60036000
POINTER=r'\*\((?:undefined4|uint|undefined1) \*\)\(param_1 \+ (0x[0-9a-f]+|[0-9]+)\)'
GLOBAL=r'_DAT_ram_([0-9a-f]+)'
OFFSETS=(8,12,16,20,24,32,48,52,56,224)
GLOBALS=(0x6003f0e0,0x6003f080,0x6003f070,0x6003f0d0,0x6003f00c)

def initial_memory(seed):
 rng=random.Random(seed)
 mem={BASE+k:rng.getrandbits(32) for k in OFFSETS}
 mem.update({addr:rng.getrandbits(32) for addr in GLOBALS})
 return mem

def ghidra_net_effect(pseudocode,initial):
 """Parse a narrow C assignment subset with Python AST; NEVER call eval/exec.
 Unsupported syntax fails closed instead of being guessed by an LLM.
 """
 memory=dict(initial)
 lines=[s.strip() for s in pseudocode.splitlines() if " = " in s]
 require(len(lines)==43,"GHIDRA_ASSIGNMENT_COUNT_NOT_43")
 def expression(expr):
  expr=re.sub(POINTER,lambda m:"M"+str(BASE+int(m.group(1),0)),expr)
  expr=re.sub(GLOBAL,lambda m:"M"+str(int(m.group(1),16)),expr)
  tree=ast.parse(expr,mode="eval").body
  def evaluate_node(node):
   if isinstance(node,ast.Constant) and type(node.value)==int:return node.value
   if isinstance(node,ast.Name) and re.fullmatch(r"M[0-9]+",node.id):
    return memory.get(int(node.id[1:]),0)
   if isinstance(node,ast.BinOp):
    lhs,rhs=evaluate_node(node.left),evaluate_node(node.right)
    if isinstance(node.op,ast.BitAnd):return lhs&rhs
    if isinstance(node.op,ast.BitOr):return lhs|rhs
    if isinstance(node.op,ast.LShift):return lhs<<rhs
   raise RuntimeError("UNSUPPORTED_GHIDRA_C_AST:"+ast.dump(node))
  return evaluate_node(tree)&MASK
 for line in lines:
  lhs,rhs=line.rstrip(";").split(" = ",1)
  match=re.fullmatch(POINTER,lhs)
  if match:
   addr=BASE+int(match.group(1),0)
   size=1 if lhs.startswith("*(undefined1") else 4
  else:
   match=re.fullmatch(GLOBAL,lhs)
   require(bool(match),"UNKNOWN_GHIDRA_TARGET:"+lhs)
   addr=int(match.group(1),16);size=4
  value=expression(rhs)
  if size==1:
   a=addr&~3;shift=(addr&3)*8
   memory[a]=((memory.get(a,0)&~(0xff<<shift))|((value&0xff)<<shift))&MASK
  else:memory[addr]=value
 return memory,len(lines)

def check_case(rows,pseudocode,seed):
 before=initial_memory(seed)
 actual=replay(rows,before,a0=BASE)
 expected,num=ghidra_net_effect(pseudocode,before)
 require(actual["memory"]==expected,"SPI_NET_EFFECT_DIFFERENTIAL:"+str(seed))
 require(not actual["edges"],"SPI_UNEXPECTED_BRANCH")
 require(len(actual["writes"])==47,"SPI_ORDERED_WRITE_COUNT")
 return actual

def negative_control(rows,pseudocode):
 changed=copy.deepcopy(rows)
 matches=[x for x in changed if x["mnemonic"]=="sw" and x["operands"]=="zero, 0xc(a0)"]
 require(len(matches)==1,"SPI_MUTATION_NOT_UNIQUE")
 matches[0]["operands"]="zero, 0x14(a0)"
 try:check_case(changed,pseudocode,3)
 except RuntimeError as e:
  require("SPI_NET_EFFECT_DIFFERENTIAL:" in str(e),"SPI_MUTATION_WRONG_REASON")
  return True
 raise RuntimeError("SPI_MUTATION_NOT_DETECTED")

def evaluate(machine,ghidra):
 bodies,decomp=evidence(machine,ghidra)
 summary={};hashes=set();vectors=0;mutations=0
 for rev in REVS:
  f=bodies[rev][NAMES[0]];g=decomp[rev][NAMES[0]]
  require(f["status"].startswith("FULL_BODY_VERIFIED"),"SPI_ROM_BYTES_UNVERIFIED")
  require(g["decompiler_status"]=="DECOMPILED","SPI_GHIDRA_FAILED")
  require(int(g["requested_address"],16)==int(f["start"],16),"SPI_GHIDRA_IDENTITY")
  require("param_1 + 0x14" in g["pseudocode"] and "6003f0e0" in g["pseudocode"],"SPI_GHIDRA_STRUCTURE")
  hashes.add(f["sha256"])
  for seed in range(30):check_case(f["instruction_listing"],g["pseudocode"],seed)
  require(negative_control(f["instruction_listing"],g["pseudocode"]),"SPI_NEGATIVE_FAIL")
  vectors+=30;mutations+=1
  summary[rev]={"entry":f["start"],"function_sha256":f["sha256"],
   "ghidra_pseudocode_sha256":hashlib.sha256(g["pseudocode"].encode()).hexdigest(),
   "vectors":30,"machine_instruction_count":f["instruction_count"],
   "machine_stores":47,"ghidra_C_assignments":43,"negative_operand_mutation_detected":True}
 require(len(hashes)==1,"SPI_REVISION_CODE_SHA_DRIFT")
 return {"schema":"ROM_SPI_INIT_GHIDRA_TEXT_ISA_NET_EFFECT_V1","original_issue_id":"ESP32C3-ROM-001",
  "name":NAMES[0],"revisions":summary,"vectors":vectors,"negative_operand_mutations":mutations,
  "revision_code_identical":True,
  "silicon_verified":False,"independent_semantic_review_approved":False,"new_api_proven":False,
  "intermediate_writes_independently_certified":False,
  "limitations":["Ghidra and ISA replay are different algorithms over the SAME ROM bytes.",
   "43 C assignments differ from 47 machine writes; transient side effects unproven.",
   "Reference executes AST-whitelisted expressions only; no LLM response data or eval.",
   "Host simulation only; no hardware invoked."]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--machine",required=True,type=pathlib.Path)
 p.add_argument("--ghidra",required=True,type=pathlib.Path)
 p.add_argument("--out",required=True,type=pathlib.Path)
 a=p.parse_args();r=evaluate(a.machine,a.ghidra)
 a.out.parent.mkdir(exist_ok=True,parents=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_SPI_NET_EFFECT",json.dumps({"name":r["name"],
  "revisions":len(r["revisions"]),"vectors":r["vectors"],
  "negative_mutations":r["negative_operand_mutations"],
  "machine_writes_per_revision":47,"C_assignments":43,"silicon":False},sort_keys=True))
if __name__=="__main__":main()
