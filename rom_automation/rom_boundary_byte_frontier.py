#!/usr/bin/env python3
"""ROM-003 E1. No symbol, function-boundary, Ghidra or oracle inputs.

Evidence-based RV32I/C extraction from E0 raw executable sections. A raw
32/16-bit JAL-with-link is a *candidate* even if its source is unconfirmed data;
only root-reachable PCs have justified source instruction provenance.
A conditional-branch destination is a BASIC BLOCK, not a function start.
"""
import argparse,collections,json,pathlib
from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
from rom_boundary_source_seal import validate_candidate_input

SCHEMA="ROM003_E1_BYTE_ONLY_CANDIDATES_V1"
BANNED={"unimp","c.unimp","ecall","ebreak","c.ebreak",".byte",
        "flw","fsw","fld","fsd","c.flw","c.fsw","c.fld","c.fsd"}
MASK=0xffffffff
def fail(cond,text):
 if not cond:raise ValueError(text)
def sx(v,bits):return v-(1<<bits) if v&(1<<(bits-1)) else v

def direct(raw,pc):
 """Decode encoded branch offset and actual link bit without trusting asm text."""
 if len(raw)==4:
  w=int.from_bytes(raw,"little");op=w&127
  if op==0x6f:
   imm=((w>>31&1)<<20)|((w>>12&255)<<12)|((w>>20&1)<<11)|((w>>21&1023)<<1)
   return (pc+sx(imm,21))&MASK,"DIRECT_CALL" if ((w>>7)&31)!=0 else "DIRECT_JUMP"
  if op==0x63 and ((w>>12)&7) in (0,1,4,5,6,7):
   imm=((w>>31&1)<<12)|((w>>7&1)<<11)|((w>>25&63)<<5)|((w>>8&15)<<1)
   return (pc+sx(imm,13))&MASK,"BASIC_BLOCK_BRANCH"
 if len(raw)==2:
  w=int.from_bytes(raw,"little")
  if w&3==1:
   kind=(w>>13)&7
   if kind in (1,5):
    imm=((w>>12&1)<<11)|((w>>11&1)<<4)|((w>>9&3)<<8)|((w>>8&1)<<10)|((w>>7&1)<<6)|((w>>6&1)<<7)|((w>>3&7)<<1)|((w>>2&1)<<5)
    return (pc+sx(imm,12))&MASK,"DIRECT_CALL" if kind==1 else "DIRECT_JUMP"
   if kind in (6,7):
    imm=((w>>12&1)<<8)|((w>>5&3)<<6)|((w>>2&1)<<5)|((w>>10&3)<<3)|((w>>3&3)<<1)
    return (pc+sx(imm,9))&MASK,"BASIC_BLOCK_BRANCH"
 return None

def regmap(payload):
 validate_candidate_input(payload)
 return [(int(r["start_pc"],16),bytes.fromhex(r["raw_hex"])) for r in payload["exec_regions"]]

def fetch(regions,pc):
 for base,raw in regions:
  if base<=pc<base+len(raw):
   return raw[pc-base:pc-base+4]
 return b""

def machine(pc,regions,disassembler):
 chunk=fetch(regions,pc)
 if len(chunk)<2 or pc&1:return None
 n=2 if chunk[0]&3!=3 else 4
 if len(chunk)<n:return None
 raw=chunk[:n]
 i=next(disassembler.disasm(raw,pc,count=1),None)
 if i is None or i.size!=n or i.mnemonic in BANNED:return None
 return {"pc":hex(pc),"raw":raw.hex(),"opcode":i.mnemonic,"length":n}

def rooted_walk(regions,root,budget=40000):
 dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 todo=collections.deque([root]);seen=set();evidence=[];unknown=[]
 while todo and len(seen)<budget:
  pc=todo.popleft()
  if pc in seen:continue
  i=machine(pc,regions,dec)
  if not i:
   unknown.append({"pc":hex(pc),"reason":"INVALID_OR_UNMAPPED_INSTRUCTION"});continue
  seen.add(pc)
  raw=bytes.fromhex(i["raw"]);parsed=direct(raw,pc)
  fall=(pc+i["length"])&MASK
  if parsed:
   dest,kind=parsed
   evidence.append({"from_pc":hex(pc),"to_pc":hex(dest),"opcode_hex":i["raw"],
                    "kind":kind,"source_provenance":"ROOTED_MACHINE_INSTRUCTION"})
   if fetch(regions,dest):todo.append(dest)
   else:unknown.append({"pc":hex(pc),"reason":"OUT_OF_EXEC_DIRECT_TARGET","target":hex(dest)})
   if kind in ("DIRECT_CALL","BASIC_BLOCK_BRANCH"):todo.append(fall)
  elif i["opcode"] in ("ret","c.jr","jr","mret","sret","uret","c.jalr","jalr"):
   unknown.append({"pc":hex(pc),"reason":"RETURN_OR_UNRESOLVED_INDIRECT",
                   "opcode":i["opcode"]})
   # After an unresolved call we cannot prove the successor. Stop conservatively.
  else:
   todo.append(fall)
 fail(not todo,"ROOTED_TRAVERSAL_BUDGET_EXCEEDED")
 return seen,evidence,unknown

def unrooted_link_scan(regions):
 """Potential encoded CALLs at every halfword, NOT validated instruction boundaries."""
 links=collections.defaultdict(list)
 for base,b in regions:
  for off in range(0,len(b)-1,2):
   pc=base+off
   if b[off]&3==3:
    if off+4>len(b) or b[off]&127!=0x6f:continue
    word=int.from_bytes(b[off:off+4],"little")
    if (word>>7)&31==0:continue
    raw=b[off:off+4]
   else:
    if b[off]&3!=1 or (b[off+1]>>5)&7!=1:continue
    raw=b[off:off+2]
   result=direct(raw,pc)
   if result is None or result[1]!="DIRECT_CALL":continue
   dest,_=result
   if fetch(regions,dest):
    links[dest].append({"from_pc":hex(pc),"opcode_hex":raw.hex(),
                        "source_provenance":"UNROOTED_RAW_HALFWORD_MAY_BE_DATA"})
 return links

def analyze(payload,max_instructions=40000):
 regions=regmap(payload);root=int(payload["root_pc"],16)
 seen,edges,unknown=rooted_walk(regions,root,max_instructions)
 raw_calls=unrooted_link_scan(regions)
 rooted_sources={int(e["from_pc"],16) for e in edges if e["kind"]=="DIRECT_CALL"}
 for e in edges:
  if e["kind"]=="DIRECT_CALL":
   dest=int(e["to_pc"],16)
   raw_calls[dest].append({"from_pc":e["from_pc"],"opcode_hex":e["opcode_hex"],
                           "source_provenance":"ROOTED_MACHINE_INSTRUCTION"})
 dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 entries=[]
 for pc,items in raw_calls.items():
  target=machine(pc,regions,dec)
  if not target:
   unknown.append({"pc":hex(pc),"reason":"CALL_TARGET_BAD_INSTRUCTION"})
   continue
  unique={(x["from_pc"],x["opcode_hex"]):x for x in items}
  witnesses=list(unique.values())
  proven=[x for x in witnesses if x["source_provenance"]=="ROOTED_MACHINE_INSTRUCTION"]
  entries.append({"entry_pc":hex(pc),"candidate_type":"POSSIBLE_FUNCTION_ENTRY_NOT_CERTIFIED",
   "rooted_call_witnesses":len(proven),"encoded_link_sources":len(witnesses),
   "machine_first_instruction":target,
   "witnesses":sorted(witnesses,key=lambda x:(x["source_provenance"],x["from_pc"]))[:5],
   "real_function_proven":False,"new_rom_api_proven":False})
 entries.sort(key=lambda x:(-int(x["rooted_call_witnesses"]>0),-x["encoded_link_sources"],int(x["entry_pc"],16)))
 raw_order=sorted(entries,key=lambda x:(-x["encoded_link_sources"],int(x["entry_pc"],16)))
 rooted_targets=sorted({x["entry_pc"] for x in entries if x["rooted_call_witnesses"]>0},key=lambda v:int(v,16))
 branch_targets=sorted({e["to_pc"] for e in edges if e["kind"]=="BASIC_BLOCK_BRANCH"})
 return {"schema":SCHEMA,"revision":payload["revision"],"root":payload["root_pc"],
  "instructions_rooted":len(seen),"rooted_control_edges":len(edges),
  "rooted_entry_candidates":rooted_targets,
  "rooted_basic_block_only_targets":branch_targets,
  "rooted_call_count":len(rooted_targets),
  "unrooted_halfword_candidate_count":len(entries),
  "candidate_records":entries[:1000],
  "ranked_possible_entries":[x["entry_pc"] for x in entries],
  "ranked_raw_link_baseline":[x["entry_pc"] for x in raw_order],
  "unresolved":unknown[:500],"unresolved_total":len(unknown),
  "unknown_interpretation":["UNROOTED_CALL_SOURCE_MAY_BE_DATA","INDIRECT_EDGES_UNRESOLVED",
   "BRANCH_TARGET_NOT_INDEPENDENT_FUNCTION_ENTRY"],
  "true_function_boundary_verified":False,"hardware_executed":False,
  "novel_usable_API_verified":False}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--input-dir",type=pathlib.Path,required=True)
 p.add_argument("--out-dir",type=pathlib.Path,required=True)
 a=p.parse_args()
 a.out_dir.mkdir(parents=True,exist_ok=True)
 for rev in ("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf"):
  payload=json.loads((a.input_dir/(rev+".json")).read_text())
  result=analyze(payload)
  (a.out_dir/(rev+".json")).write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
  print("E1_ROM_ROOTED",json.dumps({"rev":rev,"rooted_instructions":result["instructions_rooted"],
    "rooted_entries":result["rooted_call_count"],
    "raw_candidates":result["unrooted_halfword_candidate_count"],
    "unresolved":result["unresolved_total"]},sort_keys=True))
if __name__=="__main__":main()
