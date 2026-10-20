#!/usr/bin/env python3
"""ROM-001 P0-A: ROM ELF e_entry direct trampoline into symbol-size gaps.

This is stricter than blindly scanning code/data: ELF e_entry is supplied as
a configured root. Decode the exact unconditional JAL bits independently of
Capstone, then read the landing instructions. No live silicon claim.
"""
import argparse,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,REVS,require,sha
from rom_fast_graph import make_symbol_index
from rom_opcode import jal,compressed_jump
from rom_p0a_indirect_roots import build_gaps,in_gap,FORBIDDEN

def direct_unconditional_j(raw,pc):
 if len(raw)==4:
  w=int.from_bytes(raw,"little")
  if w&127==0x6f and (w>>7)&31==0:
   return jal(raw,pc)
 if len(raw)==2:
  w=int.from_bytes(raw,"little")
  if w&3==1 and (w>>13)&7==5:return compressed_jump(raw,pc)
 return None

def enumerate_bounded_gap_cfg(blob,elf,sections,gaps,pairs,roots,limit=4000):
 """May-reach superset from fixed ELF roots. Branch conditions are unknown."""
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 from rom_gap_branch_seeds import branch_target
 ranges=[(int(x["sh_addr"]),int(x["sh_addr"])+int(x["sh_size"]),x.data()) for x in sections]
 dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 todo=list(roots);seen=set();unknown=[];edges=[];visited_symbol_entries=set()
 while todo and len(seen)<limit:
  pc=todo.pop()
  if pc in seen:continue
  if any(a<=pc<b for a,b in pairs):
   visited_symbol_entries.add(hex(pc));continue
  section=next(((a,b,data) for a,b,data in ranges if a<=pc<b),None)
  if section is None:
   unknown.append({"pc":hex(pc),"reason":"NOT_IN_ELF_EXEC"});continue
  a,b,data=section
  instruction=next(dec.disasm(data[pc-a:min(pc-a+4,len(data))],pc,count=1),None)
  if instruction is None or instruction.mnemonic in FORBIDDEN:
   unknown.append({"pc":hex(pc),"reason":"INVALID_OR_UNSUPPORTED_RV32IMC"});continue
  seen.add(pc)
  raw=bytes(instruction.bytes)
  result=branch_target(raw,pc)
  fallthrough=pc+instruction.size
  if result is not None:
   dest,kind,link=result
   edges.append({"source":hex(pc),"destination":hex(dest),"kind":kind,"link":link})
   todo.append(dest)
   if kind in ("B_RV32","CB_RVC") or link:todo.append(fallthrough)
  elif instruction.mnemonic in ("jalr","ret","jr","c.jr","c.jalr","ecall","ebreak","c.ebreak"):
   unknown.append({"pc":hex(pc),"reason":"INDIRECT_OR_TERMINATOR","opcode":instruction.mnemonic})
  else:
   todo.append(fallthrough)
 return {
  "visited_gap_instructions":len(seen),
  "visited_gap_bytes_minimum":sum(2 for _ in seen),
  "direct_control_edges":edges[:500],
  "direct_control_edge_count":len(edges),
  "named_function_target_boundaries":sorted(visited_symbol_entries)[:120],
  "unresolved_terminators":unknown[:120],
  "unresolved_terminators_count":len(unknown),
  "hit_node_limit":bool(todo),
  "mode":"OVERAPPROX_MAY_REACH_NO_SILICON_PROOF",
  "all_visited_pcs_sample":[hex(x) for x in sorted(seen)[:100]]
 }

def inspect_one(blob,rev,graph):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 elf=ELFFile(io.BytesIO(blob))
 sections,bounds,pairs,owners,entries,_=make_symbol_index(elf)
 gaps=build_gaps(bounds,pairs)
 source={int(s["sh_addr"]):(int(s["sh_addr"])+int(s["sh_size"]),s.data()) for s in sections}
 def get_bytes(pc,length):
  for b,(e,data) in source.items():
   if b<=pc<e:return data[pc-b:min(e-b,pc-b+length)]
  return b""
 def matching_owners(pc):
  return [{"entry":hex(a),"size":b-a,"names":entries[f"{a:08x}:{b-a:x}"]["aliases"]}
    for a,b in owners(pc)]
 pc=int(elf.header["e_entry"])
 require(pc!=0 and get_bytes(pc,4),"INVALID_ELF_ENTRY")
 decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 trail=[];seen=set();stop="LIMIT";n=0
 while n<16:
  if pc in seen:stop="CYCLE";break
  seen.add(pc);n+=1
  decoded=list(decoder.disasm(get_bytes(pc,64),pc))
  if not decoded:stop="UNDECODED";break
  first=decoded[0]
  raw=bytes(first.bytes)
  if first.mnemonic in FORBIDDEN:stop="INVALID_RV32IMC";break
  jump=direct_unconditional_j(raw,pc)
  is_gap=in_gap(gaps,pc)
  owners_at=matching_owners(pc)
  sample=[]
  if jump is None:
   for item in decoded[:12]:
    if item.mnemonic in FORBIDDEN:break
    sample.append({"pc":hex(item.address),"opcode":item.mnemonic,"raw_bytes":bytes(item.bytes).hex()})
  trail.append({"pc":hex(pc),"first_opcode":first.mnemonic,"first_raw_bytes":raw.hex(),
    "in_positive_size_STT_FUNC":bool(owners_at),
    "in_unclassified_exec_gap":is_gap,
    "matching_symbol_owner":owners_at,
    "unconditional_direct_jump":hex(jump) if jump is not None else None,
    "straightline_sample":sample,
    "direct_trampoline_verified_from_ELF_image":jump is not None})
  if jump is None:
   stop="NONTRAMPOLINE_LANDING";break
  if not get_bytes(jump,2):
   stop="JUMP_OUTSIDE_ELF_EXEC_SECTIONS";break
  pc=jump
 else:stop="MAX_CHAIN_STEPS"
 first_hop=trail[0]["unconditional_direct_jump"] if trail else None
 cfg=enumerate_bounded_gap_cfg(blob,elf,sections,gaps,pairs,[int(elf.header["e_entry"])])
 require(first_hop is not None,"ELF_ENTRY_NOT_DIRECT_JUMP")
 return {"rev":rev,"elf_sha256":hashlib.sha256(blob).hexdigest(),
  "elf_entry":hex(int(elf.header["e_entry"])),"first_jump_target":first_hop,
  "first_target_in_STT_FUNC_size_gap":in_gap(gaps,int(first_hop,16)),
  "root_jump_chain":trail,"stopped_because":stop,
  "bounded_entry_CFG":cfg,
  "novel_hardware_function_verified":False,
  "ROM_silicon_execution_proven":False,
  "interpretation":"ELF configured entry root and disassembled raw branch, not proof of physical boot path",
  "next_classify":"If landing traverses to a known alias, it is a documented trampoline; otherwise preserve as unknown label/entry until CFG and prior art are checked."}

def evaluate(rom,graph):
 require(sha(rom)==ROM_SHA,"OFFICIAL_ROM_ARCHIVE_SHA")
 require(graph["schema"]=="ESP32C3_ALL_ROM_FAST_GRAPH_V1" and graph["rom_source_sha256"]==ROM_SHA,"PINNED_GRAPH")
 outputs={}
 with tarfile.open(rom,"r:gz") as t:
  for rev in REVS:
   file=[m for m in t.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   require(len(file)==1,"MISSING_REV_ELF")
   b=t.extractfile(file[0]).read()
   require(hashlib.sha256(b).hexdigest()==graph["all_revisions"][rev]["elf_sha256"],"ELF_SHA_MISMATCH")
   outputs[rev]=inspect_one(b,rev,graph)
 return {"schema":"ROM001_P0A_ELF_ENTRY_TRAMPOLINE_V1",
   "original_issue_id":"ESP32C3-ROM-001","ROM_sha256":ROM_SHA,
   "revisions":outputs,"independent_novelty":0,"physical_execution":0}
def main():
 p=argparse.ArgumentParser()
 for x in ("rom","graph","out"):p.add_argument("--"+x,required=True,type=pathlib.Path)
 a=p.parse_args();r=evaluate(a.rom,json.loads(a.graph.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_P0A_ENTRY_JUMPS",json.dumps({rev:{
   "entry":x["elf_entry"],"first_target":x["first_jump_target"],
   "chain_length":len(x["root_jump_chain"]),"stop":x["stopped_because"],
   "first_target_gap":x["first_target_in_STT_FUNC_size_gap"]}
   for rev,x in r["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
