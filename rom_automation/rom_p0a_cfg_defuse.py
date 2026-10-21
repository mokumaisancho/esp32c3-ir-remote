#!/usr/bin/env python3
"""ROM-001 P0-A: bounded CFG-unique-predecessor register provenance for JALR.
Only machine-encoded local edges; no claims of global/silicon reachability.
A value from writable RAM, a call, unsupported opcode or CFG join is UNKNOWN.
"""
import argparse,bisect,collections,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,REVS,require,sha
from rom_fast_graph import make_symbol_index
from rom_gap_branch_seeds import branch_target
from rom_strict_indirect import decode_jalr,probable_last_writer,signed,readonly_literal
from rom_p0a_indirect_roots import build_gaps,in_gap
from rom_rvc_register_effects import rvc_effect
MASK=0xffffffff
def w32(ins):
 b=bytes(ins.bytes)
 return int.from_bytes(b,"little") if len(b)==4 else None

def predecessors(seq):
 """Under-approximation of explicitly encoded local control flow, with unknown flag."""
 pcs={x.address:i for i,x in enumerate(seq)}
 inc=[set() for _ in seq]
 uncertain={}
 for i,x in enumerate(seq):
  raw=bytes(x.bytes)
  decoded=branch_target(raw,x.address)
  nextpc=x.address+x.size
  if decoded:
   dest,kind,link=decoded
   if dest in pcs:inc[pcs[dest]].add(i)
   if kind.startswith("B_") or kind.startswith("CB_") or link:
    if nextpc in pcs:inc[pcs[nextpc]].add(i)
    if link:uncertain[i]="CALL_RETURN_BARRIER"  # calls may clobber
   continue
  if decode_jalr(x):
   # Indirect call can return but its callee can change registers.
   if (j:=decode_jalr(x))["rd"]!=0 and nextpc in pcs:
    inc[pcs[nextpc]].add(i);uncertain[i]="CALL_RETURN_BARRIER"
   continue
  if x.size==2:
   effect=rvc_effect(bytes(x.bytes))
   if effect["kind"]=="CONTROL":
    # c.jr has no fallthrough. c.jalr may return, but clobbers
    # all values without a callee summary. Neither is an ordinary
    # instruction through which register constants can propagate.
    if effect["mnemonic"]=="c.jalr" and nextpc in pcs:
     inc[pcs[nextpc]].add(i);uncertain[i]="CALL_RETURN_BARRIER"
    elif effect["mnemonic"]=="c.j_or_branch":
     # Already handled valid c.j/c.beqz/c.bnez by branch_target.
     # Any remaining control encoding is unknown, not fallthrough.
     uncertain[i]="COMPRESSED_CONTROL_BARRIER"
    continue
   if effect["kind"]=="UNKNOWN":
    # Unknown compressed opcode may also affect control flow.
    # A sequential next PC is not a validated predecessor.
    uncertain[i]="UNMODELED_COMPRESSED_OPCODE"
  if x.mnemonic in ("ecall","ebreak","c.ebreak"):
   continue
  if nextpc in pcs:inc[pcs[nextpc]].add(i)
 return inc,uncertain

def infer_register_value(seq,idx,reg,max_steps=48):
 """Unique local predecessor chain only; nonzero source x-register is unknown at entry.
 Return raw proven integer and raw-def witnesses, otherwise typed UNKNOWN reason.
 """
 if reg==0:return {"value":0,"kind":"REGISTER_X0","witnesses":[]}
 incoming,uncertain=predecessors(seq)
 ops=[];witness=[];seen=set();at=idx
 for _ in range(max_steps):
  if at in seen:return {"unresolved":"CFG_CYCLE"}
  seen.add(at)
  prior=incoming[at]
  if len(prior)!=1:return {"unresolved":"CFG_JOIN_OR_NO_PREDECESSOR"}
  p=next(iter(prior))
  if p in uncertain:return {"unresolved":uncertain[p]}
  ins=seq[p];v=w32(ins)
  if v is None:
   effect=rvc_effect(bytes(ins.bytes))
   kind=effect["kind"]
   if kind=="UNKNOWN":return {"unresolved":"UNMODELED_COMPRESSED_OPCODE"}
   if kind=="CONTROL":
    if effect["mnemonic"]=="c.j_or_branch":
     at=p;continue
    return {"unresolved":"COMPRESSED_CONTROL_BARRIER"}
   if kind=="PRESERVE":
    at=p;continue
   if effect.get("rd")!=reg:
    at=p;continue
   if kind=="ADD_IMM":
    ops.append(("ADD",effect["imm"]))
    witness.append({"pc":hex(ins.address),"raw":bytes(ins.bytes).hex()})
    at=p;continue
   if kind=="ASSIGN_IMM":
    base=effect["value"]
    for op_kind,operand in reversed(ops):
     base=(base+operand if op_kind=="ADD" else base|operand)&MASK
    return {"value":base,"kind":"UNIQUE_CFG_RV32C_DEFINITION",
      "witnesses":list(reversed(witness+[{"pc":hex(ins.address),"raw":bytes(ins.bytes).hex()}]))}
   return {"unresolved":"COMPRESSED_REGISTER_WRITER_UNSUPPORTED"}
  opcode=v&127
  # Branches and stores are read-only for registers, may remain on unique path.
  if opcode in (0x23,0x63,0x0f):
   at=p;continue
  if opcode in (0x6f,0x67,0x73):
   return {"unresolved":"CONTROL_CSR_BARRIER"}
  dest=(v>>7)&31
  if opcode in (0x37,0x17):
   if dest==reg:
    base=(v&0xfffff000)+(ins.address if opcode==0x17 else 0)
    for kind,operand in reversed(ops):
     base=((base+operand) if kind=="ADD" else (base|operand))&MASK
    return {"value":base&MASK,
      "kind":"UNIQUE_CFG_REG_DEFINITION",
      "witnesses":list(reversed(witness+[{"pc":hex(ins.address),"raw":bytes(ins.bytes).hex()}]))}
   at=p;continue
  if opcode==0x13:
   func=(v>>12)&7
   if dest!=reg:at=p;continue
   src=(v>>15)&31;imm=signed(v>>20,12)
   if func not in (0,6):return {"unresolved":"NONCONSTANT_ALU_TRANSFORM"}
   if src==reg:
    ops.append(("ADD" if func==0 else "OR",imm&MASK if func==6 else imm))
    witness.append({"pc":hex(ins.address),"raw":bytes(ins.bytes).hex()})
    at=p;continue
   if src==0:
    base=imm&MASK
    for kind,operand in reversed(ops):
     base=(base+operand if kind=="ADD" else base|operand)&MASK
    return {"value":base,"kind":"UNIQUE_CFG_X0_IMMEDIATE",
      "witnesses":list(reversed(witness+[{"pc":hex(ins.address),"raw":bytes(ins.bytes).hex()}]))}
   return {"unresolved":"TRANSFER_FROM_UNRESOLVED_REGISTER"}
  # Custom/reserved opcode encodings may write any modeled source register.
  if opcode in (0x0b,0x5b):return {"unresolved":"UNKNOWN_OPCODE_POSSIBLE_REG_WRITE"}
  # All writes, loads and atomics fail closed on changed source.
  if opcode in (0x03,0x33,0x1b,0x2f) and dest==reg:
   return {"unresolved":"LOAD_OR_UNMODELED_REG_WRITE"}
  if opcode not in (0x03,0x33,0x1b,0x2f,0x37,0x17,0x13):
   return {"unresolved":"UNKNOWN_OPCODE_POSSIBLE_REG_WRITE"}
  at=p
 return {"unresolved":"LOOKBACK_LIMIT"}

def is_rom_exec_address(target,section_intervals):
 return any(start<=target<stop for start,stop in section_intervals)

def scan_one(blob,rev,graph):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 elf=ELFFile(io.BytesIO(blob));sections,bounds,pairs,owners,entries,_=make_symbol_index(elf)
 gaps=build_gaps(bounds,pairs)
 dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC);dec.skipdata=True
 named=graph["function_byte_evidence"][rev]
 counts=collections.Counter();hits=[]
 by_sec={}
 for s in sections:
  base=int(s["sh_addr"]);data=s.data();ins=list(dec.disasm(data,base))
  require(sum(x.size for x in ins)==len(data),"DECODER_SKIPPED_SECTION_BYTES")
  by_sec[base]=(base+len(data),ins,[x.address for x in ins])
 for key,item in named.items():
  addr=int(item["entry"],16);end=addr+item["size_bytes"]
  v=next(((b,ins,starts) for b,(e,ins,starts) in by_sec.items() if b<=addr<end<=e),None)
  if not v:continue
  base,ins,starts=v;lo=bisect.bisect_left(starts,addr);hi=bisect.bisect_left(starts,end)
  seq=ins[lo:hi]
  if not seq or seq[0].address!=addr or seq[-1].address+seq[-1].size!=end:continue
  for i,x in enumerate(seq):
   call=decode_jalr(x)
   if call is None or (call["rs1"]==1 and call["rd"]==0 and call["imm"]==0):continue
   counts["nonreturn_JALR"]+=1
   value=infer_register_value(seq,i,call["rs1"])
   if "value" not in value:
    counts[value["unresolved"]]+=1;continue
   target=(value["value"]+call["imm"])&MASK&~1
   # A syntactically constant JALR to address zero is NOT an executable
   # ROM callee. Rev0 contains 95 such machine-word patterns, some in
   # check_condCOUNTER labels. Do not treat zero or an unallocated address
   # as a recovered function or target.
   if not is_rom_exec_address(target,[(b,e) for b,(e,_,_) in by_sec.items()]):
    counts["NON_EXECUTABLE_TARGET_REJECTED"]+=1
    if target==0:counts["ZERO_ADDRESS_REJECTED"]+=1
    continue
   counts["CFG_LOCAL_CONSTANT_TARGET"]+=1
   match=in_gap(gaps,target)
   if match:counts["TARGET_IN_ELF_NAME_GAP"]+=1
   if len(hits)<300:
    hits.append({"caller_function":key,"call_pc":hex(x.address),
      "call_machine":bytes(x.bytes).hex(),"target":hex(target),
      "inside_unknown_symbol_gap":match,
      "bounded_local_provenance":value,
      "global_cfg_proven":False,"runtime_proven":False,
      "new_function_proven":False})
 return {"revision":rev,"ELF_sha256":hashlib.sha256(blob).hexdigest(),
   "counts":dict(counts),"candidate_local_constant_edges":hits,
   "confirmed_novel_function_count":0,
   "warning":"Unique predecessor inside named function is not global uniqueness. Computed RAM/table pointers excluded."}

def evaluate(rom,graph):
 require(sha(rom)==ROM_SHA,"OFFICIAL_ROM_TAR_SHA")
 require(graph["schema"]=="ESP32C3_ALL_ROM_FAST_GRAPH_V1" and graph["rom_source_sha256"]==ROM_SHA,"PINNED_GRAPH")
 result={}
 with tarfile.open(rom,"r:gz") as t:
  for rev in REVS:
   ms=[m for m in t.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   require(len(ms)==1,"ELF_REV_ID")
   b=t.extractfile(ms[0]).read()
   require(hashlib.sha256(b).hexdigest()==graph["all_revisions"][rev]["elf_sha256"],"ELF_SHA_DRIFT")
   result[rev]=scan_one(b,rev,graph)
 return {"schema":"ROM001_P0A_BOUNDED_CFG_DEFUSE_V1","original_issue_id":"ESP32C3-ROM-001",
  "source_ROM_sha256":ROM_SHA,"revisions":result,
  "globally_proven_targets":0,"silicon_confirmed":0}
def main():
 p=argparse.ArgumentParser()
 for n in ("rom","graph","out"):p.add_argument("--"+n,required=True,type=pathlib.Path)
 a=p.parse_args();r=evaluate(a.rom,json.loads(a.graph.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_P0A_CFG_DEFUSE",json.dumps({rev:v["counts"] for rev,v in r["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
