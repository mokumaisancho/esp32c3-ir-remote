#!/usr/bin/env python3
"""ESP32C3-ROM-001: bounded machine-byte evidence for indirect ROM calls.

Prove a static target only through adjacent RV32I instruction encodings in a
verified STT_FUNC body. Do not infer hardware execution, function novelty, or
that data matches constitute real control transfers.
"""
import argparse,collections,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile
from decision_gate import REVS,ROM_SHA,require,sha

MASK=0xffffffff
def signed(v,bits):return v-(1<<bits) if v&(1<<(bits-1)) else v
def word(ins):
 raw=bytes(ins.bytes)
 return int.from_bytes(raw,"little") if len(raw)==4 else None
def op(ins):return None if word(ins) is None else word(ins)&0x7f
def register_result(ins):
 """Register directly overwritten by supported 32-bit opcodes; conservative."""
 w=word(ins)
 if w is None:return None
 if op(ins) in (0x17,0x37,0x13,0x03,0x67,0x33,0x1b,0x73,0x6f):
  return (w>>7)&31
 return None
def is_nop(ins):
 w=word(ins)
 return w==0x00000013 or bytes(ins.bytes)==bytes.fromhex("0100")
def address_builder(a,b):
 """AUIPC/LUI + ADDI (or AUIPC + LW immediate pointer slot).
 All fields are decoded from binary, not Capstone's operands.
 """
 wa,wb=word(a),word(b)
 if wa is None or wb is None:return None
 kind=wa&0x7f
 rd=(wa>>7)&31
 if kind not in (0x17,0x37) or not rd:return None
 rb=(wb>>15)&31
 dest=(wb>>7)&31
 if rb!=rd or not dest:return None
 operand=wb&0x7f
 if operand not in (0x13,0x03):return None
 if operand==0x13 and (wb>>12)&7!=0:return None
 if operand==0x03 and (wb>>12)&7!=2:return None
 base=(int(a.address) if kind==0x17 else 0)+(wa&0xfffff000)
 slot=(base+signed(wb>>20,12))&MASK
 return {"dest_reg":dest,"resolved_value":slot,
   "producer_pc":hex(a.address),"producer_bytes":bytes(a.bytes).hex(),
   "consumer_pc":hex(b.address),"consumer_bytes":bytes(b.bytes).hex(),
   "opcode_pattern":("AUIPC_" if kind==0x17 else "LUI_")+("ADDI" if operand==0x13 else "LW"),
   "is_load":operand==0x03}
def decode_jalr(ins):
 w=word(ins)
 if w is not None and w&0x7f==0x67 and (w>>12)&7==0:
  return {"rs1":(w>>15)&31,"rd":(w>>7)&31,"imm":signed(w>>20,12),"compressed":False}
 # RVC: C.JR and C.JALR exactly require rs2=0, rs1 nonzero, funct3=100, quadrant2
 raw=bytes(ins.bytes)
 if len(raw)==2:
  w=int.from_bytes(raw,"little")
  if w&3==2 and w>>13&7==4 and w>>2&31==0 and w>>7&31:
   return {"rs1":(w>>7)&31,"rd":1 if w>>12&1 else 0,"imm":0,"compressed":True}
 return None
def readonly_literal(elf,addr):
 """Static immutable little-endian ROM literal only, never MMIO/RAM."""
 for s in elf.iter_sections():
  if s["sh_type"]!="SHT_PROGBITS":continue
  flags=int(s["sh_flags"])
  if not flags&2 or flags&1 or flags&4:continue
  base=int(s["sh_addr"])
  if base<=addr and addr+4<=base+int(s["sh_size"]):
   return int.from_bytes(s.data()[addr-base:addr-base+4],"little")
 return None
def candidate_call(seq,idx,elf,entry_to_key):
 ins=seq[idx];call=decode_jalr(ins)
 if call is None or (call["rs1"]==1 and call["rd"]==0 and call["imm"]==0):
  return None
 # Only adjacent two-instruction materializations plus possible NOPs.
 # No unverified register state, mutable pointer tables or arbitrary jump indices.
 tail=seq[max(0,idx-5):idx]
 clean=[x for x in tail if not is_nop(x)]
 matching=[]
 if len(clean)>=2:
  pair=address_builder(clean[-2],clean[-1])
  if pair and not pair["is_load"] and pair["dest_reg"]==call["rs1"]:
   matching.append((pair,"DIRECT_CONSTANT",None))
  if pair and pair["is_load"] and pair["dest_reg"]==call["rs1"]:
   literal=readonly_literal(elf,pair["resolved_value"])
   if literal is not None:matching.append((pair,"RODATA_ABSOLUTE_WORD",literal))
 if len(clean)>=3:
  pair=address_builder(clean[-3],clean[-2])
  middle=clean[-1];w=word(middle)
  if pair and not pair["is_load"] and w is not None and w&0x7f==0x03 and (w>>12)&7==2:
   reg=(w>>7)&31;src=(w>>15)&31
   if src==pair["dest_reg"] and reg==call["rs1"]:
    slot=(pair["resolved_value"]+signed(w>>20,12))&MASK
    literal=readonly_literal(elf,slot)
    if literal is not None:
     q=dict(pair);q["load_pc"]=hex(middle.address);q["load_machine_bytes"]=bytes(middle.bytes).hex();q["readonly_slot"]=hex(slot)
     matching.append((q,"RODATA_BASE_LW",literal))
 for build,kind,target in matching:
  calculated=(build["resolved_value"] if target is None else target)
  final=(calculated+call["imm"])&MASK&~1
  if final not in entry_to_key:continue
  # Require input instruction sequences be contiguous in byte addresses.
  used=[x for x in clean[-(3 if kind=="RODATA_BASE_LW" else 2):]]+[ins]
  if any(x.address+x.size!=y.address for x,y in zip(used,used[1:])):continue
  if kind=="DIRECT_CONSTANT" and call["rs1"]!=build["dest_reg"]:continue
  return {"call_pc":hex(ins.address),"call_machine_bytes":bytes(ins.bytes).hex(),
    "kind":kind,"build":build,"resolved_callee":hex(final),
    "callee_function_ids":entry_to_key[final],
    "jalr_rd":call["rd"],"evidence":"EXACT_RV32_MACHINE_BYTES",
    "dynamic_execution_proven":False,"novel_feature_proven":False}
 return None

def probable_last_writer(ins):
 """Syntactic nearest writer only, not a whole-program register dataflow proof."""
 w=word(ins)
 if w is not None:
  opcode=w&0x7f
  if opcode in (0x03,0x13,0x17,0x37,0x33,0x67,0x6f,0x73,0x1b,0x2f):
   dest=(w>>7)&31
   if dest:
    group=("MEMORY_LOAD" if opcode==0x03 else
           "PC_REL_MATERIALIZATION" if opcode in (0x17,0x37) else
           "ALU_COMPUTATION" if opcode in (0x13,0x33,0x1b) else
           "CONTROL_OR_CSR")
    return dest,group
  return None
 raw=bytes(ins.bytes)
 if len(raw)!=2:return None
 w=int.from_bytes(raw,"little")
 name=ins.mnemonic
 if name in ("c.lw","c.flw"):
  return 8+((w>>2)&7),"COMPRESSED_MEMORY_LOAD"
 if name in ("c.lwsp",):
  return (w>>7)&31,"COMPRESSED_MEMORY_LOAD"
 if name in ("c.mv","c.add","c.li","c.lui","c.addi","c.addi16sp",
             "c.addi4spn","c.slli","c.srli","c.srai","c.andi","c.sub",
             "c.xor","c.or","c.and","c.slli"):
  return (w>>7)&31,"COMPRESSED_ALU_OR_MOVE"
 return None

def prior_register_class(seq,index,reg,max_lookback=24):
 """Bounded within a straight-line block; conservative unknown on branch."""
 control={"beq","bne","blt","bge","bltu","bgeu","bgez","bltz",
  "beqz","bnez","blez","bgtz","c.beqz","c.bnez","c.j","j",
  "c.jal","jal","jalr","c.jalr","jr","c.jr","ret","ecall","ebreak"}
 examined=0
 for pos in range(index-1,max(-1,index-max_lookback-1),-1):
  q=seq[pos]
  if q.mnemonic in control:return "CONTROL_FLOW_BARRIER",None
  writer=probable_last_writer(q)
  if writer and writer[0]==reg:
   return writer[1],{"source_pc":hex(q.address),"source_bytes":bytes(q.bytes).hex(),"mnemonic":q.mnemonic}
  examined+=1
 return "NOT_IN_BOUNDED_STRAIGHT_LINE",None

def trace_load_base(seq,index,reg,elf,entry_to_key,call_imm=0):
 """Bounded two-level def-use: JALR source <- LW <- PC-relative base.

 No cross-branch assumptions, no writable/nonexec RAM content guesses.
 Returns a typed hint and, only if exact frozen memory and ELF entry match,
 a structural potential target.
 """
 kind,source=prior_register_class(seq,index,reg)
 info={"jalr_reg_source":kind,"load_base_provenance":"NOT_APPLICABLE",
       "machine_proven_candidate":None}
 if kind not in ("MEMORY_LOAD","COMPRESSED_MEMORY_LOAD") or not source:return info
 ix=next((p for p in range(index-1,-1,-1)
          if seq[p].address==int(source["source_pc"],16)),None)
 require(ix is not None,"DEF_USE_SOURCE_NOT_FOUND")
 load=seq[ix];w=word(load);base=None;offset=None
 if w is not None and w&0x7f==0x03 and (w>>12)&7==2:
  base=(w>>15)&31;offset=signed(w>>20,12)
 elif load.mnemonic=="c.lw" and len(load.bytes)==2:
  w=int.from_bytes(bytes(load.bytes),"little")
  base=8+((w>>7)&7)
  offset=(((w>>10)&7)<<3)|(((w>>6)&1)<<2)|(((w>>5)&1)<<6)
 elif load.mnemonic=="c.lwsp" and len(load.bytes)==2:
  w=int.from_bytes(bytes(load.bytes),"little")
  base=2
  offset=(((w>>12)&1)<<5)|(((w>>4)&7)<<2)|(((w>>2)&3)<<6)
 if base is None:
  info["load_base_provenance"]="UNSUPPORTED_LOAD_OPCODE"
  return info
 upstream,location=prior_register_class(seq,ix,base)
 info.update({"load_pc":hex(load.address),"load_base_reg":base,
     "load_offset":offset,"load_base_provenance":upstream})
 if base==2 and upstream=="NOT_IN_BOUNDED_STRAIGHT_LINE":
  info["load_base_provenance"]="STACK_POINTER_UNMODELED"
 if upstream=="NOT_IN_BOUNDED_STRAIGHT_LINE" and base in range(10,18):
  info["load_base_provenance"]="ARGUMENT_REGISTER_UNMODELED"
 if upstream!="PC_REL_MATERIALIZATION" or not location:return info
 producer=next((p for p in range(ix-1,-1,-1)
               if seq[p].address==int(location["source_pc"],16)),None)
 if producer is None:return info
 instr=seq[producer];u=word(instr)
 if u is None or u&0x7f not in (0x17,0x37) or (u>>7)&31!=base:return info
 high=u&0xfffff000
 value=((instr.address if u&0x7f==0x17 else 0)+high+offset)&MASK
 info["load_base_provenance"]="STATIC_COMPUTED_BASE_REGION_NOT_YET_CONFIRMED"
 info["candidate_readonly_slot"]=hex(value)
 literal=readonly_literal(elf,value)
 if literal is None:return info
 dest=(literal+call_imm)&MASK&~1
 if dest not in entry_to_key:return info
 info["machine_proven_candidate"]={
  "kind":"BOUNDED_IMMUTABLE_ROM_POINTER",
  "slot":hex(value),"slot_value":hex(literal),"resolved_callee":hex(dest),
  "callee_function_ids":entry_to_key[dest],
  "producer_pc":hex(instr.address),"load_pc":hex(load.address),
  "dynamic_execution_proven":False,"independent_novelty_proven":False}
 return info

def inspect_revision(blob,revision,graph):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 elf=ELFFile(io.BytesIO(blob))
 targets=collections.defaultdict(list)
 funcs=graph["function_byte_evidence"][revision]
 for key,item in funcs.items():targets[int(item["entry"],16)].append(key)
 decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 decoder.skipdata=True
 hits=[];counts=collections.Counter();unknown_samples=[];source_classes=collections.Counter();source_samples=collections.defaultdict(list);base_source_samples=collections.defaultdict(list)
 for s in elf.iter_sections():
  if s["sh_type"]!="SHT_PROGBITS" or not int(s["sh_flags"])&4:continue
  base=int(s["sh_addr"]);ins=list(decoder.disasm(s.data(),base))
  addresses=[x.address for x in ins]
  import bisect
  for key,f in funcs.items():
   entry=int(f["entry"],16);end=entry+f["size_bytes"]
   if not(base<=entry<end<=base+int(s["sh_size"])):continue
   lo=bisect.bisect_left(addresses,entry);hi=bisect.bisect_left(addresses,end)
   seq=ins[lo:hi]
   if not seq or seq[0].address!=entry or seq[-1].address+seq[-1].size!=end:continue
   for i,x in enumerate(seq):
    c=decode_jalr(x)
    if c is None:continue
    if c["rs1"]==1 and c["rd"]==0 and c["imm"]==0:
     counts["return_like"]+=1;continue
    counts["unresolved_or_indirect"]+=1
    inferred=candidate_call(seq,i,elf,targets)
    if inferred:
     inferred["caller_function_id"]=key
     inferred["revision"]=revision
     hits.append(inferred);counts["machine_bytes_resolved_function_entry"]+=1
     counts[inferred["kind"]]+=1
    else:
     category,last=prior_register_class(seq,i,c["rs1"])
     base_trace=trace_load_base(seq,i,c["rs1"],elf,targets,c["imm"])
     if base_trace["machine_proven_candidate"] is not None:
      edge=dict(base_trace["machine_proven_candidate"])
      edge["caller_function_id"]=key;edge["revision"]=revision
      edge["call_pc"]=hex(x.address);edge["call_machine_bytes"]=bytes(x.bytes).hex()
      hits.append(edge);counts["machine_bytes_resolved_function_entry"]+=1
      counts["BOUNDED_IMMUTABLE_ROM_POINTER"]+=1
      continue
     source_classes[category]+=1
     source_classes["BASE_"+base_trace["load_base_provenance"]]+=1
     observed={"caller_function_id":key,"call_pc":hex(x.address),
       "machine_bytes":bytes(x.bytes).hex(),"rs1":c["rs1"],
       "rd":c["rd"],"nearest_register_source":category,"source_instruction":last,
       "base_trace":base_trace,"limitation":"Bounded byte-level register provenance, not actual call target"}
     if len(source_samples[category])<8:source_samples[category].append(observed)
     if len(base_source_samples[base_trace["load_base_provenance"]])<20:
      base_source_samples[base_trace["load_base_provenance"]].append(observed)
     if len(unknown_samples)<25:unknown_samples.append(observed)
 return {"revision":revision,"elf_sha256":hashlib.sha256(blob).hexdigest(),
  "function_bodies_indexed":len(funcs),"counts":dict(counts),
  "resolved_strict_machine_byte_edges":hits,
  "unresolved_examples":unknown_samples,
  "unresolved_register_source_classes":dict(source_classes),
  "base_classification_does_not_add_indirect_calls_without_readonly_exact_match":True,
  "unresolved_source_examples_per_class":dict(source_samples),
  "unresolved_base_examples_per_class":dict(base_source_samples),
  "dynamic_execution_proven":False,
  "supported_patterns":["AUIPC_ADDI_JALR","LUI_ADDI_JALR","AUIPC_LW_JALR","AUIPC_ADDI_LW_JALR"],
  "limitations":["Only contiguous in-function code, no dynamic indexing/relocations or mutable tables.",
    "Bounded register source classes denote nearest syntactic writer, not independently solved dataflow.",
    "An ELF STT_FUNC target with exact bytes is a structural possibility, not executed call.",
    "No physical tests; no ECV4 runtime or semantic novelty approval."]}
def evaluate(rom,graph):
 require(sha(rom)==ROM_SHA,"OFFICIAL_ROM_TAR_SHA")
 require(graph.get("schema")=="ESP32C3_ALL_ROM_FAST_GRAPH_V1","GRAPH_SCHEMA")
 require(graph.get("rom_source_sha256")==ROM_SHA,"GRAPH_ROM_SHA")
 out={}
 with tarfile.open(rom,"r:gz") as t:
  for rev in REVS:
   items=[m for m in t.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   require(len(items)==1,"ROM_REV_NOT_UNIQUE")
   blob=t.extractfile(items[0]).read()
   require(hashlib.sha256(blob).hexdigest()==graph["all_revisions"][rev]["elf_sha256"],"ELF_INPUT_MUTATED")
   out[rev]=inspect_revision(blob,rev,graph)
 return {"schema":"ROM001_STRICT_INDIRECT_V1","original_issue_id":"ESP32C3-ROM-001",
  "pinned_rom_sha256":ROM_SHA,"revisions":out,
  "verified_dynamic_calls":0,"novel_function_certified":0,
  "ECV4SuiteBridge_invoked":False}
def main():
 p=argparse.ArgumentParser()
 for f in ("rom","graph","out"):p.add_argument("--"+f,required=True,type=pathlib.Path)
 a=p.parse_args();r=evaluate(a.rom,json.loads(a.graph.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,sort_keys=True,separators=(",",":"))+"\n")
 print("ROM_STRICT_INDIRECT",json.dumps({k:v["counts"] for k,v in r["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
