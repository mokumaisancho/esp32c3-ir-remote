#!/usr/bin/env python3
"""ROM-001: prove constant-address SRAM store sites feeding unresolved JALR slots.

Uses official ROM binary and typed machine instructions, no runtime effects
claimed. Read traces identify SRAM slots, not their values. Only stores with a
statically reconstructed destination are credited as initializer candidates.
"""
import argparse,bisect,collections,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile
from decision_gate import REVS,ROM_SHA,require,sha
from rom_strict_indirect import word,signed,probable_last_writer,official_c3_memory_region

def real_store(ins):
 raw=bytes(ins.bytes)
 if len(raw)==2:
  c=int.from_bytes(raw,"little")
  # RV32C C.SW: quadrant 0, funct3 110, compact base/data registers.
  if c&3==0 and c>>13&7==6:
   offset=((c>>10&7)<<3)|((c>>6&1)<<2)|((c>>5&1)<<6)
   return {"base_reg":8+((c>>7)&7),"value_reg":8+((c>>2)&7),
    "offset":offset,"width_bytes":4,"machine_bytes":raw.hex(),"encoding":"C.SW"}
  # RV32C C.SWSP: quadrant 2, funct3 110, base SP.
  if c&3==2 and c>>13&7==6:
   offset=((c>>9&15)<<2)|((c>>7&3)<<6)
   return {"base_reg":2,"value_reg":(c>>2)&31,
    "offset":offset,"width_bytes":4,"machine_bytes":raw.hex(),"encoding":"C.SWSP"}
 w=word(ins)
 if w is not None and w&0x7f==0x23 and (w>>12)&7 in (0,1,2):
  imm=((w>>25)&0x7f)<<5 | ((w>>7)&0x1f)
  return {"base_reg":(w>>15)&31,"value_reg":(w>>20)&31,
   "offset":signed(imm,12),"width_bytes":1<<((w>>12)&7),
   "machine_bytes":bytes(ins.bytes).hex(),"encoding":"RV32I_STORE"}
 return None

def nearest_writer_index(seq,limit,reg,window=32):
 """Within one linear/basic-block window. Branch barrier stops search."""
 control={"beq","bne","blt","bge","bltu","bgeu","bgez","bltz",
  "beqz","bnez","blez","bgtz","c.beqz","c.bnez",
  "c.j","j","c.jal","jal","jalr","c.jalr","jr","c.jr","ret",
  "ecall","ebreak"}
 for i in range(limit-1,max(-1,limit-window-1),-1):
  if seq[i].mnemonic in control:return None
  writer=probable_last_writer(seq[i])
  if writer and writer[0]==reg:return i
 return None

def static_register_value(seq,prior,reg,depth=3):
 if depth<=0:return None
 ix=nearest_writer_index(seq,prior,reg)
 if ix is None:return None
 ins=seq[ix];w=word(ins)
 if w is None:return None
 op=w&0x7f;rd=(w>>7)&31
 if rd!=reg:return None
 if op in (0x17,0x37):
  return (((ins.address if op==0x17 else 0)+(w&0xfffff000))&0xffffffff,
   [{"pc":hex(ins.address),"raw":bytes(ins.bytes).hex(),"kind":"AUIPC" if op==0x17 else "LUI"}])
 if op==0x13 and (w>>12)&7==0:
  rs=(w>>15)&31;imm=signed(w>>20,12)
  if rs==0:return (imm&0xffffffff,[{"pc":hex(ins.address),"raw":bytes(ins.bytes).hex(),"kind":"ADDI_FROM_ZERO"}])
  earlier=static_register_value(seq,ix,rs,depth-1)
  if earlier is None:return None
  return ((earlier[0]+imm)&0xffffffff,earlier[1]+[{"pc":hex(ins.address),"raw":bytes(ins.bytes).hex(),"kind":"ADDI"}])
 return None

def detect_store(seq,ix,target_slots):
 ins=seq[ix];op=real_store(ins)
 if op is None:return None
 earlier=static_register_value(seq,ix,op["base_reg"])
 if earlier is None:return None
 addr=(earlier[0]+op["offset"])&0xffffffff
 if addr not in target_slots:return None
 return {"store_pc":hex(ins.address),"store_binary":op["machine_bytes"],
   "target_sram_slot":hex(addr),"stored_value_register":op["value_reg"],
   "width_bytes":op["width_bytes"],"instruction_encoding":op["encoding"],"address_provenance":earlier[1],
   "target_region":official_c3_memory_region(addr),
   "actual_written_function_pointer_value":None,
   "runtime_execution_verified":False}

def collect_sram_slots(strict):
 require(strict.get("schema")=="ROM001_STRICT_INDIRECT_V1","STRICT_SOURCE_SCHEMA")
 require(strict.get("pinned_rom_sha256")==ROM_SHA,"STRICT_SOURCE_SHA")
 out={}
 for rev in REVS:
  src=strict["revisions"][rev]["unresolved_base_examples_per_class"]
  arr=src["STATIC_COMPUTED_BASE_REGION_NOT_YET_CONFIRMED"]
  require(len(arr)==20,"MISSING_P0_EXAMPLES:"+rev)
  slots={int(x["base_trace"]["candidate_readonly_slot"],16) for x in arr}
  require(len(slots)==13,"SRAM_SLOT_COUNT_DRIFT:"+rev)
  require(all(official_c3_memory_region(a)=="INTERNAL_SRAM" for a in slots),"NON_SRAM_SOURCE")
  out[rev]=slots
 return out

def scan_one(blob,rev,graph,target_slots):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 elf=ELFFile(io.BytesIO(blob))
 decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC);decoder.skipdata=True
 functions=graph["function_byte_evidence"][rev]
 all_sites=[];total_stores=0
 for section in elf.iter_sections():
  if section["sh_type"]!="SHT_PROGBITS" or not int(section["sh_flags"])&4:continue
  start=int(section["sh_addr"]);data=section.data()
  ins=list(decoder.disasm(data,start));pcs=[x.address for x in ins]
  for fn_id,entry in functions.items():
   a=int(entry["entry"],16);b=a+entry["size_bytes"]
   if not(start<=a<b<=start+len(data)):continue
   lo=bisect.bisect_left(pcs,a);hi=bisect.bisect_left(pcs,b)
   seq=ins[lo:hi]
   if not seq or seq[0].address!=a or seq[-1].address+seq[-1].size!=b:continue
   for i,obj in enumerate(seq):
    if real_store(obj) is None:continue
    total_stores+=1
    hit=detect_store(seq,i,target_slots)
    if hit:
     hit["function_id"]=fn_id;hit["aliases"]=entry["aliases"]
     all_sites.append(hit)
 return {"revision":rev,"candidate_indirect_sram_slots":[hex(x) for x in sorted(target_slots)],
  "function_bodies":len(functions),"all_RV32I_store_instructions":total_stores,
  "exact_address_store_candidates":all_sites,
  "exact_address_store_candidate_count":len(all_sites),
  "dynamic_table_initialized_verified":False,
  "unresolved_slots":[hex(x) for x in sorted(target_slots-set(int(x["target_sram_slot"],16) for x in all_sites))],
  "limitations":["Only RV32I 32bit SB/SH/SW with bounded PC-relative or absolute base; compressed stores and register-pointer writes not solved.",
    "Match proves a possible static store destination inside a function-sized ELF region, not executed initialization.",
    "Stored register value is UNKNOWN, so linkage from RAM table to callee is NOT proven."]}

def evaluate(rom,graph,strict):
 require(sha(rom)==ROM_SHA,"OFFICIAL_PINNED_ROM")
 require(graph.get("schema")=="ESP32C3_ALL_ROM_FAST_GRAPH_V1" and graph["rom_source_sha256"]==ROM_SHA,"GRAPH_SOURCE")
 targets=collect_sram_slots(strict);per={}
 with tarfile.open(rom,"r:gz") as tar:
  for rev in REVS:
   entries=[m for m in tar.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   require(len(entries)==1,"ROM_REV_INCOMPLETE")
   blob=tar.extractfile(entries[0]).read()
   require(hashlib.sha256(blob).hexdigest()==graph["all_revisions"][rev]["elf_sha256"],"ELF_SHA")
   per[rev]=scan_one(blob,rev,graph,targets[rev])
 return {"schema":"ROM001_SRAM_INDIRECT_SOURCE_STORE_PROVENANCE_V1",
  "original_issue_id":"ESP32C3-ROM-001","source_ROM_sha256":ROM_SHA,
  "revisions":per,"new_executed_function_links_certified":0,
  "independent_hardware_test_count":0,"ECV4_runtime_invoked":False}
def main():
 p=argparse.ArgumentParser()
 for k in ("rom","graph","strict","out"):p.add_argument("--"+k,required=True,type=pathlib.Path)
 a=p.parse_args()
 result=evaluate(a.rom,json.loads(a.graph.read_text()),json.loads(a.strict.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
 print("ROM_SRAM_WRITER_AUDIT",json.dumps({
  r:{"slots":len(v["candidate_indirect_sram_slots"]),
     "stores":v["all_RV32I_store_instructions"],
     "statically_addressed_sites":v["exact_address_store_candidate_count"],
     "slots_still_unresolved":len(v["unresolved_slots"])}
  for r,v in result["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
