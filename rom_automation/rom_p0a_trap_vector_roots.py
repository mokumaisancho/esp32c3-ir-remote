#!/usr/bin/env python3
"""ROM-001 P0-A other roots: machine-byte mtvec/mtvt CSR writers and ELF relocations.

A real mtvec write is a *potential* trap/exception entry root. Its source
register value can be independently recovered only from exact adjacent
RISC-V LUI/ADDI or AUIPC/ADDI without intervening register mutation.
Both named STT_FUNC instructions and boot-root-CFG visited PC addresses
are eligible. Code byte coincidences from all other gap bytes are ignored.
No silicon execution or trap firing is asserted.
"""
import argparse,bisect,collections,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,REVS,require,sha
from rom_fast_graph import make_symbol_index
from new_function_hunt import merged
from rom_p0a_indirect_roots import build_gaps,in_gap

VECTORS={0x305:"mtvec",0x307:"mtvt"}
def sext(v,bits):
 return v-(1<<bits) if v & (1<<(bits-1)) else v

def csr_vector_write(raw):
 if len(raw)!=4:return None
 w=int.from_bytes(raw,"little")
 if w&127!=0x73:return None
 csr=(w>>20)&0xfff;operation=(w>>12)&7
 rs=(w>>15)&31
 if csr not in VECTORS or operation not in (1,2,3,5,6,7):return None
 if operation in (2,3,6,7) and rs==0:return None
 return {"csr":hex(csr),"name":VECTORS[csr],
   "writer_value_register":rs if operation in (1,2,3) else None,
   "csr_operation":operation,"immediate_value":rs if operation in (5,6,7) else None,
   "is_overwrite":operation in (1,5),"source_raw_machine_bytes":raw.hex()}

def resolve_adjacent_value(history,write_pc,register):
 """Evidence only for adjacent raw 32-bit defining opcodes. No fallthrough/alias."""
 if register is None:return None
 if register==0:return {"value":0,"kind":"CONSTANT_X0","origin":[]}
 last=[(pc,bytes(raw)) for pc,raw in history if pc<write_pc]
 if not last:return None
 lastpc,raw=last[-1]
 if lastpc+len(raw)!=write_pc or len(raw)!=4:return None
 w=int.from_bytes(raw,"little");op=w&127
 rd=(w>>7)&31
 if rd!=register:return None
 if op==0x37:
  return {"value":w&0xfffff000,"kind":"EXACT_PRECEDING_LUI","origin":[hex(lastpc)]}
 if op==0x13 and (w>>12)&7==0:
  rs=(w>>15)&31;delta=sext((w>>20)&0xfff,12)
  if rs==0:
   return {"value":delta&0xffffffff,"kind":"ADDI_FROM_X0","origin":[hex(lastpc)]}
  if rs!=register or len(last)<2:return None
  prevpc,prevraw=last[-2]
  if prevpc+len(prevraw)!=lastpc or len(prevraw)!=4:return None
  prev=int.from_bytes(prevraw,"little")
  if ((prev>>7)&31)!=register:return None
  if prev&127==0x37:
   return {"value":((prev&0xfffff000)+delta)&0xffffffff,
           "kind":"ADJACENT_LUI_ADDI","origin":[hex(prevpc),hex(lastpc)]}
  if prev&127==0x17:
   return {"value":(prevpc+(prev&0xfffff000)+delta)&0xffffffff,
           "kind":"ADJACENT_AUIPC_ADDI","origin":[hex(prevpc),hex(lastpc)]}
 return None

def scan_elf(blob,rev,graph,boot):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 elf=ELFFile(io.BytesIO(blob))
 sections,bounds,pairs,owners,entries,zeros=make_symbol_index(elf)
 gaps=build_gaps(bounds,pairs)
 boot_pcs={int(x,16) for x in boot["bounded_entry_CFG"]["all_visited_pcs_sample"]}
 require(len(boot_pcs)==boot["bounded_entry_CFG"]["visited_gap_instructions"]<=100,
         "BOOT_ROOT_SAMPLE_NOT_EXHAUSTIVE")
 covered=merged(pairs);starts=[a for a,b in covered]
 def in_func(pc,length):
  i=bisect.bisect_right(starts,pc)-1
  return i>=0 and pc+length<=covered[i][1]
 def target_context(addr):
  known=owners(addr)
  return {"in_ROM_exec":any(a<=addr<b for a,b in bounds),
   "in_ELF_symbol_coverage":bool(known),
   "in_unlabelled_executable_gap":in_gap(gaps,addr),
   "matching_symbols":[entries[f"{a:08x}:{b-a:x}"]["aliases"] for a,b in known]}
 decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 decoder.skipdata=True
 writes=[];read_only=0;static_counts=collections.Counter()
 for sec in sections:
  base=int(sec["sh_addr"]);contents=sec.data()
  ins=list(decoder.disasm(contents,base))
  require(sum(x.size for x in ins)==len(contents),"DISASM_BYTES_MISSING")
  for i,obj in enumerate(ins):
   if not (in_func(obj.address,obj.size) or obj.address in boot_pcs):continue
   raw=bytes(obj.bytes)
   w=csr_vector_write(raw)
   if w is None:
    if len(raw)==4 and int.from_bytes(raw,"little")&127==0x73 and
       (int.from_bytes(raw,"little")>>20)&0xfff in VECTORS:
      read_only+=1
    continue
   static_counts[w["name"]]+=1
   hist=[(x.address,bytes(x.bytes)) for x in ins[max(0,i-2):i]]
   resolved=resolve_adjacent_value(hist,obj.address,w["writer_value_register"])
   if resolved is None and w["immediate_value"] is not None:
    resolved={"value":w["immediate_value"],"kind":"CSR_IMMEDIATE_ZIMM","origin":[hex(obj.address)]}
   ctx=None
   if resolved is not None:
    value=resolved["value"]
    # mtvec low two bits encode mode; all other bits are base.
    base_addr=value&~3 if w["name"]=="mtvec" else value
    ctx=target_context(base_addr)
    ctx.update({"raw_written_value":hex(value),"potential_vector_base":hex(base_addr),
                "csr_mode_low_bits":value&3,"value_provenance":resolved})
   writes.append({"pc":hex(obj.address),**w,
    "source_type":"NAMED_STT_FUNC" if in_func(obj.address,obj.size) else "ELF_ENTRY_ROOT_REACHABLE_UNNAMED",
    "raw_adjacent_definition_witnesses":[{"pc":hex(x),"raw":b.hex()} for x,b in hist],
    "static_value_only_if_adjacent":ctx,
    "runtime_written_value_verified":False,
    "trap_vector_real_execution_verified":False})
 reloc=[{"section":sec.name,"count":sec.num_relocations()} for sec in elf.iter_sections()
        if sec["sh_type"] in ("SHT_REL","SHT_RELA")]
 return {"revision":rev,"elf_sha256":hashlib.sha256(blob).hexdigest(),
  "mtvec_mtvt_possible_static_writes":len(writes),
  "writes_by_vector_CSR":dict(static_counts),
  "vector_CSR_read_only_or_nonwriting_pattern_count":read_only,
  "proven_adjacent_static_values":sum(x["static_value_only_if_adjacent"] is not None for x in writes),
  "potential_trap_roots_in_unlabelled_ROM":sum(
   bool(x["static_value_only_if_adjacent"] and
        x["static_value_only_if_adjacent"]["in_unlabelled_executable_gap"]) for x in writes),
  "relocation_section_inventory":reloc,
  "ELF_relocation_count":sum(x["count"] for x in reloc),
  "writers":writes,
  "silicon_trap_dispatch_verified":0,
  "coverage_limit":["Only positive-size STT_FUNC sections and the confirmed boot root 55 addresses, not all possible control-flow.",
   "Register values from non-adjacent calculations, tables, compressed encodings and runtime initialization are unresolved.",
   "CSRRS/CSRRC with zero source are read-only, not a vector write.",
   "Relocations in the published ELF do not include runtime linked application code."]}

def evaluate(rom,graph,entry):
 require(sha(rom)==ROM_SHA,"PINNED_ROM_ARCHIVE_SHA")
 require(graph["schema"]=="ESP32C3_ALL_ROM_FAST_GRAPH_V1" and
  graph["rom_source_sha256"]==ROM_SHA,"GRAPH_IDENTITY")
 require(entry["schema"]=="ROM001_P0A_ELF_ENTRY_TRAMPOLINE_V1" and
  entry["ROM_sha256"]==ROM_SHA,"ENTRY_ROOT_IDENTITY")
 output={}
 with tarfile.open(rom,mode="r:gz") as tar:
  for rev in REVS:
   blobrefs=[x for x in tar.getmembers() if x.isfile() and pathlib.PurePosixPath(x.name).name==rev]
   require(len(blobrefs)==1,"ROM_REV_MISSING")
   blob=tar.extractfile(blobrefs[0]).read()
   require(hashlib.sha256(blob).hexdigest()==graph["all_revisions"][rev]["elf_sha256"],"REV_SOURCE_SHA")
   output[rev]=scan_elf(blob,rev,graph,entry["revisions"][rev])
 return {"schema":"ROM001_P0A_OTHER_TRAP_VECTOR_ROOTS_V1",
   "original_issue_id":"ESP32C3-ROM-001","ROM_SHA256":ROM_SHA,
   "revisions":output,"new_function_proven":0,"device_observation":0}

def main():
 p=argparse.ArgumentParser()
 for name in ("rom","graph","entry","out"):
  p.add_argument("--"+name,required=True,type=pathlib.Path)
 a=p.parse_args()
 r=evaluate(a.rom,json.loads(a.graph.read_text()),json.loads(a.entry.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
 print("ROM_P0A_TRAP_ROOTS",json.dumps({
  rev:{k:v[k] for k in ("mtvec_mtvt_possible_static_writes","writes_by_vector_CSR",
      "proven_adjacent_static_values","potential_trap_roots_in_unlabelled_ROM",
      "ELF_relocation_count")} for rev,v in r["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
