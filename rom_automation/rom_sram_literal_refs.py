#!/usr/bin/env python3
"""ROM-001: static SRAM indirect slot references in original ELF data/code.

Scan immutable byte words for the nine unresolved SRAM addresses and exact
PC relative HI20/LO12 pairs. Raw code word coincidences are only hints.
No ROM writes, no actual memory contents, no new callback edge certified.
"""
import argparse,hashlib,io,json,pathlib,tarfile,collections
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,REVS,require,sha
from rom_sram_writer_audit import collect_sram_slots
from rom_strict_indirect import official_c3_memory_region

def scan_one(blob,rev,targets):
 elf=ELFFile(io.BytesIO(blob))
 bytarget={n:{"nonexec_little_endian_word_refs":[],"exec_word_coincidences":[],"section_relative_offsets":[]} for n in sorted(targets)}
 totals=collections.Counter()
 for section in elf.iter_sections():
  if section["sh_type"]!="SHT_PROGBITS" or not int(section["sh_flags"])&2 or not int(section["sh_size"]):continue
  base=int(section["sh_addr"]);raw=section.data();xflag=bool(int(section["sh_flags"])&4)
  for n in sorted(targets):
   needle=n.to_bytes(4,"little")
   # Seek exact little-endian data slot, preserve source section/offset
   i=raw.find(needle)
   while i>=0:
    address=base+i;is_aligned=address%4==0
    if is_aligned:
     key="exec_word_coincidences" if xflag else "nonexec_little_endian_word_refs"
     if len(bytarget[n][key])<20:
      bytarget[n][key].append({"source":hex(address),"section":section.name,"byte_offset":i})
     totals[key]+=1
    i=raw.find(needle,i+1)
  # Section-relative 32-bit words are not execution proofs; gather only if exactly a target offset.
  for n in sorted(targets):
   relative=n-base
   if 0<=relative<=len(raw)-4 and not xflag:
    bytarget[n]["section_relative_offsets"].append({"section":section.name,"offset":relative})
 return {"revision":rev,"targets":{hex(a):bytarget[a] for a in sorted(targets)},
  "counts":dict(totals),"confirmed_callback_edges":0,
  "limitations":["Exact ELF stored bytes only; runtime SRAM initialized by another image or peripheral is not visible.",
   "No flow from these bytes to a JALR instruction is proven.",
   "Section-relative offsets may be incidental and not pointer-table entries."]}

def evaluate(rom,strict,writer):
 require(sha(rom)==ROM_SHA,"PINNED_ROM_SOURCE")
 require(writer.get("schema")=="ROM001_SRAM_INDIRECT_SOURCE_STORE_PROVENANCE_V1","WRITER_SOURCE_SCHEMA")
 require(writer["source_ROM_sha256"]==ROM_SHA,"WRITER_INPUT_HASH")
 slots=collect_sram_slots(strict)
 missing={}
 for rev in REVS:
  resolved={int(x["target_sram_slot"],16) for x in writer["revisions"][rev]["exact_address_store_candidates"]}
  missing[rev]=slots[rev]-resolved
  require(len(missing[rev])==9,"NINE_UNRESOLVED_SLOT_DRIFT")
  require(all(official_c3_memory_region(x)=="INTERNAL_SRAM" for x in missing[rev]),"NON_SRAM_TARGET")
 results={}
 with tarfile.open(rom,"r:gz") as t:
  for rev in REVS:
   matches=[m for m in t.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   require(len(matches)==1,"ROM_REVISION_MISSING")
   blob=t.extractfile(matches[0]).read()
   results[rev]=scan_one(blob,rev,missing[rev])
 return {"schema":"ROM001_NINE_SRAM_LITERAL_DATA_REFS_V1",
  "original_issue_id":"ESP32C3-ROM-001",
  "ROM_SHA256":ROM_SHA,"revisions":results,
  "silicon_verified":False,"new_callback_link_proven":False}
def main():
 p=argparse.ArgumentParser()
 for key in ("rom","strict","writer","out"):p.add_argument("--"+key,required=True,type=pathlib.Path)
 a=p.parse_args()
 result=evaluate(a.rom,json.loads(a.strict.read_text()),json.loads(a.writer.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
 print("ROM_SRAM_LITERAL_REFERENCES",json.dumps({rev:v["counts"] for rev,v in result["revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
