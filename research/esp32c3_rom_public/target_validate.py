#!/usr/bin/env python3
"""Validate fixed ROM JAL jump targets against ELF executable bytes and named STT_FUNC."""
import csv,hashlib,io,json,pathlib,tarfile,urllib.request
from collections import Counter
from elftools.elf.elffile import ELFFile
from rom_opcode import classify
P=pathlib.Path(__file__).resolve().parent;O=P/"output"/"targets";O.mkdir(parents=True,exist_ok=True)
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
with (P/"rom_api_baseline.csv").open() as f:known=[x for x in csv.DictReader(f) if x["type"]=="function"]
if len(known)!=648:raise RuntimeError("BAD_BASELINE_COUNT")
data=urllib.request.urlopen(urllib.request.Request(URL,headers={"User-Agent":"ROM-QA-targets/1"}),timeout=120).read()
if hashlib.sha256(data).hexdigest()!=SHA:raise RuntimeError("ARCHIVE_DIGEST_MISMATCH")
summary={"schema":"ROM_JAL_TARGET_VALIDATE_V1","revisions":{},"limitations":["Target in executable segment and STT_FUNC at that exact address is not semantic proof","Known symbol to ELF symbol association is structural, not verified behavior"]}
with tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as tf:
 for filename in ("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf"):
  items=[x for x in tf.getmembers() if pathlib.PurePosixPath(x.name).name==filename]
  if len(items)!=1:raise RuntimeError("EXPECTED_EXACTLY_ONE_ELF")
  elf=ELFFile(io.BytesIO(tf.extractfile(items[0]).read()))
  secs=[(int(s["sh_addr"]),s.data(),s.name) for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS" and int(s["sh_flags"])&4]
  func={}
  for s in elf.iter_sections():
   if s["sh_type"]=="SHT_SYMTAB":
    for sym in s.iter_symbols():
     if sym["st_info"]["type"]=="STT_FUNC" and int(sym["st_value"]):
      func.setdefault(int(sym["st_value"]),[]).append(sym.name)
  results=[];stats=Counter(); mismatches=[];mismatches=[]
  for row in known:
   a=int(row["address"],16)
   source=[(base,chunk,section) for base,chunk,section in secs if base<=a<base+len(chunk)]
   if len(source)!=1:raise RuntimeError("AMBIGUOUS_SOURCE")
   base,chunk,section=source[0]
   dec=classify(chunk[a-base:a-base+8],a)
   if dec["kind"]!="JAL" or dec["target"] is None:raise RuntimeError("NOT_JAL_ENTRY")
   target=dec["target"]
   in_exec=any(x<=target<x+len(blob) for x,blob,_ in secs)
   names=func.get(target,[])
   if row["symbol"] not in names:
    mismatches.append({"rom_symbol":row["symbol"],"target":hex(target),
                       "elf_symbols":names,"reason":"NAME_ALIAS_OR_UNANNOTATED_NOT_RESOLVED"})
    stats["name_mismatch_unresolved"]+=1
   else:
    stats["matched_named_function"]+=1
   stats["valid_exec" if in_exec else "outside_exec"]+=1
   stats["exact_STT_FUNC" if names else "not_STT_FUNC"]+=1
   results.append({"known_rom_name":row["symbol"],"rom_entry":hex(a),"target":hex(target),
      "target_executable":in_exec,"elf_function_names":";".join(names),"source_section":section})
  with (O/(filename+".csv")).open("w",newline="") as f:
   writer=csv.DictWriter(f,fieldnames=list(results[0]));writer.writeheader();writer.writerows(results)
  summary["revisions"][filename]={"counts":dict(stats),"total":len(results),"sample":results[:8], "unresolved_name_mismatches":mismatches,
     "semantic_verdict":"NOT_CERTIFIED","structural_verdict":"PASS" if stats["outside_exec"]==0 and stats["not_STT_FUNC"]==0 else "REQUIRES_REVIEW"}
  if stats["outside_exec"]>0:raise RuntimeError("FAIL_CLOSED_JUMP_OUTSIDE_EXECUTABLE")
  if stats["not_STT_FUNC"]>0:raise RuntimeError("FAIL_CLOSED_JUMP_TARGET_NOT_ELF_FUNCTION")
(O/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
print(json.dumps(summary,indent=2))
if any(x["name_mismatch_count"] for x in summary["revisions"].values()):
 raise RuntimeError("FAIL_CLOSED_UNRECONCILED_LINKER_ELF_NAMES")
