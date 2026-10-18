#!/usr/bin/env python3
"""AC03: independently account for executable byte ranges and decode failures.

Metrics distinguish symbol-size gaps from unrecognized bytes and from CFG reachability.
"""
import hashlib,io,json,pathlib,tarfile,urllib.request
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"coverage";OUT.mkdir(parents=True,exist_ok=True)
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
def merged(intervals):
 output=[]
 for a,b in sorted(intervals):
  if b<=a:raise RuntimeError("BAD_RANGE")
  if output and a<=output[-1][1]:output[-1]=(output[-1][0],max(output[-1][1],b))
  else:output.append((a,b))
 return output
def coverage(segments,functions):
 executable=merged(segments)
 if sum(b-a for a,b in executable)!=sum(b-a for a,b in segments):
  raise RuntimeError("EXECUTABLE_SECTIONS_OVERLAP")
 clipped=[]
 for a,b in functions:
  for x,y in executable:
   left,right=max(a,x),min(b,y)
   if left<right:clipped.append((left,right))
 count=sum(b-a for a,b in merged(clipped))
 total=sum(b-a for a,b in executable)
 if count>total:raise RuntimeError("COVERAGE_EXCEEDS_TOTAL")
 return total,count,total-count
assert merged([(2,5),(5,10),(1,3)])==[(1,10)]
assert coverage([(0,10)],[(0,5),(4,7)])==(10,7,3)
assert coverage([(0,10)],[])==(10,0,10)
payload=urllib.request.urlopen(urllib.request.Request(URL,headers={"User-Agent":"rom-coverage-audit/1"}),timeout=120).read()
if hashlib.sha256(payload).hexdigest()!=SHA:raise RuntimeError("ARCHIVE_DIGEST_MISMATCH")
existing=json.loads((ROOT/"output"/"entry_audit"/"entry_audit_summary.json").read_text())
report={"schema":"ROM_AC03_INDEPENDENT_COVERAGE_V1","source_sha256":SHA,"independent_synthetic_tests":3,
"revision_metrics":{},"limits":["Symbol size coverage is not verified CFG reachability","Linear disassembly may decode embedded data as valid instructions","Non-ELF-STT_FUNC-covered bytes are not automatically unclassified code"]}
with tarfile.open(fileobj=io.BytesIO(payload),mode="r:gz") as tar:
 for name in REVS:
  found=[x for x in tar.getmembers() if pathlib.PurePosixPath(x.name).name==name]
  if len(found)!=1:raise RuntimeError("MISSING_ELF")
  elf=ELFFile(io.BytesIO(tar.extractfile(found[0]).read()))
  sections=[s for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS" and int(s["sh_flags"])&4]
  intervals=[(int(s["sh_addr"]),int(s["sh_addr"])+int(s["sh_size"])) for s in sections]
  funcs=[]
  for s in elf.iter_sections():
   if s["sh_type"]=="SHT_SYMTAB":
    for sym in s.iter_symbols():
     if sym["st_info"]["type"]=="STT_FUNC" and int(sym["st_size"])>0:
      a=int(sym["st_value"]);funcs.append((a,a+int(sym["st_size"])))
  total,within,notcovered=coverage(intervals,funcs)
  decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC);decoder.skipdata=True
  undecoded=0;decoded=0;instruction_count=0
  for section in sections:
   start=int(section["sh_addr"]);size=int(section["sh_size"])
   seen=0
   for ins in decoder.disasm(section.data(),start):
    seen+=ins.size
    if ins.mnemonic==".byte":undecoded+=ins.size
    else:decoded+=ins.size;instruction_count+=1
   if seen!=size:raise RuntimeError("MISSING_SECTION_BYTES:"+name+":"+section.name)
  if decoded+undecoded!=total:raise RuntimeError("NON_EXHAUSTIVE_LINEAR_SCAN")
  prior=existing["revisions"][name]
  if total!=prior["executable_bytes"] or within!=prior["covered_by_ELF_STT_FUNC_size_intervals_bytes"] or notcovered!=prior["not_covered_by_ELF_STT_FUNC_size_intervals_bytes"]:
   raise RuntimeError("INDEPENDENT_ELF_METRICS_DISAGREE:"+name)
  report["revision_metrics"][name]={"executable_bytes":total,"symbol_size_covered_bytes":within,
   "not_symbol_size_covered_bytes":notcovered,"symbol_size_gap_percentage":round(100*notcovered/total,5),
   "linearly_decoded_bytes":decoded,"undecodable_bytes":undecoded,
   "undecodable_percentage":round(100*undecoded/total,5),"instruction_count":instruction_count,
   "cfg_reachability":"NOT_CERTIFIED"}
(OUT/"ac03.json").write_text(json.dumps(report,indent=2)+"\n")
print("AC03_COVERAGE_AUDIT",json.dumps(report,sort_keys=True))
