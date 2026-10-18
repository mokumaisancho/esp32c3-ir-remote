#!/usr/bin/env python3
"""Deterministic cross-revision comparison of four Wi-Fi MAC ROM function bodies.
No inference of hardware behavior from absent direct edges.
"""
import hashlib,io,json,pathlib,tarfile,urllib.request
from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
from elftools.elf.elffile import ELFFile
from rom_opcode import jal,compressed_jump
ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"mac_revision_diff";OUT.mkdir(parents=True,exist_ok=True)
NAMES=("wdev_mac_sleep","wdev_mac_wakeup","hal_disable_mac","hal_enable_mac")
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
def scan(elf):
 syms={}
 for sec in elf.iter_sections():
  if sec["sh_type"]=="SHT_SYMTAB":
   for sym in sec.iter_symbols():
    if sym.name in NAMES and sym["st_info"]["type"]=="STT_FUNC":
     syms.setdefault(sym.name,[]).append((int(sym["st_value"]),int(sym["st_size"])))
 sections=[s for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS" and int(s["sh_flags"])&4]
 decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC);decoder.skipdata=True
 out={}
 for name in NAMES:
  places=set(syms.get(name,[]))
  if len(places)!=1:raise RuntimeError("FUNCTION_MISSING_OR_MULTIPLE:"+name+":"+str(places))
  address,size=next(iter(places))
  section=[s for s in sections if int(s["sh_addr"])<=address and address+size<=int(s["sh_addr"])+int(s["sh_size"])]
  if len(section)!=1 or not size:raise RuntimeError("BODY_OUTSIDE_SECTION:"+name)
  sec=section[0];body=sec.data()[address-int(sec["sh_addr"]):address-int(sec["sh_addr"])+size]
  instructions=list(decoder.disasm(body,address))
  if sum(i.size for i in instructions)!=size or any(i.mnemonic==".byte" for i in instructions):
   raise RuntimeError("BODY_NOT_FULLY_DECODED:"+name)
  direct=[];indirect=[];mnemonics=[]
  for ins in instructions:
   mnemonics.append(ins.mnemonic)
   raw=bytes(ins.bytes);dst=jal(raw,ins.address)
   if dst is None:dst=compressed_jump(raw,ins.address)
   if dst is not None:direct.append({"pc":hex(ins.address),"target":hex(dst),"kind":ins.mnemonic})
   if ins.mnemonic in ("jalr","c.jalr","c.jr","jr"):indirect.append({"pc":hex(ins.address),"mnemonic":ins.mnemonic,"operands":ins.op_str})
  out[name]={"start":hex(address),"size":size,"sha256":hashlib.sha256(body).hexdigest(),
    "instruction_count":len(instructions),"mnemonic_sequence":mnemonics,"direct_transfers":direct,"indirect_transfers":indirect,
    "instruction_evidence":[{"pc":hex(i.address),"hex":bytes(i.bytes).hex(),"mnemonic":i.mnemonic,"operands":i.op_str} for i in instructions]}
 return out
req=urllib.request.Request(URL,headers={"User-Agent":"rom-mac-revision-audit/1"})
archive=urllib.request.urlopen(req,timeout=120).read()
if hashlib.sha256(archive).hexdigest()!=SHA:raise RuntimeError("SHA_MISMATCH")
result={"schema":"ESP32C3_MAC_REVISION_BODY_DIFF_V1","archive_sha256":SHA,"revision_bodies":{},"cautions":["Direct branch presence is not runtime behavior","Cannot resolve register-indirect calls without dataflow","Machine code hash inequality does not establish semantic inequality"]}
with tarfile.open(fileobj=io.BytesIO(archive),mode="r:gz") as tar:
 for rev in REVS:
  found=[m for m in tar.getmembers() if pathlib.PurePosixPath(m.name).name==rev]
  if len(found)!=1:raise RuntimeError("ELF_NOT_UNIQUE")
  elf=ELFFile(io.BytesIO(tar.extractfile(found[0]).read()))
  result["revision_bodies"][rev]=scan(elf)
  (OUT/(rev+".json")).write_text(json.dumps(result["revision_bodies"][rev],indent=2)+"\n")
summary={}
for name in NAMES:
 rows={rev:result["revision_bodies"][rev][name] for rev in REVS}
 summary[name]={"size_by_rev":{rev:x["size"] for rev,x in rows.items()},
   "direct_transfer_count":{rev:len(x["direct_transfers"]) for rev,x in rows.items()},
   "indirect_transfer_count":{rev:len(x["indirect_transfers"]) for rev,x in rows.items()},
   "same_machine_code_all_revisions":len({x["sha256"] for x in rows.values()})==1,
   "same_mnemonic_sequence_all_revisions":len({tuple(x["mnemonic_sequence"]) for x in rows.values()})==1}
result["comparison"]=summary
(OUT/"summary.json").write_text(json.dumps(result,indent=2)+"\n")
print("MAC_REVISION_DIFF_RESULT "+json.dumps({"schema":result["schema"],"comparison":summary},sort_keys=True))
