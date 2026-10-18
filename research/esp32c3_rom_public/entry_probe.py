#!/usr/bin/env python3
"""Audit linker entrypoints using two independent fixed decoders and ELF section bytes.
Not proof of callability or semantic validity. Tests are negative as well as positive.
"""
import csv,hashlib,io,json,pathlib,tarfile,urllib.request
from collections import Counter
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
from rom_opcode import classify
P=pathlib.Path(__file__).resolve().parent
O=P/"output"/"entry_probe";O.mkdir(parents=True,exist_ok=True)
U="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
with (P/"rom_api_baseline.csv").open() as f: refs=[r for r in csv.DictReader(f) if r["type"]=="function"]
if len(refs)!=648: raise RuntimeError("BASELINE_MISMATCH")
blob=urllib.request.urlopen(urllib.request.Request(U,headers={"User-Agent":"ROM-QA/1"}),timeout=120).read()
if hashlib.sha256(blob).hexdigest()!=SHA:raise RuntimeError("ARCHIVE_SHA_MISMATCH")
report={"schema":"ROM_ENTRY_DOUBLE_DECODE_V1","source_sha256":SHA,"revisions":{}}
with tarfile.open(fileobj=io.BytesIO(blob),mode="r:gz") as archive:
 for name in ("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf"):
  matches=[m for m in archive.getmembers() if pathlib.Path(m.name).name==name]
  if len(matches)!=1:raise RuntimeError("ELF_COUNT_MISMATCH")
  elf=ELFFile(io.BytesIO(archive.extractfile(matches[0]).read()))
  sections=[(int(s["sh_addr"]),s.data(),s.name) for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS" and int(s["sh_flags"])&4]
  cs=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
  out=[]; counts=Counter()
  for r in refs:
   addr=int(r["address"],16)
   candidates=[(base,code,section) for base,code,section in sections if base<=addr<base+len(code)]
   if len(candidates)!=1:raise RuntimeError("ROM_ENTRY_SECTION_INVALID")
   base,code,section=candidates[0];chunk=code[addr-base:addr-base+12]
   decoded=list(cs.disasm(chunk,addr,count=1))
   if not decoded or decoded[0].address!=addr:raise RuntimeError("ROM_ENTRY_DECODE_FAILED")
   instr=decoded[0]
   custom=classify(chunk,addr)
   if custom["kind"] in ("JAL","C_J_OR_C_JAL","AUIPC_JALR"):
    if custom["target"] is None:raise RuntimeError("BRANCH_TARGET_NONE")
   counts[custom["kind"]]+=1
   out.append({"name":r["symbol"],"address":hex(addr),"section":section,
     "raw_8b":chunk[:8].hex(),"capstone_mnemonic":instr.mnemonic,"capstone_op_str":instr.op_str,
     "custom_kind":custom["kind"],"custom_target":"" if custom["target"] is None else hex(custom["target"])})
  if len(out)!=648:raise RuntimeError("ENTRY_ROWS_WRONG")
  with (O/(name+".csv")).open("w",newline="") as f:
   w=csv.DictWriter(f,fieldnames=list(out[0]));w.writeheader();w.writerows(out)
  report["revisions"][name]={"entries":len(out),"class_counts":dict(counts),"first_twelve":out[:12],
    "unknown_semantics":"Not determined: byte decoding alone does not prove an API or side effects"}
(O/"summary.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps(report,indent=2))
