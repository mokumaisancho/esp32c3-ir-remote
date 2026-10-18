#!/usr/bin/env python3
"""One-shot MAC delta RCA: all changed instructions, resolved calls, and independent GNU machine words."""
import hashlib,io,json,pathlib,re,subprocess,tarfile,tempfile,urllib.request,difflib
from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
from elftools.elf.elffile import ELFFile
from rom_opcode import jal,compressed_jump
ROOT=pathlib.Path(__file__).resolve().parent;OUT=ROOT/"output"/"mac_rca";OUT.mkdir(parents=True,exist_ok=True)
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
FUNCTIONS=("wdev_mac_sleep","wdev_mac_wakeup","hal_disable_mac","hal_enable_mac")
def analyze(elf):
 symbols={};addr={}
 for sec in elf.iter_sections():
  if sec["sh_type"]=="SHT_SYMTAB":
   for sym in sec.iter_symbols():
    if sym["st_info"]["type"]=="STT_FUNC" and int(sym["st_value"]):
     addr.setdefault(int(sym["st_value"]),set()).add(sym.name)
     if sym.name in FUNCTIONS:symbols.setdefault(sym.name,set()).add((int(sym["st_value"]),int(sym["st_size"])))
 sections=[s for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS" and int(s["sh_flags"])&4]
 cs=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 funcs={}
 for name in FUNCTIONS:
  candidates=symbols.get(name,set())
  if len(candidates)!=1:raise RuntimeError("FUNCTION_SYMBOL_MISSING_OR_AMBIGUOUS:"+name)
  start,size=next(iter(candidates))
  sect=[s for s in sections if int(s["sh_addr"])<=start and start+size<=int(s["sh_addr"])+int(s["sh_size"])]
  if len(sect)!=1:raise RuntimeError("FUNCTION_OUTSIDE_SECTION:"+name)
  body=sect[0].data()[start-int(sect[0]["sh_addr"]):start-int(sect[0]["sh_addr"])+size]
  inst=list(cs.disasm(body,start))
  if sum(x.size for x in inst)!=size:raise RuntimeError("UNDECODED_FUNCTION:"+name)
  rows=[];calls=[]
  for ins in inst:
   target=jal(bytes(ins.bytes),ins.address)
   if target is None:target=compressed_jump(bytes(ins.bytes),ins.address)
   row={"pc":hex(ins.address),"hex":bytes(ins.bytes).hex(),"mnemonic":ins.mnemonic,"operands":ins.op_str}
   if target is not None:
    row["target"]=hex(target);row["target_function_names"]=sorted(addr.get(target,()))
    calls.append(row)
   elif ins.mnemonic in ("jalr","c.jalr","jr","c.jr"):calls.append({**row,"target":"UNRESOLVED_INDIRECT"})
   rows.append(row)
  funcs[name]={"address":hex(start),"size":size,"sha256":hashlib.sha256(body).hexdigest(),"body_hex":body.hex(),"instructions":rows,"calls_and_jumps":calls}
 return funcs
def verify_objdump(elfpath, funcs):
 output=subprocess.check_output(["riscv64-linux-gnu-objdump","-d",str(elfpath)],text=True,timeout=120)
 parsed={}
 for line in output.splitlines():
  m=re.match(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{4}|[0-9a-fA-F]{8})\s+",line)
  if m:parsed[int(m.group(1),16)]=m.group(2).lower()
 for name,fn in funcs.items():
  for ins in fn["instructions"]:
   pc=int(ins["pc"],16)
   if parsed.get(pc)!=bytes.fromhex(ins["hex"])[::-1].hex():
    raise RuntimeError("GNU_CAPSTONE_WORD_MISMATCH:"+name+":"+ins["pc"])
 return True
req=urllib.request.Request(URL,headers={"User-Agent":"esp32c3-mac-rca/1"})
blob=urllib.request.urlopen(req,timeout=120).read()
if hashlib.sha256(blob).hexdigest()!=SHA:raise RuntimeError("ROM_ARCHIVE_SHA_MISMATCH")
data={}
with tarfile.open(fileobj=io.BytesIO(blob),mode="r:gz") as t, tempfile.TemporaryDirectory() as tmp:
 for rev in REVS:
  matches=[m for m in t.getmembers() if pathlib.PurePosixPath(m.name).name==rev]
  if len(matches)!=1:raise RuntimeError("ELF_MISSING_OR_DUPLICATE")
  content=t.extractfile(matches[0]).read();path=pathlib.Path(tmp)/rev;path.write_bytes(content)
  funcs=analyze(ELFFile(io.BytesIO(content)))
  verify_objdump(path,funcs)
  data[rev]=funcs
report={"schema":"MAC_RCA_COMPLETE_EVIDENCE_V1","archive_sha256":SHA,"gnu_objdump_full_body_comparison":"PASS","functions":{},"limitations":["Direct calls supported by bytes, indirect targets remain unresolved","Branch paths show static structure, not dynamic electrical measurements"]}
for name in FUNCTIONS:
 allrev={rev:data[rev][name] for rev in REVS}
 base=allrev[REVS[0]]["instructions"];candidate=allrev[REVS[1]]["instructions"]
 diff=difflib.SequenceMatcher(a=[(x["mnemonic"],x["operands"]) for x in base],b=[(x["mnemonic"],x["operands"]) for x in candidate],autojunk=False)
 changes=[]
 for kind,i,j,k,l in diff.get_opcodes():
  if kind!="equal":changes.append({"type":kind,"rev0":base[i:j],"rev101":candidate[k:l]})
 report["functions"][name]={"size_by_revision":{r:v["size"] for r,v in allrev.items()},
 "sha_by_revision":{r:v["sha256"] for r,v in allrev.items()},
 "rev0_rev3_equal":allrev[REVS[0]]["sha256"]==allrev[REVS[2]]["sha256"],
 "rev101_direct_and_indirect_transfers":allrev[REVS[1]]["calls_and_jumps"],
 "rev0_direct_and_indirect_transfers":allrev[REVS[0]]["calls_and_jumps"],
 "changed_instruction_blocks":changes}
(OUT/"complete_mac_rca.json").write_text(json.dumps(report,indent=2)+"\n")
print("MAC_RCA_SUMMARY "+json.dumps({n:{"changed_blocks":len(v["changed_instruction_blocks"]),"rev0_rev3_equal":v["rev0_rev3_equal"],
 "rev101_transfers":v["rev101_direct_and_indirect_transfers"]} for n,v in report["functions"].items()},sort_keys=True))
