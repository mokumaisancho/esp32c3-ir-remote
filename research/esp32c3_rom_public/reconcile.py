#!/usr/bin/env python3
import csv,hashlib,io,json,pathlib,re,tarfile,urllib.request
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
P=pathlib.Path(__file__).resolve().parent;O=P/"output"/"reconciliation";O.mkdir(parents=True,exist_ok=True)
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
LD_SOURCE="espressif/esp-idf/esp32c3.rom.ld blob f615f3ac3a5125837c74636463bec92b6db2465b"
def get(url):return urllib.request.urlopen(url,timeout=120).read()
archive=get(URL)
assert hashlib.sha256(archive).hexdigest()==SHA,"archive hash mismatch"
# Read the checked-in, provenance-tracked official linker CSV instead of unpinned master.
# A current upstream source with the same row count may silently change addresses.
with (P/"rom_api_baseline.csv").open(newline="") as f:
 rows=[dict(name=x["symbol"],address=int(x["address"],16),
            kind=x["type"],group=x["group"]) for x in csv.DictReader(f)]
if len(rows)!=864 or sum(r["kind"]=="function" for r in rows)!=648 or len({x["name"] for x in rows})!=864:
 raise RuntimeError("G1_PINNED_BASELINE_DRIFT")

known={r["address"]:r for r in rows if r["kind"]=="function"}
def save(name,rows,fields):
 with (O/name).open("w",newline="") as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
summary={"archive_sha256":SHA,"baseline_functions":len(known),"revisions":{}}
with tarfile.open(fileobj=io.BytesIO(archive),mode="r:gz") as tar:
 members=[m for m in tar if m.isfile() and re.search(r"esp32c3_rev(?:0|101|3)_rom\.elf$",m.name)]
 assert len(members)==3,[m.name for m in members]
 for member in members:
  elf=ELFFile(io.BytesIO(tar.extractfile(member).read())); assert elf["e_machine"]=="EM_RISCV"
  funcs=[]
  for sec in elf.iter_sections():
   if sec["sh_type"]=="SHT_SYMTAB":
    for sym in sec.iter_symbols():
     if sym["st_info"]["type"]=="STT_FUNC" and int(sym["st_value"]):
      funcs.append((sym.name,int(sym["st_value"]),int(sym["st_size"])))
  n=pathlib.Path(member.name).stem;entries={a for _,a,_ in funcs}
  print("RECONCILIATION_ADDRESS_DIAGNOSTIC",json.dumps({
    "revision":n,"baseline_first":[hex(k) for k in list(known)[:6]],
    "elf_first":[[z,hex(a),size] for z,a,size in funcs[:6]],
    "elf_address_min":hex(min(entries)),"elf_address_max":hex(max(entries)),
    "elf_section_addresses":[[z.name,hex(int(z["sh_addr"]))] for z in elf.iter_sections() if int(z["sh_flags"])&4],
    "raw_intersection":len(entries & set(known))},sort_keys=True))
  extra=[{"symbol":x,"address":hex(a),"size":z,"classification":"ELF_ONLY_UNVERIFIED"} for x,a,z in funcs if a not in known]
  missing=[{"symbol":r["name"],"address":hex(a),"group":r["group"]} for a,r in known.items() if a not in entries]
  matched=[{"rom_symbol":known[a]["name"],"elf_symbol":x,"address":hex(a)} for x,a,z in funcs if a in known]
  # Separate same-name correspondences from address equality (independent evidence).
  known_by_name={x["name"]:x for x in rows if x["kind"]=="function"}
  name_matched=[{"rom_symbol":x,"rom_address":hex(known_by_name[x]["address"]),"elf_address":hex(a),"same_address":a==known_by_name[x]["address"]} for x,a,z in funcs if x in known_by_name]
  save(n+"_name_matches.csv",name_matched,["rom_symbol","rom_address","elf_address","same_address"])
  save(n+"_elf_only.csv",extra,["symbol","address","size","classification"])
  save(n+"_baseline_missing.csv",missing,["symbol","address","group"])
  save(n+"_matched.csv",matched,["rom_symbol","elf_symbol","address"])
  summary["revisions"][n]={"elf_function_symbols":len(funcs),"unique_entry_addresses":len(entries),"matched_elf_symbols":len(matched),"elf_only_symbols":len(extra),"baseline_missing":len(missing),"elf_only_distinct_addresses":len({int(x["address"],16) for x in extra}),"name_matches":len(name_matched)}
(O/"reconciliation.json").write_text(json.dumps(summary,indent=2)+"\n")
print(json.dumps(summary,indent=2))
