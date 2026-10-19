#!/usr/bin/env python3
"""Pin and integrate official ESP-IDF ROM linker, header and SoC register data.

Produce source-referenced inventory of known names before any novelty analysis.
Independent source classes: vintage IDF linker snapshots, current IDF headers,
and the SHA-locked official ROM ELF release. Never equate internal ELF with API.
"""
import ast, collections, concurrent.futures, csv, hashlib, io, json, pathlib, re, tarfile, urllib.request
from elftools.elf.elffile import ELFFile

ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"idf_known";OUT.mkdir(parents=True,exist_ok=True)
IDF_REFS={
 "v4.4.8":"e499576efdb086551abe309a72899302f82077b7",
 "v5.5.1":"fcae32885b0296b32044cb99ecbdc50d98dddb83",
 "master-2026-10-16":"1c42e514c90ae621af33bde3b6ad3dac22edcbfd",
}
LATEST="master-2026-10-16"
ROM_URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
ROM_SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
LD="components/esp_rom/esp32c3/ld"
LATEST_HEADER_DIRS=(
 "components/esp_rom/include",
 "components/esp_rom/esp32c3/include/esp32c3/rom",
 "components/soc/esp32c3/register/soc",
 "components/soc/esp32c3/include/soc",
)
AGENT={"User-Agent":"esp32c3-rom-evidence-integrator/1","Accept":"application/vnd.github+json"}
def download(url,timeout=90,max_bytes=8*1024*1024):
 with urllib.request.urlopen(urllib.request.Request(url,headers=AGENT),timeout=timeout) as r:
  b=r.read(max_bytes+1)
 if len(b)>max_bytes:raise RuntimeError("SOURCE_FILE_TOO_LARGE:"+url)
 return b
def listing(snapshot,directory):
 sha=IDF_REFS[snapshot]
 url="https://api.github.com/repos/espressif/esp-idf/contents/"+directory+"?ref="+sha
 rows=json.loads(download(url))
 if not isinstance(rows,list):raise RuntimeError("SOURCE_DIRECTORY_NOT_LIST:"+directory)
 selected=[x["path"] for x in rows if x.get("type")=="file" and x["name"].endswith((".ld",".h"))]
 if not selected:raise RuntimeError("SOURCE_DIRECTORY_EMPTY:"+directory)
 return sorted(selected)
def source(item):
 snapshot,path=item
 url="https://raw.githubusercontent.com/espressif/esp-idf/"+IDF_REFS[snapshot]+"/"+path
 data=download(url)
 return item,data,{"snapshot":snapshot,"commit":IDF_REFS[snapshot],"path":path,"sha256":hashlib.sha256(data).hexdigest(),
                    "bytes":len(data),"source_url":url}
def no_comments(s):
 return re.sub(r"//[^\n]*","",re.sub(r"/\*.*?\*/","",s,flags=re.S))
def linker_symbols(text,snapshot,path):
 clean=no_comments(text)
 # Version- and group-aware provenance is the file; address is NOT assumed to apply to all revisions.
 reg=re.compile(r"(?m)^\s*(?:PROVIDE(?:_HIDDEN)?\s*\(\s*)?([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*|0[xX][\da-fA-F]+|\d+)\s*\)?\s*;\s*$")
 rows=[]
 for m in reg.finditer(clean):
  name,value=m.group(1),m.group(2)
  numeric=bool(re.fullmatch(r"0[xX][\da-fA-F]+|\d+",value))
  rows.append({"snapshot":snapshot,"path":path,"symbol":name,
      "address":hex(int(value,0)) if numeric else "",
      "alias_of":"" if numeric else value,"ld_scope":"REVISION_OR_ECO_SPECIFIC" if re.search(r"eco\d+|\\.version",path) else "FILE_SCOPE_UNRESOLVED"})
 return rows
def macros_and_declarations(text,snapshot,path):
 clean=no_comments(text).replace("\\\n","")
 macros=[];decl=[]
 for line in clean.splitlines():
  m=re.match(r"\s*#\s*define\s+([A-Za-z_]\w*)\s+(.+)$",line)
  if m and "(" not in m.group(1):macros.append({"snapshot":snapshot,"path":path,"name":m.group(1),"expression":m.group(2).strip()})
 # A declaration is evidence of documentation only, not proof of a callable ROM API.
 pattern=r"(?m)^\s*(?:extern\s+)?(?:const\s+|volatile\s+|unsigned\s+|struct\s+|enum\s+)*[A-Za-z_]\w*(?:\s+|\s*\*\s*)+([A-Za-z_]\w*)\s*\([^;{}#]{0,450}\)\s*;"
 for m in re.finditer(pattern,clean):
  decl.append({"snapshot":snapshot,"path":path,"symbol":m.group(1)})
 return macros,decl
def address_expr(expr,lookup):
 # Safe arithmetic subset, no eval(), no C casts, no macro calls.
 try:tree=ast.parse(expr,mode="eval")
 except (SyntaxError,ValueError):return None
 def run(n):
  if isinstance(n,ast.Expression):return run(n.body)
  if isinstance(n,ast.Constant) and type(n.value) is int:return n.value
  if isinstance(n,ast.Name):return lookup[n.id]
  if isinstance(n,ast.BinOp) and isinstance(n.op,(ast.Add,ast.Sub,ast.BitOr,ast.LShift,ast.RShift)):
   l,r=run(n.left),run(n.right)
   if isinstance(n.op,ast.Add):return l+r
   if isinstance(n.op,ast.Sub):return l-r
   if isinstance(n.op,ast.BitOr):return l|r
   if isinstance(n.op,ast.LShift):return l<<r
   return l>>r
  raise ValueError("NON_CONSTANT")
 try:
  val=run(tree)
  return val if isinstance(val,int) and 0<=val<2**32 else None
 except (KeyError,ValueError,OverflowError,RecursionError):return None
def dump_csv(path,fields,rows):
 with path.open("w",newline="") as f:
  w=csv.DictWriter(f,fields);w.writeheader();w.writerows(rows)
def main():
 items=[]
 for snap in IDF_REFS:
  items +=[(snap,p) for p in listing(snap,LD)]
 for d in LATEST_HEADER_DIRS:
  items +=[(LATEST,p) for p in listing(LATEST,d)]
 if len(items)!=len(set(items)):raise RuntimeError("DUPLICATE_SOURCE_FILES")
 sources={};manifest=[]
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
  for item,data,record in pool.map(source,items):
   sources[item]=data.decode("utf-8")
   manifest.append(record)
 manifest.sort(key=lambda r:(r["snapshot"],r["path"]))
 ldrows=[];macros=[];decl=[]
 for snap,path in sorted(sources):
  text=sources[(snap,path)]
  if path.endswith(".ld"):ldrows.extend(linker_symbols(text,snap,path))
  else:
   m,d=macros_and_declarations(text,snap,path)
   macros.extend(m);decl.extend(d)
 if len(ldrows)<864:raise RuntimeError("INCOMPLETE_IDF_LINKER_EXTRACTION:"+str(len(ldrows)))
 baseline=list(csv.DictReader((ROOT/"rom_api_baseline.csv").open()))
 if len(baseline)!=864:raise RuntimeError("PINNED_BASELINE_INCOMPLETE")
 ld_byname=collections.defaultdict(list)
 for r in ldrows:ld_byname[r["symbol"]].append(r)
 declarations={r["symbol"] for r in decl}
 # Macro expression evaluation is bounded and only makes conservative, exact numerical matches.
 macro_map=collections.defaultdict(list)
 for m in macros:macro_map[m["name"]].append(m)
 resolved={};ambiguous=set()
 for _ in range(12):
  changes=0
  for name,definitions in macro_map.items():
   if name in ambiguous:continue
   numbers={address_expr(d["expression"],resolved) for d in definitions}
   numbers.discard(None)
   if len(numbers)>1:
    ambiguous.add(name);resolved.pop(name,None)
    continue
   if len(numbers)==1 and name not in resolved:
    resolved[name]=next(iter(numbers));changes+=1
  if not changes:break
 register_rows=[]
 for m in macros:
  name=m["name"]
  if name not in resolved or name in ambiguous:continue
  if name.startswith("DR_REG_") or name.endswith(("_REG","_BASE")):
   register_rows.append({**m,"address":hex(resolved[name])})
 reg_by_addr=collections.defaultdict(list)
 for m in register_rows:reg_by_addr[m["address"]].append(m["name"])
 archive=download(ROM_URL,timeout=120,max_bytes=128*1024*1024)
 if hashlib.sha256(archive).hexdigest()!=ROM_SHA:raise RuntimeError("ROM_ARCHIVE_SHA_MISMATCH")
 elfrows=[]
 with tarfile.open(fileobj=io.BytesIO(archive),mode="r:gz") as t:
  for rev in REVS:
   found=[m for m in t.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   if len(found)!=1:raise RuntimeError("ROM_ELF_NOT_UNIQUE:"+rev)
   elf=ELFFile(io.BytesIO(t.extractfile(found[0]).read()))
   if elf["e_machine"]!="EM_RISCV":raise RuntimeError("ROM_ELF_ARCH_MISMATCH")
   for section in elf.iter_sections():
    if section["sh_type"]!="SHT_SYMTAB":continue
    for s in section.iter_symbols():
     typ=s["st_info"]["type"]
     if not s.name or typ not in ("STT_FUNC","STT_OBJECT","STT_NOTYPE") or not int(s["st_value"]):continue
     elfrows.append({"revision":rev,"name":s.name,"address":hex(int(s["st_value"])),
        "size":int(s["st_size"]),"kind":typ,
        "declared_in_idf_ld":int(s.name in ld_byname),
        "declared_in_idf_header":int(s.name in declarations)})
 cand=json.loads((ROOT/"output"/"internal_function_candidates.json").read_text())
 crows=[]
 for c in cand["all_candidates"]:
  name=c["elf_function_name"];definitions=ld_byname.get(name,[])
  crows.append({"name":name,"idf_ld_definitions":len(definitions),
    "idf_ld_snapshots":";".join(sorted({x["snapshot"] for x in definitions})),
    "idf_header_declaration":int(name in declarations),
    "classification":"KNOWN_IDF_LINKER_NAME" if definitions else
      ("KNOWN_HEADER_DECLARATION" if name in declarations else "UNRESOLVED_IN_SELECTED_IDF_SOURCES"),
    "novelty_certified":False})
 mmiorows=[]
 for rev in REVS:
  raw=json.loads((ROOT/"output"/"register_access"/(rev+".mmio.json")).read_text())
  for hit in raw:
   address=hit["address"].lower()
   matches=sorted(set(reg_by_addr.get(address,[])))
   mmiorows.append({"revision":rev,"address":address,"access_pc":hit["access_pc"],
     "matching_header_macros":";".join(matches),"header_exact_match":int(bool(matches)),
     "match_type":"EXACT_NUMERIC_MACRO_ONLY" if matches else "UNRESOLVED_BY_SELECTED_MACROS"})
 baseline_verification=[]
 for row in baseline:
  ds=[x for x in ld_byname.get(row["symbol"],[]) if x["path"].endswith("/esp32c3.rom.ld") and x["address"]]
  values={d["address"] for d in ds}
  baseline_verification.append({"symbol":row["symbol"],"address":row["address"].lower(),
     "found_in_primary_ld":bool(ds),"any_matching_primary_address":row["address"].lower() in values})
 candidate_examples=[
   {"name":x["name"],"classification":x["classification"],
    "source_files":sorted({d["snapshot"]+":"+d["path"] for d in ld_byname[x["name"]]})[:7]}
   for x in crows]
 report={"schema":"ROM_ESP_IDF_KNOWN_INVENTORY_V1","original_issue_id":"ESP32C3-ROM-001",
  "idf_commits":IDF_REFS,"rom_sha256":ROM_SHA,
  "source_files":len(manifest),"idf_linker_assignments":len(ldrows),
  "idf_linker_distinct_names":len(ld_byname),"idf_header_macro_definitions":len(macros),
  "idf_numeric_address_macros":len(register_rows),"idf_header_function_declarations":len(decl),
  "elf_symtab_named_rows":len(elfrows),
  "candidate_count":len(crows),"candidate_idf_linker_name_matches":sum(x["idf_ld_definitions"]>0 for x in crows),
  "candidate_idf_header_name_matches":sum(x["idf_header_declaration"]>0 for x in crows),
  "candidate_not_named_in_selected_idf_sources":sum(x["classification"]=="UNRESOLVED_IN_SELECTED_IDF_SOURCES" for x in crows),
  "mmio_access_rows":len(mmiorows),"mmio_exact_header_name_rows":sum(x["header_exact_match"] for x in mmiorows),
  "ambiguous_header_macro_names":len(ambiguous),
  "baseline_present_in_primary_ld":sum(x["found_in_primary_ld"] for x in baseline_verification),
  "baseline_matching_primary_ld_address":sum(x["any_matching_primary_address"] for x in baseline_verification),
  "idf_linker_file_counts":{name:sum(x["snapshot"]==name and x["path"].endswith(".ld") for x in manifest) for name in IDF_REFS},
  "candidate_known_names":[x["name"] for x in crows if x["classification"]!="UNRESOLVED_IN_SELECTED_IDF_SOURCES"],
  "candidate_unresolved_names":[x["name"] for x in crows if x["classification"]=="UNRESOLVED_IN_SELECTED_IDF_SOURCES"],
  "candidate_source_provenance":candidate_examples,
  "limitations":["Linker names are NOT all callable external APIs",
    "ELF functions are named by vendor ELF but do not prove public availability",
    "ECO-specific definitions are NOT assumed compatible with all three revision ELFs",
    "Header macro arithmetic is conservative, unmatched macros are not unimplemented hardware",
    "This inventory is bounded to listed three IDF versions and selected header directories",
    "An unmatched name is NOT evidence of functional novelty"]}
 dump_csv(OUT/"baseline_crosscheck.csv",["symbol","address","found_in_primary_ld","any_matching_primary_address"],baseline_verification)
 dump_csv(OUT/"sources.csv",list(manifest[0]),manifest)
 dump_csv(OUT/"linker_symbols.csv",["snapshot","path","symbol","address","alias_of","ld_scope"],ldrows)
 dump_csv(OUT/"elf_symbols.csv",["revision","name","address","size","kind","declared_in_idf_ld","declared_in_idf_header"],elfrows)
 dump_csv(OUT/"header_definitions.csv",["snapshot","path","name","expression"],macros)
 dump_csv(OUT/"header_register_addresses.csv",["snapshot","path","name","expression","address"],register_rows)
 dump_csv(OUT/"header_function_declarations.csv",["snapshot","path","symbol"],decl)
 dump_csv(OUT/"candidates_reclassified.csv",list(crows[0]),crows)
 dump_csv(OUT/"mmio_header_matches.csv",list(mmiorows[0]),mmiorows)
 (OUT/"summary.json").write_text(json.dumps(report,indent=2)+"\n")
 print("IDF_KNOWN_INVENTORY_RESULT "+json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
