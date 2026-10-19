#!/usr/bin/env python3
"""This stage MUST be gated by 88/88 independent semantic review."""
import argparse,hashlib,io,json,pathlib,tarfile,urllib.request
from collections import defaultdict
from elftools.elf.elffile import ELFFile
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
def verify_gate(s):
 if s.get("schema")!="ROM_RESEARCH_AUTOPILOT_V1" or s.get("candidate_count")!=88 or s.get("semantic_review_closed")!=88 or s.get("semantic_review_pending")!=0 or s.get("release_discovery") is not True:
  raise RuntimeError("FAIL_CLOSED_ORIGINAL_88_SEMANTIC_GATE")
 rows=s.get("tasks",[])
 if len(rows)!=88 or len({x["name"] for x in rows})!=88 or any(x["status"]!="REVIEWED" for x in rows):
  raise RuntimeError("FAIL_CLOSED_PER_CANDIDATE_VERDICT")
 return {x["name"] for x in rows}
def run(state,out):
 names=verify_gate(state)
 blob=urllib.request.urlopen(urllib.request.Request(URL,headers={"User-Agent":"rom-discovery-after-88/1"}),timeout=120).read()
 if hashlib.sha256(blob).hexdigest()!=SHA:raise RuntimeError("SOURCE_ROM_ELF_DIGEST_MISMATCH")
 candidates=defaultdict(list)
 with tarfile.open(fileobj=io.BytesIO(blob),mode="r:gz") as z:
  for rev in REVS:
   entries=[x for x in z.getmembers() if x.isfile() and pathlib.PurePosixPath(x.name).name==rev]
   if len(entries)!=1:raise RuntimeError("ELF_MISSING_OR_DUPLICATE")
   elf=ELFFile(io.BytesIO(z.extractfile(entries[0]).read()))
   for section in elf.iter_sections():
    if section["sh_type"]!="SHT_SYMTAB":continue
    for symbol in section.iter_symbols():
     if symbol.name and symbol["st_info"]["type"]=="STT_FUNC" and int(symbol["st_size"])>0 and symbol.name not in names:
      candidates[symbol.name].append({"revision":rev,"address":hex(int(symbol["st_value"])),"size":int(symbol["st_size"])})
 report={"schema":"ROM_POST_88_FUNCTION_POPULATION_V1","original_88_semantically_reviewed":88,
  "additional_named_functions":len(candidates),"novel_api_proven":0,
  "limitations":["ELF function symbol names do not prove novel APIs","Unlabeled code and indirect targets require separate analysis"],
  "additional_functions":dict(sorted(candidates.items()))}
 out.mkdir(parents=True,exist_ok=True);(out/"new_functions.json").write_text(json.dumps(report,indent=2)+"\n")
 print("POST_88_DISCOVERY",json.dumps({k:v for k,v in report.items() if k!="additional_functions"},sort_keys=True))
def main():
 p=argparse.ArgumentParser();p.add_argument("--state",type=pathlib.Path,required=True);p.add_argument("--out",type=pathlib.Path,required=True)
 a=p.parse_args();run(json.loads(a.state.read_text()),a.out)
if __name__=="__main__":main()
