#!/usr/bin/env python3
"""Prepare and verify Ghidra experiment inputs from existing full 88-body audit."""
import csv,hashlib,io,json,pathlib,tarfile,urllib.request
R=pathlib.Path(__file__).resolve().parent
O=R/"output"/"ghidra";O.mkdir(parents=True,exist_ok=True)
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
def main():
 src=R/"output"/"candidate_full"/"candidate_summary.json"
 summary=json.loads(src.read_text())
 records=summary["all_candidates"]
 if len(records)!=88 or len({x["elf_name"] for x in records})!=88:
  raise RuntimeError("CANDIDATE_IDENTITY_LOST")
 names=sorted(x["elf_name"] for x in records)
 blob=urllib.request.urlopen(urllib.request.Request(URL,headers={"User-Agent":"rom-ghidra-evidence/1"}),timeout=120).read()
 if hashlib.sha256(blob).hexdigest()!=SHA:raise RuntimeError("ROM_SOURCE_ARCHIVE_HASH_MISMATCH")
 report={"schema":"ROM_GHIDRA_INPUT_V1","source_sha256":SHA,"revisions":{}}
 with tarfile.open(fileobj=io.BytesIO(blob),mode="r:gz") as tar:
  for rev in REVS:
   hits=[x for x in tar.getmembers() if x.isfile() and pathlib.PurePosixPath(x.name).name==rev]
   if len(hits)!=1:raise RuntimeError("ROM_REVISION_NOT_UNIQUE:"+rev)
   rom=tar.extractfile(hits[0]).read();p=O/rev;p.write_bytes(rom)
   evidence=json.loads((R/"output"/"candidate_full"/(rev+".candidate_full.json")).read_text())
   if set(evidence)!=set(names):raise RuntimeError("REVISION_EVIDENCE_DIFFERENT_FROM_CANDIDATES")
   with (O/(rev+".names.tsv")).open("w",newline="") as f:
    writer=csv.writer(f,delimiter="\t",lineterminator="\n")
    for name in names:
     row=evidence[name]
     if row["status"]=="ABSENT_SYMBOL":address="ABSENT"
     elif row["status"].startswith("FULL_BODY_VERIFIED"):address=row["start"]
     else:raise RuntimeError("UNCERTIFIED_ELF_FUNCTION:"+name+":"+rev)
     writer.writerow([name,address])
   report["revisions"][rev]={"elf_sha256":hashlib.sha256(rom).hexdigest(),
       "present":sum(evidence[name]["status"]!="ABSENT_SYMBOL" for name in names)}
 (O/"input_manifest.json").write_text(json.dumps(report,indent=2)+"\n")
 print("GHIDRA_INPUT_PREPARATION",json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
