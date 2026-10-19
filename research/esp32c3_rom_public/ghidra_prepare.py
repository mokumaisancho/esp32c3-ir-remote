#!/usr/bin/env python3
"""Prepare pinned ROM and all candidate addresses for headless Ghidra."""
import hashlib,io,json,pathlib,tarfile,urllib.request
ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"ghidra";OUT.mkdir(parents=True,exist_ok=True)
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
req=urllib.request.Request(URL,headers={"User-Agent":"esp32c3-ghidra-import/1"})
archive=urllib.request.urlopen(req,timeout=120).read()
if hashlib.sha256(archive).hexdigest()!=SHA:raise SystemExit("UNPINNED_ARCHIVE")
counts={}
with tarfile.open(fileobj=io.BytesIO(archive),mode="r:gz") as t:
 for rev in REVS:
  ms=[x for x in t.getmembers() if x.isfile() and pathlib.PurePosixPath(x.name).name==rev]
  if len(ms)!=1:raise SystemExit("ROM_REVISION_NOT_UNIQUE")
  content=t.extractfile(ms[0]).read();(OUT/rev).write_bytes(content)
  src=json.loads((ROOT/"output"/"candidate_full"/(rev+".candidate_full.json")).read_text())
  pairs=[(name,x["start"]) for name,x in src.items() if x.get("status","").startswith("FULL_BODY_VERIFIED")]
  if not pairs:raise SystemExit("NO_VALIDATED_FUNCTIONS:"+rev)
  with (OUT/(rev+".candidates.tsv")).open("w") as f:
   f.writelines(name+"\t"+addr+"\n" for name,addr in sorted(pairs))
  counts[rev]=len(pairs)
report={"schema":"ROM_GHIDRA_INPUT_V1","archive_sha256":SHA,"candidate_body_count":counts}
(OUT/"input_manifest.json").write_text(json.dumps(report,indent=2)+"\n")
print("ROM_GHIDRA_INPUT_READY",json.dumps(report,sort_keys=True))
