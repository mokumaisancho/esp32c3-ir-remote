#!/usr/bin/env python3
"""Independent GNU objdump vs RISC-V byte-decoder check for ESP32-C3 ROM.

The source of observed targets is binutils' RISC-V disassembler. It does not
reuse Capstone or the custom opcode decoder for expected target computation.
"""
import csv
import hashlib
import io
import json
import pathlib
import re
import subprocess
import tarfile
import tempfile
import urllib.request

HERE=pathlib.Path(__file__).resolve().parent
OUT=HERE/"output"/"independent_objdump"
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
EXPECTED="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
BINARY="riscv64-linux-gnu-objdump"
LINE=re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2,8}\s+)(.+)$")

def parse_target_line(text):
    m=LINE.match(text)
    if not m:
        return None
    pc=int(m.group(1),16)
    rest=m.group(2).strip()
    if not rest.startswith(("j\t","j ","jal\t","jal ")):
        return (pc,None,"NOT_JUMP")
    # Prefer the actual assembler-generated target address to symbol names.
    target=re.search(r"\b(?:0x)?([0-9a-fA-F]{8})\s*<",rest)
    if not target:
        target=re.search(r"(?:^|[,\s])(?:0x)?([0-9a-fA-F]{8})(?:\s|$)",rest)
    if not target:
        return (pc,None,"UNPARSEABLE_BRANCH")
    return (pc,int(target.group(1),16),"JUMP")

def parse_objdump(out):
    result={}
    for line in out.splitlines():
        p=parse_target_line(line)
        if p:
            addr,target,status=p
            if addr in result and result[addr]!=(target,status):
                raise RuntimeError("G3_DUPLICATE_OBJDUMP_PC:"+hex(addr))
            result[addr]=(target,status)
    return result

def main():
    with (HERE/"rom_api_baseline.csv").open(newline="") as f:
        records=[x for x in csv.DictReader(f) if x["type"]=="function"]
    if len(records)!=648 or len({int(r["address"],16) for r in records})!=648:
        raise RuntimeError("G1_BASELINE_INCOMPLETE")
    request=urllib.request.Request(URL,headers={"User-Agent":"ESP32C3-ROM-internal-verify/1"})
    archive=urllib.request.urlopen(request,timeout=120).read()
    if hashlib.sha256(archive).hexdigest()!=EXPECTED:
        raise RuntimeError("G1_ARCHIVE_SHA_MISMATCH")
    OUT.mkdir(parents=True,exist_ok=True)
    report={"schema":"ESP32C3_GNU_BINUTILS_INDEPENDENT_TARGET_AUDIT_V1",
            "validator":"GNU binutils RISC-V objdump; independent of custom opcode and Capstone",
            "archive_sha256":EXPECTED,"revisions":{}}
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(fileobj=io.BytesIO(archive),mode="r:gz") as tar:
        for rev in REVS:
            items=[m for m in tar.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
            if len(items)!=1:raise RuntimeError("G1_ELF_REVISION_COUNT:"+rev)
            raw=tar.extractfile(items[0]).read()
            path=pathlib.Path(tmp)/rev;path.write_bytes(raw)
            proc=subprocess.run([BINARY,"-d","-j",".fixed.text",str(path)],
                check=True,capture_output=True,text=True,timeout=90)
            decoded=parse_objdump(proc.stdout)
            reference=json.loads((HERE/"output"/"entry_audit"/(rev+".entries.json")).read_text())
            by_pc={int(row["known_address"],16):row for row in reference}
            if len(by_pc)!=648:raise RuntimeError("G3_INCOMPLETE_CUSTOM_ENTRY_AUDIT")
            matches=[];differences=[]
            for r in records:
                addr=int(r["address"],16)
                target,status=decoded.get(addr,(None,"NO_OBJDUMP_INSTRUCTION"))
                expected=by_pc[addr].get("branch_target")
                expected=int(expected,16) if expected else None
                proof={"symbol":r["symbol"],"entry":hex(addr),"objdump_target":hex(target) if target is not None else None,
                      "custom_target":hex(expected) if expected is not None else None,"status":status,
                      "equal":target is not None and target==expected}
                (matches if proof["equal"] and status=="JUMP" else differences).append(proof)
            report["revisions"][rev]={"total":648,"independent_matches":len(matches),
                "independent_mismatches":len(differences),
                "first_disagreements":differences[:20],"elf_sha256":hashlib.sha256(raw).hexdigest()}
            if differences:
                raise RuntimeError("G3_GNU_OBJDUMP_DISAGREEMENT:"+rev+":"+str(differences[:3]))
    (OUT/"summary.json").write_text(json.dumps(report,indent=2)+"\n")
    print("INDEPENDENT_OBJDUMP_RESULT "+json.dumps(report,separators=(",",":")))
    return report

if __name__=="__main__": main()
