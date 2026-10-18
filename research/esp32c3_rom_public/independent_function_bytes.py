#!/usr/bin/env python3
"""Verify internal ROM function bodies against independent GNU objdump output.

No expected bytes or function meaning is hardcoded: comparison is GNU binutils
vs Capstone trace obtained from identical, hash-pinned official ELF.
"""
import hashlib,io,json,pathlib,re,subprocess,tarfile,tempfile,urllib.request
ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"focused"
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
# GNU objdump prints 16/32 bit little-endian instructions as integer hex.
LINE=re.compile(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{4}|[0-9a-fA-F]{8})\s+(.*)$")
def parse_disasm(text):
    rows={}
    for l in text.splitlines():
        m=LINE.match(l)
        if not m:continue
        addr=int(m.group(1),16);word=m.group(2)
        if addr in rows:raise ValueError("DUPLICATE_GNU_INSTRUCTION_PC")
        rows[addr]=word.lower()
    return rows
def compare_trace(trace, words):
    if not trace:return "EMPTY_FUNCTION_TRACE"
    for ins in trace:
        pc=int(ins["pc"],16)
        expected=bytes.fromhex(ins["hex"])[::-1].hex()
        found=words.get(pc)
        if found != expected:
            return {"pc":hex(pc),"capstone_little_endian":ins["hex"],
                "independent_gnu_machine_word":found,"expected_integer_hex":expected}
    return None
def selftest():
    x=parse_disasm(" 40000004:  00000013    nop\n 40000008: 8082    ret\n")
    assert x=={0x40000004:"00000013",0x40000008:"8082"},x
    assert compare_trace([{"pc":"0x40000004","hex":"13000000"}],x) is None
    assert isinstance(compare_trace([{"pc":"0x40000004","hex":"93000000"}],x),dict)
    assert isinstance(compare_trace([{"pc":"0x40000004","hex":"13000000"}],{}),dict)
    return 4

def main():
    tests=selftest()
    data=urllib.request.urlopen(urllib.request.Request(URL,headers={"User-Agent":"ROM-independent-core-audit"}),timeout=120).read()
    if hashlib.sha256(data).hexdigest()!=SHA:raise RuntimeError("G1_BAD_ARCHIVE")
    summary={"schema":"ROM_INDEPENDENT_INTERNAL_FUNCTION_BYTES_V1",
      "methods":"GNU binutils objdump machine words versus Capstone-derived ELF function byte traces",
      "source_archive_sha256":SHA,"synthetic_negative_and_positive_checks":tests,
      "revisions":{},
      "limit":"Byte-decoder agreement does not validate functional meaning or runtime side effects"}
    with tempfile.TemporaryDirectory() as tmp,tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as tar:
        for rev in REVS:
            member=[m for m in tar.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
            if len(member)!=1:raise RuntimeError("G1_REV_MISSING")
            raw=tar.extractfile(member[0]).read()
            elf=pathlib.Path(tmp)/rev;elf.write_bytes(raw)
            traces=json.loads((OUT/(rev+".json")).read_text())
            results=[]
            for fn in traces:
                if fn.get("status")!="EXTRACTED":raise RuntimeError("G3_TARGET_NOT_EXTRACTED:"+fn["name"])
                start=int(fn["address"],16);end=start+fn["size_bytes"]
                cmd=["riscv64-linux-gnu-objdump","-d","--start-address="+hex(start),
                     "--stop-address="+hex(end),str(elf)]
                result=subprocess.run(cmd,capture_output=True,text=True,timeout=80,check=True)
                parsed=parse_disasm(result.stdout)
                mismatch=compare_trace(fn["instructions"],parsed)
                row={"name":fn["name"],"start":fn["address"],
                     "size":fn["size_bytes"],"capstone_instructions":len(fn["instructions"]),
                     "objdump_instruction_rows_in_range":len(parsed),
                     "byte_mismatch":mismatch,
                     "status":"PASS" if mismatch is None and len(parsed)==len(fn["instructions"]) else "FAIL"}
                results.append(row)
                if row["status"]!="PASS":raise RuntimeError("G3_GNU_INDEPENDENT_FUNCTION_DISAGREEMENT:"+str(row))
            summary["revisions"][rev]={"elf_sha256":hashlib.sha256(raw).hexdigest(),
                  "validated_functions":len(results),"validated_instruction_count":sum(x["capstone_instructions"] for x in results),
                  "entries":results}
    (OUT/"independent_internal_function_comparison.json").write_text(json.dumps(summary,indent=2)+"\n")
    print("INDEPENDENT_FUNCTION_RESULT "+json.dumps(summary,separators=(",",":")))
if __name__=="__main__":main()
