#!/usr/bin/env python3
"""Independent quality gate: ELF function symbols vs linker address inventory.

This test deliberately separates 'not represented as STT_FUNC' from 'outside
executable ROM'. Neither is proof of an undocumented function.
"""
import csv, hashlib, io, json, pathlib, tarfile, urllib.request
from elftools.elf.elffile import ELFFile

ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"quality"; OUT.mkdir(parents=True,exist_ok=True)
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
def baseline():
    with (ROOT/"rom_api_baseline.csv").open() as f: rows=list(csv.DictReader(f))
    assert len(rows)==864 and sum(r["type"]=="function" for r in rows)==648
    return [(r["symbol"],int(r["address"],16)) for r in rows if r["type"]=="function"]
def in_sections(addr,sections):
    return any(start<=addr<stop for start,stop in sections)
def negative_tests():
    assert in_sections(0x40000018,[(0x40000000,0x40002000)])
    assert not in_sections(0x40002000,[(0x40000000,0x40002000)])
    assert not in_sections(0x50000000,[(0x40000000,0x40002000)])
    assert in_sections(0x40000018,[]) is False
    # A symbol absent from STT_FUNC may still reside in executable machine code.
    assert (0x40000018 not in {0x40007814}) and in_sections(0x40000018,[(0x40000000,0x40001c80)])
negative_tests()
request=urllib.request.Request(URL,headers={"User-Agent":"ESP-ROM-QA/1"})
data=urllib.request.urlopen(request,timeout=120).read()
assert hashlib.sha256(data).hexdigest()==SHA
known=baseline()
report={"schema":"ESP32C3_ROM_INDEPENDENT_SECTION_QA_V1","archive_sha256":SHA,"negative_tests":"PASS","revisions":{}}
with tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as tar:
    for name in ["esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf"]:
        found=[m for m in tar.getmembers() if pathlib.PurePosixPath(m.name).name==name]
        if len(found)!=1:raise RuntimeError("missing/duplicate "+name)
        e=ELFFile(io.BytesIO(tar.extractfile(found[0]).read()))
        if e["e_machine"]!="EM_RISCV":raise RuntimeError("wrong arch")
        sections=[(int(s["sh_addr"]),int(s["sh_addr"])+int(s["sh_size"])) for s in e.iter_sections()
                  if s["sh_type"]=="SHT_PROGBITS" and int(s["sh_flags"])&4]
        entry=set()
        for s in e.iter_sections():
            if s["sh_type"]=="SHT_SYMTAB":
                entry.update(int(z["st_value"]) for z in s.iter_symbols() if z["st_info"]["type"]=="STT_FUNC" and int(z["st_value"]))
        within=[(n,a) for n,a in known if in_sections(a,sections)]
        outside=[(n,a) for n,a in known if not in_sections(a,sections)]
        symbol_match=[(n,a) for n,a in known if a in entry]
        # Preserve a sample of each category so a human can independently inspect.
        report["revisions"][name]={"known_function_symbols":len(known),"inside_executable_section":len(within),
            "outside_executable_section":len(outside),"matching_STT_FUNC_address":len(symbol_match),
            "inside_but_not_STT_FUNC":len([1 for _,a in within if a not in entry]),
            "outside_examples":[{"name":n,"addr":hex(a)} for n,a in outside[:20]],
            "inside_examples":[{"name":n,"addr":hex(a)} for n,a in within[:15]],
            "executable_section_intervals":[[hex(a),hex(b)] for a,b in sections]}
        if not within:raise RuntimeError("FAIL_CLOSED_NO_KNOWN_ROM_ADDRESSES_IN_EXECUTABLE_SECTIONS")
(OUT/"section_quality.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps(report,indent=2))
