#!/usr/bin/env python3
"""ESP32-C3 ROM: conservative register access evidence, no semantic invention.

This script records CSR opcodes and adjacent LUI[/ADDI]+LOAD/STORE patterns.
Neither proves dynamic execution, undocumented status, nor functional effects.
"""
import collections
import hashlib
import io
import json
import pathlib
import tarfile
import urllib.request

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
from elftools.elf.elffile import ELFFile
from rom_mmio import scan_adjacent
from rom_opcode import csr_number

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "output" / "register_access"
URL = "https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA = "caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVISIONS = ("esp32c3_rev0_rom.elf", "esp32c3_rev101_rom.elf", "esp32c3_rev3_rom.elf")

def decode(blob):
    elf = ELFFile(io.BytesIO(blob))
    if elf["e_machine"] != "EM_RISCV":
        raise RuntimeError("WRONG_ELF_ARCHITECTURE")
    decoder = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
    decoder.skipdata = True
    mmios, csrs = [], []
    info = {"executable_sections": 0, "decoded_instructions": 0, "undecoded_bytes": 0}
    symbols = []
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_SYMTAB":
            for sym in section.iter_symbols():
                if sym["st_info"]["type"] == "STT_FUNC" and int(sym["st_value"]) and int(sym["st_size"]):
                    symbols.append((int(sym["st_value"]), int(sym["st_value"]) + int(sym["st_size"]), sym.name))
    symbols.sort()
    def owner(pc):
        # Symbol ranges are metadata hints; overlap is represented as ambiguous.
        names = [name for start, stop, name in symbols if start <= pc < stop]
        return names if len(names) <= 3 else names[:3] + ["OTHER_OVERLAP_OMITTED"]
    for section in elf.iter_sections():
        if section["sh_type"] != "SHT_PROGBITS" or not (int(section["sh_flags"]) & 4):
            continue
        info["executable_sections"] += 1
        instructions = list(decoder.disasm(section.data(), int(section["sh_addr"])))
        info["decoded_instructions"] += sum(ins.mnemonic != ".byte" for ins in instructions)
        info["undecoded_bytes"] += sum(ins.size for ins in instructions if ins.mnemonic == ".byte")
        actual = [(ins.address,bytes(ins.bytes)) for ins in instructions if ins.mnemonic != ".byte"]
        found = scan_adjacent(actual)
        for cand in found:
            cand["revision_elf_sha256"] = hashlib.sha256(blob).hexdigest()
            cand["section"] = section.name
            cand["function_hints"] = owner(int(cand["access_pc"],16))
        mmios.extend(found)
        for ins in instructions:
            if ins.mnemonic == ".byte":continue
            csr = csr_number(ins.bytes)
            if csr is not None:
                csrs.append({"address":hex(ins.address), "csr":hex(csr),
                    "mnemonic":ins.mnemonic, "operands":ins.op_str, "raw_bytes":bytes(ins.bytes).hex(),
                    "section":section.name,"function_hints":owner(ins.address)})
    if info["decoded_instructions"] < 1000:
        raise RuntimeError("INCOMPLETE_EXECUTABLE_CODE_OR_WRONG_ARCH")
    return info,mmios,csrs

def main():
    req = urllib.request.Request(URL,headers={"User-Agent":"ESP32C3-ROM-AUDIT/1"})
    archive = urllib.request.urlopen(req,timeout=120).read()
    if hashlib.sha256(archive).hexdigest() != SHA:
        raise RuntimeError("G1_ARCHIVE_DIGEST_MISMATCH")
    OUT.mkdir(parents=True,exist_ok=True)
    summary = {"schema":"ROM_REGISTER_ACCESS_V1", "source_archive_sha256":SHA,
        "classification":"CANDIDATE_ONLY_STATIC_OPCODE_EVIDENCE",
        "warnings":["MMIO scanner only handles adjacent LUI[/ADDI]+load/store patterns",
                    "Linearly decoded instructions may include embedded data/unreachable code",
                    "Function owner comes from ELF metadata and may overlap",
                    "These are not claims of undocumented or dynamically executed functionality"],
        "revisions":{}}
    with tarfile.open(fileobj=io.BytesIO(archive),mode="r:gz") as tar:
        for filename in REVISIONS:
            hits=[m for m in tar.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==filename]
            if len(hits)!=1: raise RuntimeError("MISSING_OR_DUPLICATE_REVISION:"+filename)
            blob=tar.extractfile(hits[0]).read()
            info,mmios,csrs=decode(blob)
            counts=collections.Counter(x["address"] for x in mmios)
            csr_counts=collections.Counter(x["csr"] for x in csrs)
            (OUT/(filename+".mmio.json")).write_text(json.dumps(mmios,indent=2)+"\n")
            (OUT/(filename+".csr.json")).write_text(json.dumps(csrs,indent=2)+"\n")
            summary["revisions"][filename]={
                "elf_sha256":hashlib.sha256(blob).hexdigest(),
                **info,
                "mmio_static_instruction_patterns":len(mmios),
                "unique_mmio_addresses":len(counts),
                "most_common_mmio_addresses":counts.most_common(50),
                "mmio_access_type_counts":dict(collections.Counter(x["kind"] for x in mmios)),
                "csr_static_access_count":len(csrs),
                "unique_csrs":len(csr_counts),
                "csr_counts":dict(sorted(csr_counts.items())),
                "first_mmio_evidence":mmios[:10],
            }
    (OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    print("REGISTER_ACCESS_RESULT "+json.dumps(summary,separators=(",",":")))
if __name__=="__main__":
    main()
