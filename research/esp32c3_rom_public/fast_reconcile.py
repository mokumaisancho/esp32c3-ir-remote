#!/usr/bin/env python3
"""Fast evidence-first ESP32-C3 ROM reconciliation, not undocumented-API certification."""
import csv, hashlib, io, json, pathlib, struct, tarfile, time, urllib.request
from collections import Counter
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "output" / "fast_reconcile"
URL = "https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
ARCHIVE_SHA = "caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"

def baseline():
    with (HERE / "rom_api_baseline.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    if len(rows) != 864 or sum(r["type"] == "function" for r in rows) != 648:
        raise RuntimeError("Incorrect linker symbol baseline")
    if len({r["symbol"] for r in rows}) != len(rows):
        raise RuntimeError("Duplicate linker symbols")
    return {int(r["address"], 16): r for r in rows if r["type"] == "function"}

def csr_number(raw):
    if len(raw) != 4: return None
    word = struct.unpack("<I", bytes(raw))[0]
    if word & 0x7f != 0x73 or ((word >> 12) & 7) == 0:
        return None
    return (word >> 20) & 0xfff

def jal_target(raw, pc):
    if len(raw) != 4: return None
    v = struct.unpack("<I", bytes(raw))[0]
    if v & 0x7f != 0x6f: return None
    imm = ((v >> 31) << 20) | (((v >> 12) & 0xff) << 12) | (((v >> 20) & 1) << 11) | (((v >> 21) & 0x3ff) << 1)
    if imm & (1 << 20): imm -= 1 << 21
    return pc + imm

def write_csv(path, data, keys):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(data)

def selftest():
    assert csr_number(bytes.fromhex("73200080")) == 0x800
    assert csr_number(bytes.fromhex("13000000")) is None
    assert jal_target(bytes.fromhex("ef000000"), 0x40000000) == 0x40000000
    assert jal_target(bytes.fromhex("ef000000"), 0x40000010) == 0x40000010
    assert jal_target(bytes.fromhex("13000000"), 0) is None
    b = baseline()
    assert len(b) == 648 and min(b) >= 0x40000000
    return True

def run():
    started = time.perf_counter()
    selftest()
    OUT.mkdir(parents=True, exist_ok=True)
    known = baseline()
    request = urllib.request.Request(URL, headers={"User-Agent": "rom-fast-reconcile/1"})
    archive = urllib.request.urlopen(request, timeout=120).read()
    if hashlib.sha256(archive).hexdigest() != ARCHIVE_SHA:
        raise RuntimeError("ROM archive checksum mismatch")
    results = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
        selected = [m for m in tf.getmembers() if m.isfile() and m.name.rsplit("/", 1)[-1] in {
            "esp32c3_rev0_rom.elf", "esp32c3_rev101_rom.elf", "esp32c3_rev3_rom.elf"}]
        if len(selected) != 3: raise RuntimeError("Expected exactly 3 C3 revisions")
        for member in sorted(selected, key=lambda m: m.name):
            name = pathlib.Path(member.name).name
            blob = tf.extractfile(member).read()
            elf = ELFFile(io.BytesIO(blob))
            if elf["e_machine"] != "EM_RISCV": raise RuntimeError("Wrong architecture")
            symtab = []
            for sec in elf.iter_sections():
                if sec["sh_type"] == "SHT_SYMTAB":
                    symtab += [{"name": s.name, "address": int(s["st_value"]), "size": int(s["st_size"])}
                               for s in sec.iter_symbols() if s["st_info"]["type"] == "STT_FUNC" and int(s["st_value"])]
            sym_addr = {r["address"] for r in symtab}
            matched = [s for s in symtab if s["address"] in known]
            other = [s for s in symtab if s["address"] not in known]
            absent = [{"known_symbol": v["symbol"], "address": hex(k)}
                      for k, v in sorted(known.items()) if k not in sym_addr]
            novel = [{"symbol": x["name"], "address": hex(x["address"]), "size": x["size"],
                      "classification": "ELF_FUNCTION_NOT_IN_648_LINKER_ENTRIES_NOT_PROOF_OF_HIDDEN_API"}
                     for x in other]
            csr = []
            direct_calls = []
            indirect = []
            decoder = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
            decoder.skipdata = True
            code_bytes = 0; decode_missing = 0
            for sec in elf.iter_sections():
                if sec["sh_type"] != "SHT_PROGBITS" or int(sec["sh_flags"]) & 4 == 0:
                    continue
                code = sec.data(); code_bytes += len(code)
                for ins in decoder.disasm(code, int(sec["sh_addr"])):
                    if ins.mnemonic == ".byte":
                        decode_missing += ins.size;continue
                    c = csr_number(ins.bytes)
                    if c is not None:
                        csr.append({"instruction_address": hex(ins.address), "csr": hex(c),
                                    "mnemonic": ins.mnemonic, "operands": ins.op_str})
                    tgt = jal_target(ins.bytes, ins.address)
                    if tgt is not None:
                        direct_calls.append({"instruction_address": hex(ins.address), "target_address": hex(tgt),
                                             "target_known_symbol": known.get(tgt, {}).get("symbol", "")})
                    if ins.mnemonic in {"jalr", "c.jalr"}:
                        indirect.append({"instruction_address": hex(ins.address), "operands": ins.op_str})
            prefix = OUT / name
            write_csv(pathlib.Path(str(prefix) + ".unmapped_functions.csv"), novel,
                      ["symbol","address","size","classification"])
            write_csv(pathlib.Path(str(prefix) + ".known_missing.csv"), absent, ["known_symbol","address"])
            write_csv(pathlib.Path(str(prefix) + ".csr.csv"), csr,
                      ["instruction_address","csr","mnemonic","operands"])
            write_csv(pathlib.Path(str(prefix) + ".direct_jal.csv"), direct_calls,
                      ["instruction_address","target_address","target_known_symbol"])
            write_csv(pathlib.Path(str(prefix) + ".indirect_jalr.csv"), indirect,
                      ["instruction_address","operands"])
            count = Counter(r["csr"] for r in csr)
            results[name] = {"sha256": hashlib.sha256(blob).hexdigest(), "elf_function_symbols": len(symtab),
                "unique_elf_function_addresses": len(sym_addr),
                "symbol_rows_matched_known_address": len(matched),
                "known_rom_function_addresses_present": len(set(known) & sym_addr),
                "known_rom_function_addresses_missing": len(absent),
                "unmapped_function_symbol_rows": len(novel),
                "csr_access_instructions": len(csr), "csr_address_counts": dict(sorted(count.items())),
                "jal_direct_instructions": len(direct_calls), "jalr_indirect_instructions": len(indirect),
                "linear_decoded_bytes": code_bytes - decode_missing, "executable_bytes": code_bytes,
                "undecoded_bytes": decode_missing}
    result = {"schema": "ESP32C3_ROM_FAST_RECONCILE_V1", "source": URL, "archive_sha256": ARCHIVE_SHA,
       "baseline_functions": len(known), "revisions": results,
       "elapsed_seconds": round(time.perf_counter() - started, 4),
       "limitations": ["Unmapped symbol is not a hidden API",
        "Linear disassembly does not establish control-flow reachability",
        "CSR instructions are extracted by actual RISC-V encoding; undocumented status needs manual reference comparison",
        "JALR indirect target remains unresolved", "Known baseline matches addresses, not semantic equivalence"]}
    (OUT / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return result

if __name__ == "__main__":
    run()
