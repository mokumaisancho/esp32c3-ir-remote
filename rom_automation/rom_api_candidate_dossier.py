#!/usr/bin/env python3
"""ROM-001: independently enumerate full instructions of revision-pinned ROM API leads.

Does not certify newness, ABI, physical safety, or external callability.
"""
import argparse,hashlib,io,json,pathlib,tarfile
from elftools.elf.elffile import ELFFile

ROM_SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REV="esp32c3_rev101_rom.elf"
ELF_SHA="9495e1453f36f7eec4112714ea1dca22d77808776adffa93dda7dda4393e8336"
TARGETS={
 "rom2_temp_to_power1":("0x4003e9fe",38,"af3082b062898053b7b87d13db160876549cc293e225cac8177410715a2422a5"),
 "ieee80211_hdrsize":("0x40045d04",50,"d2ed103b58694067105363a1b04cfa29ea1dc22f534d0e642324925d878f1798"),
 "rom2_get_tx_gain_value1":("0x4003efb4",72,"7fe6e5bf1ecec26be5f568afc08f8e5758c56dbc14df1f0a3a3220d122f6a001")
}
STORES={"sw","sh","sb","c.sw","c.swsp","sc.w","amoswap.w","amoadd.w","amoor.w","amoand.w","amoxor.w"}
LOADS={"lw","lh","lhu","lb","lbu","c.lw","c.lwsp"}
CSR=("csrr", "csrw", "csrs", "csrc")
TRAPS={"ecall","ebreak","c.ebreak","unimp","c.unimp",".byte"}
FLOAT={"flw","fsw","fld","fsd","c.flw","c.fsw","c.fld","c.fsd"}
RETURN={"c.jr ra","jr ra","ret","jalr zero, 0(ra)","jalr zero,0(ra)"}
CALL={"jal","jalr","c.jal","c.jalr"}

def summary(instructions, expected_size):
    addresses=[int(x["pc"],16) for x in instructions]
    size=sum(len(bytes.fromhex(x["hex"])) for x in instructions)
    m=[x["mnemonic"] for x in instructions]
    texts=[x["mnemonic"]+" "+x["operands"] for x in instructions]
    is_return=[x in RETURN for x in texts]
    invalid=[x for x in m if x in TRAPS or x in FLOAT]
    stores=[x for x in m if x in STORES or x.startswith(("amo","fence"))]
    indirect_calls=[x for x,b in zip(m,is_return) if x in CALL and not b]
    return {
        "complete_disassembly":size==expected_size and len(set(addresses))==len(addresses),
        "instruction_count":len(instructions),"loaded_instructions":sum(x in LOADS for x in m),
        "store_or_atomic_instructions":stores,"trap_or_invalid_instructions":invalid,
        "nonreturn_direct_or_indirect_call_instructions":indirect_calls,
        "return_instructions":sum(is_return),
        "local_no_store_no_call_heuristic":size==expected_size and not stores and not invalid and not indirect_calls and any(is_return),
        "callable_or_abi_proven":False,"previously_unpublished_proven":False,
        "new_hardware_capability_proven":False
    }

def evaluate(path):
    from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
    data=path.read_bytes()
    if hashlib.sha256(data).hexdigest()!=ROM_SHA:raise ValueError("PINNED_ROM_ARCHIVE_SHA_MISMATCH")
    with tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as t:
        candidates=[m for m in t.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==REV]
        if len(candidates)!=1:raise ValueError("ROM_REVISION_COUNT")
        b=t.extractfile(candidates[0]).read()
    if hashlib.sha256(b).hexdigest()!=ELF_SHA:raise ValueError("REV101_ELF_SHA_MISMATCH")
    e=ELFFile(io.BytesIO(b))
    tables=[s for s in e.iter_sections() if s["sh_type"]=="SHT_SYMTAB"]
    sections=[s for s in e.iter_sections() if s["sh_type"]=="SHT_PROGBITS" and int(s["sh_flags"])&4]
    decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
    results={}
    for name,(expected_address,expected_size,expected_hash) in TARGETS.items():
        matches=[s for tab in tables for s in tab.iter_symbols()
                 if s.name==name and s["st_info"]["type"]=="STT_FUNC"]
        if len(matches)!=1:raise ValueError("SYMBOL_CARDINALITY:"+name)
        sym=matches[0];a=int(sym["st_value"]);n=int(sym["st_size"])
        if (hex(a),n)!=(expected_address,expected_size):raise ValueError("ENTRY_OR_SIZE_DRIFT:"+name)
        blocks=[section.data()[a-int(section["sh_addr"]):a-int(section["sh_addr"])+n]
                for section in sections if int(section["sh_addr"])<=a and a+n<=int(section["sh_addr"])+int(section["sh_size"])]
        if len(blocks)!=1:raise ValueError("FUNCTION_CODE_SECTION_AMBIGUOUS:"+name)
        block=blocks[0]
        if hashlib.sha256(block).hexdigest()!=expected_hash:raise ValueError("PINNED_FUNCTION_BYTE_DRIFT:"+name)
        decoded=list(decoder.disasm(block,a))
        if sum(x.size for x in decoded)!=n:raise ValueError("INCOMPLETE_MACHINE_DECODE:"+name)
        instructions=[{"pc":hex(x.address),"hex":bytes(x.bytes).hex(),"mnemonic":x.mnemonic,"operands":x.op_str} for x in decoded]
        risk=summary(instructions,n)
        results[name]={"revision":REV,"entry":hex(a),"size_bytes":n,
                       "function_sha256":expected_hash,"instructions":instructions,"static_evidence":risk,
                       "symbol_from_public_vendor_ROM_ELF":True,
                       "novelty_and_safety_status":"UNVERIFIED"}
    return {"schema":"ROM001_NEW_API_FUNCTION_DOSSIERS_V1","source_archive_sha256":ROM_SHA,
            "source_rev101_elf_sha256":ELF_SHA,"original_issue":"ESP32C3-ROM-001",
            "analysis_method":"complete RV32IMC Capstone disassembly of pinned machine bytes",
            "new_api_certified_count":0,"new_api_candidates":results,
            "next_gate":"Recover complete data/control semantics and input/output ABI; independently falsify published equivalents; no physical call without approved revision-specific test."}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--rom",required=True,type=pathlib.Path)
    parser.add_argument("--out",required=True,type=pathlib.Path)
    a=parser.parse_args()
    result=evaluate(a.rom);a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("ROM001_CANDIDATES",json.dumps({k:{"entry":v["entry"],**v["static_evidence"]} for k,v in result["new_api_candidates"].items()},sort_keys=True))
if __name__=="__main__":main()
