#!/usr/bin/env python3
"""ROM core algorithm inspection: instruction-accurate function body traces.

DO NOT infer function semantics from symbol names alone.
Print bounded full instruction evidence so a reviewer can reconstruct algorithms.
"""
import hashlib,io,json,pathlib,tarfile,urllib.request
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
from rom_opcode import jal,compressed_jump
BASE=pathlib.Path(__file__).resolve().parent
OUT=BASE/"output"/"focused"
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
FUNCTIONS=("r_emi_alloc_em_mapping_by_offset","r_emi_free_em_mapping_by_offset","hal_enable_mac",
           "r_lld_test_start","GetSecurityInfoProc")
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
MAX_PRINT_INSTRUCTIONS=150
def inspect(elf,name,mmio_events,csr_events):
    syms=[]
    addr_to_names={}
    for section in elf.iter_sections():
        if section["sh_type"]!="SHT_SYMTAB": continue
        for s in section.iter_symbols():
            if s["st_info"]["type"]!="STT_FUNC" or not int(s["st_value"]):continue
            address=int(s["st_value"]);sz=int(s["st_size"])
            addr_to_names.setdefault(address,[]).append(s.name)
            if s.name==name:syms.append((address,sz))
    if len(set(syms))!=1 or syms[0][1]<4:
        return {"name":name,"status":"FUNCTION_MISSING_OR_AMBIGUOUS","symbols":syms}
    address,size=syms[0]
    matches=[sec for sec in elf.iter_sections() if sec["sh_type"]=="SHT_PROGBITS" and int(sec["sh_flags"])&4
             and int(sec["sh_addr"])<=address and address+size<=int(sec["sh_addr"])+int(sec["sh_size"])]
    if len(matches)!=1: return {"name":name,"status":"FUNCTION_OUTSIDE_SINGLE_EXECUTABLE_SECTION","address":hex(address),"size":size}
    section=matches[0];start=address-int(section["sh_addr"])
    data=section.data()[start:start+size]
    decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC);decoder.skipdata=True
    instructions=list(decoder.disasm(data,address))
    total=sum(ins.size for ins in instructions)
    if total!=size: raise RuntimeError("INCOMPLETE_DISASSEMBLY:"+name)
    trace=[];direct=[];branch=[];indirect=[]; undecoded=0
    for i,ins in enumerate(instructions):
        raw=bytes(ins.bytes)
        target=jal(raw,ins.address)
        if target is None:target=compressed_jump(raw,ins.address)
        note=[]
        if target is not None:
            names=addr_to_names.get(target,[])
            note.append("DIRECT_TARGET="+hex(target)+((" NAME="+",".join(names)) if names else ""))
            direct.append({"pc":hex(ins.address),"target":hex(target),"elf_names":names})
        if ins.mnemonic in ("beq","bne","blt","bge","bltu","bgeu","c.beqz","c.bnez"):
            branch.append({"pc":hex(ins.address),"mnemonic":ins.mnemonic,"operands":ins.op_str})
        if ins.mnemonic in ("jalr","c.jr","c.jalr"):
            indirect.append({"pc":hex(ins.address),"mnemonic":ins.mnemonic,"operands":ins.op_str})
        if ins.mnemonic==".byte":undecoded+=ins.size
        trace.append({"pc":hex(ins.address),"hex":raw.hex(),"mnemonic":ins.mnemonic,
                      "operands":ins.op_str,"notes":note})
    lo,hi=address,address+size
    registers=[{"kind":"MMIO","pc":x["access_pc"],"address":x["address"],"pattern":x["pattern"],
                "raw_bytes":x["source_bytes"],"access":x["kind"]}
        for x in mmio_events if lo<=int(x["access_pc"],16)<hi]
    registers +=[{"kind":"CSR","pc":x["address"],"address":x["csr"],
                 "mnemonic":x["mnemonic"],"raw_bytes":x["raw_bytes"]}
        for x in csr_events if lo<=int(x["address"],16)<hi]
    return {"name":name,"status":"EXTRACTED","address":hex(address),"size_bytes":size,"section":section.name,
            "machine_code_sha256":hashlib.sha256(data).hexdigest(),"instruction_count":len(instructions),
            "undecoded_bytes":undecoded,"branch_count":len(branch),
            "direct_jump_count":len(direct),"indirect_transfer_count":len(indirect),
            "direct_jumps":direct,"conditional_branches":branch,"indirect_transfers":indirect,
            "register_access_evidence":registers,"instructions":trace}
def main():
    request=urllib.request.Request(URL,headers={"User-Agent":"rom-core-analysis/1"})
    tarbytes=urllib.request.urlopen(request,timeout=120).read()
    if hashlib.sha256(tarbytes).hexdigest()!=SHA:raise RuntimeError("G1_ARCHIVE_SHA_MISMATCH")
    OUT.mkdir(parents=True,exist_ok=True)
    summary={"schema":"ROM_CORE_FUNCTION_DISASSEMBLY_V1","archive_sha256":SHA,"revisions":{},
      "limitation":"Instruction evidence and symbolic direct targets only; not executable pseudocode or inferred hardware behavior."}
    with tarfile.open(fileobj=io.BytesIO(tarbytes),mode="r:gz") as archive:
        for rev in REVS:
            records=[m for m in archive.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
            if len(records)!=1:raise RuntimeError("G1_REVISION_MISSING_OR_DUPLICATE:"+rev)
            blob=archive.extractfile(records[0]).read(); elf=ELFFile(io.BytesIO(blob))
            if elf["e_machine"]!="EM_RISCV":raise RuntimeError("G1_ELF_NOT_RISCV")
            mmio=json.loads((BASE/"output"/"register_access"/(rev+".mmio.json")).read_text())
            csr=json.loads((BASE/"output"/"register_access"/(rev+".csr.json")).read_text())
            outputs=[inspect(elf,name,mmio,csr) for name in FUNCTIONS]
            summary["revisions"][rev]={x["name"]:{k:v for k,v in x.items() if k not in
                ("instructions","direct_jumps","conditional_branches","indirect_transfers","register_access_evidence")}
                for x in outputs}
            (OUT/(rev+".json")).write_text(json.dumps(outputs,indent=2)+"\n")
            if rev=="esp32c3_rev3_rom.elf":
                for x in outputs:
                    # 150 real instruction lines per function, plus register evidence; no artificial meaning labels.
                    print("FUNCTION_MACHINE_CODE "+json.dumps({
                        "revision":rev,"name":x["name"],"status":x["status"],
                        "address":x.get("address"),"size":x.get("size_bytes"),
                        "machine_code_sha256":x.get("machine_code_sha256"),
                        "registers":x.get("register_access_evidence",[]),
                        "direct_jumps":x.get("direct_jumps",[]),
                        "branch_count":x.get("branch_count"),
                        "indirect_count":x.get("indirect_transfer_count"),
                        "total_instructions":x.get("instruction_count"),
                        "instructions":x.get("instructions",[])[:MAX_PRINT_INSTRUCTIONS],
                        "truncated_print":len(x.get("instructions",[]))>MAX_PRINT_INSTRUCTIONS
                    },separators=(",",":")))
    (OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    print("FUNCTION_CORE_SUMMARY "+json.dumps(summary,separators=(",",":")))
if __name__=="__main__":main()
