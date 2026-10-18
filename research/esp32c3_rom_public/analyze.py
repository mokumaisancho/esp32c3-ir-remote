#!/usr/bin/env python3
import csv,hashlib,io,json,pathlib,re,tarfile,urllib.request
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output";OUT.mkdir(parents=True,exist_ok=True)
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
EXPECTED="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
data=urllib.request.urlopen(URL,timeout=120).read()
actual=hashlib.sha256(data).hexdigest()
if actual!=EXPECTED: raise ValueError("Archive SHA256 mismatch: "+actual)
report={"source":URL,"archive_sha256":actual,"targets":{}}
with tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as tar:
    matched=[m for m in tar if m.isfile() and re.search(r"esp32c3.*rom.*\.elf$",m.name,re.I)]
    if not matched:
        names=[m.name for m in tar.getmembers() if "esp32c3" in m.name.lower()]
        raise RuntimeError("No ESP32C3 ROM ELF found; candidate entries: "+str(names[:30]))
    for member in matched:
        blob=tar.extractfile(member).read(); name=pathlib.Path(member.name).name
        elf=ELFFile(io.BytesIO(blob))
        if elf["e_machine"]!="EM_RISCV":raise ValueError("Wrong architecture: "+name)
        funcs=[]; sections=[]; suspicious=[]
        for sec in elf.iter_sections():
            if sec["sh_type"]=="SHT_SYMTAB":
                for sym in sec.iter_symbols():
                    if sym["st_info"]["type"]=="STT_FUNC" and sym["st_value"]:
                        funcs.append({"symbol":sym.name,"address":hex(int(sym["st_value"])),"size":int(sym["st_size"])})
            if sec["sh_type"]=="SHT_PROGBITS" and int(sec["sh_flags"])&4:
                machine=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
                machine.skipdata=True
                buf=sec.data(); decoded=list(machine.disasm(buf,int(sec["sh_addr"])))
                gaps=sum(ins.size for ins in decoded if ins.mnemonic==".byte")
                sections.append({"section":sec.name,"address":hex(int(sec["sh_addr"])),"size":len(buf),"undecoded_bytes":gaps,"decoded_bytes":len(buf)-gaps,"coverage_note":"linear scan only; data embedded in executable sections possible"})
                for ins in decoded:
                    if ins.mnemonic.startswith(("csr","csrr")) or ins.mnemonic in ("jal","jalr"):
                        suspicious.append({"address":hex(ins.address),"mnemonic":ins.mnemonic,"operands":ins.op_str})
        for suffix,rows,cols in [("functions",funcs,["symbol","address","size"]),("control_csr",suspicious,["address","mnemonic","operands"])]:
            with (OUT/(name+"."+suffix+".csv")).open("w",newline="") as f:
                w=csv.DictWriter(f,fieldnames=cols);w.writeheader();w.writerows(rows)
        report["targets"][name]={"sha256":hashlib.sha256(blob).hexdigest(),"elf_functions":len(funcs),"sections":sections,"csr_control_instructions":len(suspicious),"source_tar_path":member.name}
(OUT/"report.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
print(json.dumps(report,indent=2))
