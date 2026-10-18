#!/usr/bin/env python3
"""ROM address-level audit: classification is evidence, never an API discovery assertion."""
import csv, hashlib, io, json, pathlib, tarfile, urllib.request
from collections import Counter
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
from rom_opcode import classify

ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"entry_audit"
ARCHIVE_URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
ARCHIVE_SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVISIONS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")

def read_baseline():
    with (ROOT/"rom_api_baseline.csv").open(newline="") as f:
        rows=list(csv.DictReader(f))
    if len(rows)!=864 or sum(x["type"]=="function" for x in rows)!=648:
        raise RuntimeError("G1_BASELINE_INCOMPLETE")
    return [(x["symbol"],int(x["address"],16)) for x in rows if x["type"]=="function"]

def covered_code(elf):
    return [s for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS" and int(s["sh_flags"]) & 4]

def extract(section, address, amount=16):
    start=int(section["sh_addr"]);size=int(section["sh_size"])
    if start<=address<start+size:
        return section.data()[address-start:address-start+amount]
    return None

def union_length(intervals):
    total=0;end=0
    for begin,finish in sorted(intervals):
        if finish<=end:continue
        total += finish-max(begin,end)
        end=finish
    return total

def analyze(archive):
    known=read_baseline()
    result={"schema":"ESP32C3_ROM_ENTRY_AUDIT_V1","archive_sha256":ARCHIVE_SHA,
            "classification_authority":"OBSERVATION_ONLY_NOT_HIDDEN_API_PROOF","revisions":{}}
    with tarfile.open(fileobj=io.BytesIO(archive),mode="r:gz") as t:
        for filename in REVISIONS:
            m=[x for x in t.getmembers() if x.isfile() and pathlib.PurePosixPath(x.name).name==filename]
            if len(m)!=1:raise RuntimeError("G1_REVISION_MISSING_OR_DUPLICATE:"+filename)
            data=t.extractfile(m[0]).read(); e=ELFFile(io.BytesIO(data))
            if e["e_machine"]!="EM_RISCV":raise RuntimeError("G1_NOT_RISCV")
            sections=covered_code(e)
            allfunc=[]
            for sec in e.iter_sections():
                if sec["sh_type"]=="SHT_SYMTAB":
                    allfunc += [(s.name,int(s["st_value"]),int(s["st_size"])) for s in sec.iter_symbols()
                                if s["st_info"]["type"]=="STT_FUNC" and int(s["st_value"])]
            by_name={name:(addr,size) for name,addr,size in allfunc if name}
            by_addr={}
            for name,addr,size in allfunc:by_addr.setdefault(addr,[]).append(name)
            rows=[];classifications=Counter();namematches=0;target_name_matches=0
            engine=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC);engine.skipdata=True
            for sym,addr in known:
                owning=[s for s in sections if extract(s,addr,1) is not None]
                if len(owning)!=1:raise RuntimeError(f"G1_KNOWN_ADDR_NOT_UNIQUE_EXEC_SECTION:{filename}:{sym}:{hex(addr)}")
                data_at=extract(owning[0],addr)
                out=classify(data_at,addr)
                first=list(engine.disasm(data_at,addr,count=2))
                if not first or first[0].mnemonic==".byte":
                    first_mnemonic="UNDECODED"
                else:first_mnemonic=first[0].mnemonic+" "+first[0].op_str
                known_elf=by_name.get(sym)
                target=out["target"]
                matches_name=known_elf is not None
                target_name=bool(known_elf and target==known_elf[0])
                namematches+=int(matches_name);target_name_matches+=int(target_name)
                classifications[out["kind"]]+=1
                rows.append({"symbol":sym,"known_address":hex(addr),"section":owning[0].name,
                             "opcode_bytes":data_at[:12].hex(),"first_instruction":first_mnemonic,
                             "branch_kind":out["kind"],"branch_target":hex(target) if target is not None else None,
                             "elf_same_name_address":hex(known_elf[0]) if known_elf else None,
                             "target_equals_same_name_elf":target_name,
                             "target_elf_symbols":by_addr.get(target,[]) if target is not None else []})
            if len(rows)!=648:raise RuntimeError("G1_648_ENTRIES_NOT_COVERED")
            # Capstone (third-party) and our independent encoding bit decoder
            # must agree on the relative JAL displacement, without using ELF
            # symbol names as either decoder's oracle.
            divergent=[]
            for row in rows:
                if row["branch_kind"]!="JAL":
                    divergent.append({"symbol":row["symbol"],"reason":"NOT_JAL"})
                    continue
                # Example: Capstone emits 'j 0x48294' for a relative offset.
                raw_operand=row["first_instruction"].split()[-1]
                try:
                    capstone_offset=int(raw_operand,0)
                    independent_offset=int(row["branch_target"],16)-int(row["known_address"],16)
                except (ValueError, TypeError):
                    divergent.append({"symbol":row["symbol"],"reason":"UNPARSEABLE_DISPLACEMENT"})
                    continue
                if capstone_offset!=independent_offset:
                    divergent.append({"symbol":row["symbol"],"reason":"OFFSET_MISMATCH",
                                      "capstone":capstone_offset,"independent":independent_offset})
            if divergent:raise RuntimeError("G3_INDEPENDENT_DISASSEMBLER_MISMATCH:"+str(divergent[:10]))
            unresolved=[{"symbol":r["symbol"],"address":r["known_address"],
                         "target":r["branch_target"],"target_ELF_names":r["target_elf_symbols"],
                         "same_name_present":bool(r["elf_same_name_address"])} for r in rows
                        if not r["target_equals_same_name_elf"]]
            if not any(row["first_instruction"]!="UNDECODED" for row in rows):
                raise RuntimeError("G3_NO_KNOWN_ENTRY_DECODES")
            intervals=[];exec_bytes=0
            for sec in sections:
                st=int(sec["sh_addr"]);en=st+int(sec["sh_size"]);exec_bytes+=en-st
                local=[(max(st,addr),min(en,addr+size)) for _,addr,size in allfunc
                       if size>0 and addr<en and addr+size>st]
                intervals+=local
            named_bytes=union_length(intervals)
            if named_bytes>exec_bytes:raise RuntimeError("G4_INVALID_FUNCTION_COVERAGE")
            result["revisions"][filename]={"sha256":hashlib.sha256(data).hexdigest(),
              "entry_rows":len(rows),"first_instruction_decode_count":sum(x["first_instruction"]!="UNDECODED" for x in rows),
              "classes":dict(sorted(classifications.items())),"elf_same_name_count":namematches,
              "direct_target_equals_same_name_elf":target_name_matches,
              "elf_function_symbols":len(allfunc),"executable_bytes":exec_bytes,
              "covered_by_ELF_STT_FUNC_size_intervals_bytes":named_bytes,
              "not_covered_by_ELF_STT_FUNC_size_intervals_bytes":exec_bytes-named_bytes,
              "coverage_caution":"size intervals are symbol metadata not program reachability",
              "sample_entries":rows[:15],
              "first_resolved_links":[r for r in rows if r["branch_target"] is not None][:20],
              "independent_capstone_offset_agreement":648,
              "unresolved_linker_names":unresolved}
            OUT.mkdir(parents=True,exist_ok=True)
            (OUT/(filename+".entries.json")).write_text(json.dumps(rows,indent=2)+"\n")
    (OUT/"entry_audit_summary.json").write_text(json.dumps(result,indent=2)+"\n")
    print("ENTRY_AUDIT_RESULT "+json.dumps(result,separators=(",",":")))
    return result

def main():
    req=urllib.request.Request(ARCHIVE_URL,headers={"User-Agent":"ROM-EVIDENCE-AUDIT"})
    data=urllib.request.urlopen(req,timeout=120).read()
    if hashlib.sha256(data).hexdigest()!=ARCHIVE_SHA:
        raise RuntimeError("G1_BAD_ARCHIVE_SHA256")
    return analyze(data)

if __name__=="__main__":
    main()
