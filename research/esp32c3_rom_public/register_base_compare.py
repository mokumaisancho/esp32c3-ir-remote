#!/usr/bin/env python3
"""Compare static ROM MMIO patterns with Espressif's published peripheral base table.

Finding a peripheral base is not evidence that a particular offset is documented,
and absence from this file cannot establish undocumented hardware.
"""
import collections
import hashlib
import json
import pathlib
import re

ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"register_access"
BASE=ROOT/"official_reg_base.h"
SOURCE_URL="https://github.com/espressif/esp-idf/blob/master/components/soc/esp32c3/register/soc/reg_base.h"
SOURCE_BLOB_SHA="d0ef6acfeeb32f66365bdbb1410ab906450374dc"

def read_bases(text):
    d=collections.defaultdict(list)
    for line in text.splitlines():
        m=re.match(r"^#define\s+(DR_REG_\w+)\s+(0x[0-9a-fA-F]+)\b",line)
        if m and (m.group(1).endswith("_BASE") or m.group(1)=="DR_REG_MMU_TABLE"):
            d[int(m.group(2),16)].append(m.group(1))
    if not d:raise ValueError("NO_OFFICIAL_BASES_FOUND")
    return dict(sorted(d.items()))

def classify_mmio(address, base_table, window=0x1000):
    addr=int(address,16) if isinstance(address,str) else int(address)
    eligible=[a for a in base_table if a<=addr<a+window]
    if not eligible:
        return {"classification":"BASE_WINDOW_UNRESOLVED","base":None,
                "offset":None,"bases":[]}
    start=max(eligible)
    return {"classification":"WITHIN_OFFICIAL_BASE_WINDOW_NOT_OFFSET_PROOF",
            "base":hex(start),"offset":hex(addr-start),"bases":sorted(base_table[start])}

def run():
    bases=read_bases(BASE.read_text())
    total={}
    for filename in ("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf"):
        p=OUT/(filename+".mmio.json")
        if not p.is_file():raise RuntimeError("MISSING_MMIO_EVIDENCE:"+filename)
        hits=json.loads(p.read_text())
        by_address=collections.defaultdict(list)
        for r in hits:
            by_address[r["address"]].append(r)
        rows=[]
        for addr, proof in sorted(by_address.items(),key=lambda x:int(x[0],16)):
            c=classify_mmio(addr,bases)
            rows.append({"address":addr, "static_evidence_count":len(proof),
                         "first_instruction_address":proof[0]["access_pc"],
                         **c})
        output=OUT/(filename+".official_base_comparison.json")
        output.write_text(json.dumps(rows,indent=2)+"\n")
        count=collections.Counter(r["classification"] for r in rows)
        total[filename]={"unique_addresses":len(rows),"classification_counts":dict(count),
            "official_base_window_hits":sum(x["classification"].startswith("WITHIN_") for x in rows),
            "undetermined_addresses":[x["address"] for x in rows if x["base"] is None],
            "top_accesses":sorted(rows,key=lambda x:-x["static_evidence_count"])[:15]}
    result={"schema":"ROM_MMIO_OFFICIAL_BASE_COMPARISON_V1",
        "source_url":SOURCE_URL,"source_blob_sha":SOURCE_BLOB_SHA,
        "source_file_sha256":hashlib.sha256(BASE.read_bytes()).hexdigest(),
        "window_bytes":0x1000,"base_definitions":sum(map(len,bases.values())),
        "limitations":["Window membership is not evidence that the exact register offset is documented",
          "A missing base-window match does not imply undocumented hardware",
          "MMIO access extraction misses complex dataflow, compressed access and computed pointers"],
        "revisions":total}
    (OUT/"official_base_comparison.json").write_text(json.dumps(result,indent=2)+"\n")
    print("REGISTER_BASE_COMPARE_RESULT "+json.dumps(result,separators=(",",":")))
    return result

if __name__=="__main__":
    run()
