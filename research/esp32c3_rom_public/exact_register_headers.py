#!/usr/bin/env python3
"""Match ROM static MMIO access addresses against vendor per-register macro offsets.

Only simple (DR_REG_X_BASE + integer offset) expressions are recognized.
Unmatched does NOT mean undocumented; macros can be dynamic or unsupported.
"""
import concurrent.futures
import collections
import hashlib
import json
import pathlib
import re
import urllib.request
from register_base_compare import read_bases

ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"register_access"
UPSTREAM_COMMIT="1c42e514c90ae621af33bde3b6ad3dac22edcbfd"
UPSTREAM="https://raw.githubusercontent.com/espressif/esp-idf/"+UPSTREAM_COMMIT+"/components/soc/esp32c3/register/soc/"
HEADERS=("apb_ctrl_reg.h","apb_saradc_reg.h","assist_debug_reg.h",
"efuse_reg.h","extmem_reg.h","gdma_reg.h","gpio_reg.h","gpio_sd_reg.h",
"i2c_reg.h","i2s_reg.h","interrupt_core0_reg.h","io_mux_reg.h","ledc_reg.h",
"nrx_reg.h","rmt_reg.h","rtc_cntl_reg.h","rtc_i2c_reg.h","sensitive_reg.h",
"spi_mem_reg.h","spi_reg.h","syscon_reg.h","system_reg.h","systimer_reg.h",
"timer_group_reg.h","uart_reg.h","uhci_reg.h","usb_serial_jtag_reg.h","xts_aes_reg.h")

def parse_exact_registers(text, base_by_name):
    mapped=[];unresolved=[]
    # A parseable reference has a pure integer addition, no expressions or macros.
    expr=re.compile(r"^\s*#define\s+([A-Za-z_][A-Za-z_0-9]*_REG)\s+"+
                    r"\(\s*(DR_REG_[A-Za-z_0-9]+_BASE)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
    for line in text.splitlines():
        m=expr.match(line)
        if not m:continue
        symbol,base,off=m.groups()
        if base in base_by_name:
            mapped.append((int(base_by_name[base])+int(off,0),symbol,base))
        else:unresolved.append({"name":symbol,"base_macro":base})
    return mapped,unresolved

def download(header):
    req=urllib.request.Request(UPSTREAM+header,headers={"User-Agent":"esp32c3-rom-audit/1"})
    data=urllib.request.urlopen(req,timeout=90).read()
    return header,data

def main():
    bases=read_bases((ROOT/"official_reg_base.h").read_text())
    by_name={name:base for base,names in bases.items() for name in names}
    mapped=collections.defaultdict(list);unknown=[];hashes={}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for fname,raw in pool.map(download,HEADERS):
            hashes[fname]=hashlib.sha256(raw).hexdigest()
            entries,unresolved=parse_exact_registers(raw.decode(),by_name)
            for address,sym,base in entries:
                mapped[address].append({"header":fname,"symbol":sym,"base":base})
            unknown.extend({"header":fname,**x} for x in unresolved)
    report={"schema":"ROM_OFFICIAL_REGISTER_EXACT_OFFSET_MATCH_V1",
      "upstream_git_commit":UPSTREAM_COMMIT,"headers_scanned":len(HEADERS),
      "header_sha256":dict(sorted(hashes.items())),"simple_register_macros_resolved":sum(map(len,mapped.values())),
      "unresolved_base_macro_references":len(unknown),
      "unresolved_base_macro_examples":unknown[:25],
      "scope":"Only simple constant-offset register definitions in version-pinned Espressif headers",
      "limitations":["Unknown header macro expressions not parsed","Missing exact offset is NOT an undocumented register",
         "No dynamic execution validation or field semantics","Unmatched vendor macro names may have aliases"],
      "revisions":{}}
    for rev in ("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf"):
        p=OUT/(rev+".mmio.json")
        if not p.exists():raise RuntimeError("MISSING_MMIO_EVIDENCE:"+rev)
        raw=json.loads(p.read_text())
        addresses=sorted({int(x["address"],16) for x in raw})
        exact=[{"address":hex(a),"vendor_symbols":mapped[a]} for a in addresses if a in mapped]
        unmatched=[hex(a) for a in addresses if a not in mapped]
        report["revisions"][rev]={"unique_rom_mmio_addresses":len(addresses),
            "exact_vendor_register_offsets_matched":len(exact),
            "not_matched_to_simple_vendor_macros":len(unmatched),
            "exact_matches":exact,"unmatched_addresses":unmatched}
    dest=OUT/"official_exact_offset_comparison.json"
    dest.write_text(json.dumps(report,indent=2)+"\n")
    print("REGISTER_EXACT_OFFSET_RESULT "+json.dumps({**{k:v for k,v in report.items() if k not in ("header_sha256","revisions")},
        "revisions":{name:{k:v for k,v in row.items() if k not in ("exact_matches","unmatched_addresses")} for name,row in report["revisions"].items()}},separators=(",",":")))
    return report
if __name__=="__main__":
    main()
