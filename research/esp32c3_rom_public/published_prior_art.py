#!/usr/bin/env python3
"""Independent, predating-2026 published ESP32-C3 Wi-Fi register evidence.

Published addresses are NOT used to tune the opcode scanner or synthetic tests.
An absent hit is not a falsification, given the scanner's strict dataflow subset.
"""
import collections
import json
import pathlib

ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"register_access"
REVISIONS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
PAPER={
  "title":"Open-Source ESP32-C3 Wi-Fi Drivers for Static Analysis",
  "year":2025,
  "arxiv":"https://arxiv.org/abs/2501.17684",
  "text":"https://www.researchgate.net/publication/388495335_Open-Source_ESP32-C3_Wi-Fi_Drivers_for_Static_Analysis",
  "details":"Author's version Table 1 and section 4.2; researcher-derived behavior, not vendor-certified register definitions."
}
# Named source register addresses were published before this 2026 ROM analysis.
# They are not synthetic test fixtures or a training/truth label for the scanner.
PUBLISHED={
 "0x60033000":"Wi-Fi MAC address configuration",
 "0x60033084":"Wi-Fi RX enable/disable",
 "0x60033088":"Wi-Fi RX DMA list base",
 "0x60033ca0":"Wi-Fi power on/off",
 "0x60033d08":"Wi-Fi TX DMA trigger/address",
 "0x60033c3c":"Wi-Fi interrupt reason",
 "0x60033c40":"Wi-Fi interrupt clear",
 "0x60033cac":"Wi-Fi TX slot clear",
 "0x600c2104":"Wi-Fi interrupt enable/disable mask (paper section 4.2)"
}

def main():
    report={"schema":"ROM_PUBLISHED_PRIOR_ART_COMPARE_V1",
      "independence":"prior publication (2025), not incorporated into algorithm or tests",
      "source":PAPER,
      "limitations":["Function meaning is as inferred by prior authors, not independently verified here",
        "No observation from strict LUI/ADDI memory scanner does not prove absent hardware use",
        "Matching address alone cannot establish identical semantics across revisions"],
      "revisions":{}}
    for rev in REVISIONS:
        p=OUT/(rev+".mmio.json")
        if not p.is_file():raise RuntimeError("MISSING_RAW_MMIO_PROOF:"+rev)
        hits=json.loads(p.read_text())
        group=collections.defaultdict(list)
        for h in hits:group[h["address"].lower()].append(h)
        matches=[];misses=[]
        for address,label in sorted(PUBLISHED.items()):
            if address in group:
                matches.append({"address":address,"prior_description":label,
                    "observed_static_count":len(group[address]),
                    "evidence":[{"pc":h["access_pc"],"function_hints":h["function_hints"],
                                 "source_bytes":h["source_bytes"]} for h in group[address][:5]]})
            else:
                misses.append({"address":address,"prior_description":label,
                    "status":"NOT_SEEN_BY_STRICT_PATTERN_ONLY"})
        report["revisions"][rev]={"published_prior_count":len(PUBLISHED),
            "matched_published_addresses":len(matches),
            "matched_prior_evidence":matches,
            "not_seen_strict_scanner":misses}
    out=OUT/"published_prior_art_comparison.json"
    out.write_text(json.dumps(report,indent=2)+"\n")
    print("PUBLISHED_PRIOR_ART_RESULT "+json.dumps(report,separators=(",",":")))
    return report

if __name__=="__main__":
    main()
