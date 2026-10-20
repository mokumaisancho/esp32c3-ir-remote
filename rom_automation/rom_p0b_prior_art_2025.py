#!/usr/bin/env python3
"""ROM-001: correct novelty candidate backlog using a 2025 ESP32-C3 study.

Mudraje et al., ENSsys 2025, Table 1 printed p.4 (PDF page index 3):
https://arxiv.org/pdf/2501.17684
DOI:10.1145/3722572.3727926
The table lists 8 ESP32-C3 Wi-Fi MMIO addresses. Only 3 intersect our
14 vendor-TRM-'Reserved' addresses. Prior art does not certify behavior
for *this* ROM revision, but disqualifies claim of first discovery.
"""
import argparse,collections,json,pathlib
from decision_gate import ROM_SHA,require
PAPER_URL="https://arxiv.org/pdf/2501.17684"
PAPER_DOI="10.1145/3722572.3727926"
# Copy of address->research authors' deduced purpose, Table 1 of 2025 paper.
TABLE1={
 0x60033000:"MAC address configuration",
 0x60033084:"Wi-Fi RX enable/disable (MS bit)",
 0x60033088:"RX DMA linked-list base address",
 0x60033ca0:"Wi-Fi power up/down",
 0x60033d08:"TX DMA address and trigger",
 0x60033c3c:"Read interrupt reason",
 0x60033c40:"Clear interrupt",
 0x60033cac:"Clear TX slot"
}
def compare(trm):
 require(trm.get("schema")=="ROM001_P0B_14_TRM_RESERVED_CLASSIFICATION_V1","TRM_SOURCE")
 require(trm["source_ROM_SHA256"]==ROM_SHA,"ROM_PIN_DRIFT")
 rows=trm["all_address_evidence"]
 require(len(rows)==16,"PINNED_16_ADDRESS_DRIFT")
 reserved={int(x["address"],16) for x in rows if x["classification"]=="TRM_RESERVED"}
 require(len(reserved)==14,"PINNED_RESERVED14_COUNT")
 known=reserved & set(TABLE1)
 require(known=={0x60033084,0x60033088,0x60033ca0},
         "PINNED_TABLE1_PRIOR_ART_ADDRESS_MISMATCH")
 detailed=[]
 for row in rows:
  addr=int(row["address"],16)
  knownprior=addr in TABLE1
  status=("PRIOR_ART_REPORTED_2025" if knownprior else
     "NO_MATCH_IN_THIS_SPECIFIC_PAPER_NOT_WORLDWIDE_NOVEL")
  detailed.append({**row,
    "2025_paper_table1_same_exact_address":knownprior,
    "2025_paper_reported_function":TABLE1.get(addr),
    "prior_art_status":status,
    "first_discovery_claim_allowed":False,
    "current_ROM_exact_operation_semantics_proven":False})
 return {"schema":"ROM001_P0B_2025_PRIOR_ART_DEDUP_V1",
  "original_issue_id":"ESP32C3-ROM-001",
  "ROM_source_sha256":ROM_SHA,
  "paper":{"title":"Reverse Engineering the ESP32-C3 Wi-Fi Drivers for Static Worst-Case Analysis of Intermittently-Powered Systems",
    "year":2025,"authors":"Mudraje et al.","DOI":PAPER_DOI,"url":PAPER_URL,
    "table":"Table 1","pdf_page_index":3,
    "source_type":"PEER_REVIEWED_REVERSE_ENGINEERING"},
  "TRM_reserved_addresses":14,
  "TRM_reserved_already_in_2025_study":len(known),
  "TRM_reserved_not_in_2025_study":len(reserved-known),
  "published_prior_addresses":[hex(x) for x in sorted(known)],
  "remaining_without_match_in_this_study":[hex(x) for x in sorted(reserved-known)],
  "all_address_evidence":detailed,
  "novel_semantics_confirmed":0,
  "limitations":["No match in this single study does not prove world-first discovery.",
     "The paper's deduced purpose is prior work, not an independently repeated silicon test for this ROM.",
     "TRM Reserved does not imply an undocumented new hardware capability."]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--trm",type=pathlib.Path,required=True)
 p.add_argument("--out",type=pathlib.Path,required=True)
 a=p.parse_args();r=compare(json.loads(a.trm.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_P0B_PRIOR_2025",json.dumps({k:r[k] for k in
  ("TRM_reserved_addresses","TRM_reserved_already_in_2025_study",
   "TRM_reserved_not_in_2025_study","published_prior_addresses",
   "novel_semantics_confirmed")},sort_keys=True))
if __name__=="__main__":main()
