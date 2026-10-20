#!/usr/bin/env python3
"""ROM001 P0B additional prior art, cross-chip provenance never equals C3 identity.

Pinned immutable GitHub blob SHA-1 + pinned git commits. Two independent
third-party repositories are used solely to identify prior *address use*:
one ESP32-S3 PHY extraction, one radio bring-up notebook, and one\nunverified C3-labelled captured register-value series. Both
sources are not authoritative C3 silicon function evidence.
"""
import argparse,hashlib,json,pathlib,re,urllib.request
from decision_gate import ROM_SHA,require
SOURCES=[
 {"id":"S3_PHY_LIBRARY_MAP","repo":"jochenhammes/esp32-sdr-trx",
  "ref":"e1aebbf2ef508c7199a9b6c6c277b57fe0b51aa9",
  "path":"docs/research/REGISTER-MAP.md",
  "blob_sha1":"c9d978e3f793725b24f4861be69fd59653692d0d",
  "target_chip":"ESP32-S3","strength":"OTHER_CHIP_SAME_ADDRESS_LITERAL_NOT_C3_SEMANTICS"},
 {"id":"FLINTOS_RADIO_PLAN","repo":"cooljackal/flintos",
  "ref":"3a516d2720b7883ce7a0996d9e915ea8397dcdb2",
  "path":"doc/plan-radio.md",
  "blob_sha1":"dd51c71856495d43555bd03d555be29fa121b0cf",
  "target_chip":"UNCONFIRMED_FOR_THE_EXACT_LINE",
  "strength":"THIRD_PARTY_RADIO_PLAN_EXACT_LITERAL_NOT_INDEPENDENT_HARDWARE_PROOF"},
 {"id":"THIRD_PARTY_C3_RADIO_CAPTURE","repo":"w1ne/labwired-core",
  "ref":"f380910758c815b887cebbb5a87f7eaceb5c9cdb",
  "path":"scripts/hw-oracle/captures/esp32c3/wifi-radio-20260611T214340Z/radio_windows.json",
  "blob_sha1":"84c5df4c4d467d71c84225d626eda46bd84c4c1f",
  "target_chip":"ESP32-C3_CLAIMED_BY_THIRD_PARTY_PATH",
  "strength":"THIRD_PARTY_CLAIMED_DEVICE_CAPTURE_NO_INDEPENDENT_SENSOR_ATTESTATION"},
 {"id":"BLE_C3_EMULATOR_ORACLE","repo":"mikroverk/esp32sim",
  "ref":"63670bb128cf0a0c019a2009be62cfe56378ce0f",
  "path":"docs/evidence/ble-c3-advertising/hardware/compare.py",
  "blob_sha1":"f8e47831fcd58a52e223f7d695fb9d826c0a4b5f",
  "target_chip":"ESP32-C3_CLAIMED_IN_BLE_HARDWARE_COMPARISON",
  "strength":"THIRD_PARTY_BLE_CONTROLLER_STATE_COMPARE_NOT_BIT_LEVEL_REGISTER_SEMANTICS"}
]
def git_blob(data):
 return hashlib.sha1(b"blob "+str(len(data)).encode()+bytes([0])+data).hexdigest()
def retrieve(source):
 url="https://raw.githubusercontent.com/"+source["repo"]+"/"+source["ref"]+"/"+source["path"]
 with urllib.request.urlopen(url,timeout=35) as fd:data=fd.read()
 require(git_blob(data)==source["blob_sha1"],"THIRD_PARTY_SOURCE_BLOB_DRIFT:"+source["id"])
 return data.decode("utf-8"),url,hashlib.sha256(data).hexdigest()
def inspect(report,texts):
 require(report.get("schema")=="ROM001_P0B_2025_PRIOR_ART_DEDUP_V1" and
   report.get("ROM_source_sha256")==ROM_SHA,"PRIOR_TRM_EVIDENCE_DRIFT")
 pending=[int(x,16) for x in report["remaining_without_match_in_this_study"]]
 require(len(pending)==11,"PRIOR_PENDING11_DRIFT")
 corpus={}
 for src in SOURCES:
  raw,url,digest=texts[src["id"]]
  corpus[src["id"]]={"url":url,"git_ref":src["ref"],"git_blob_sha1":src["blob_sha1"],
    "source_sha256":digest,"target_chip":src["target_chip"],
    "evidence_strength":src["strength"],"addresses":{}}
  lines=raw.splitlines()
  for addr in pending:
   needle=f"0x{addr:08x}"
   found=[{"line":i+1,"excerpt":line[:400]} for i,line in enumerate(lines)
          if re.search(r"(?i)(?<![a-f0-9])"+re.escape(needle)+r"(?![a-f0-9])",line)]
   if found:corpus[src["id"]]["addresses"][hex(addr)]=found[:12]
 rows=[]
 for addr in pending:
  hits=[{"corpus":key,"chip":SOURCES[i]["target_chip"],
    "strength":SOURCES[i]["strength"],"evidence":corpus[key]["addresses"][hex(addr)]}
   for i,key in enumerate([s["id"] for s in SOURCES])
   if hex(addr) in corpus[key]["addresses"]]
  rows.append({"address":hex(addr),"source_hits":hits,
    "same_chip_exact_register_function_proven":False,
    "published_worldfirst_novelty_claim_approved":False,
    "state":"OTHER_SOURCE_ADDRESS_MATCH_NOT_CHIP_VERIFIED" if hits else
            "NO_EXACT_MATCH_IN_THESE_FOUR_PINNED_SOURCES_NOT_WORLDWIDE_ABSENT"})
 return {"schema":"ROM001_P0B_11_CROSS_CORPUS_ADDRESS_EVIDENCE_V1",
   "original_issue_id":"ESP32C3-ROM-001","source_ROM_sha256":ROM_SHA,
   "documents":corpus,"examined_remaining":11,
   "rows":rows,"other_source_exact_address_matches":sum(bool(x["source_hits"]) for x in rows),
   "remaining_no_exact_matches_in_four_sources":sum(not x["source_hits"] for x in rows),
   "independently_verified_C3_new_semantics":0,
   "limits":["ESP32-S3 PHY address coincidence is NOT ESP32-C3 register function equivalence.",
     "Third-party C3-labelled captures have no independent board-attestation or measurement replay; some radio plans may be speculative and are not proof of hardware-level behavior.",
     "Textual equality without register read/write trace or same-chip source is only search prioritization.",
     "A missing exact address in four sources does not imply undocumented worldwide."]}

def evaluate(prior):
 corpus={}
 for src in SOURCES:
  text,url,digest=retrieve(src)
  corpus[src["id"]]=(text,url,digest)
 return inspect(prior,corpus)

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--prior",type=pathlib.Path,required=True)
 p.add_argument("--out",type=pathlib.Path,required=True)
 a=p.parse_args()
 result=evaluate(json.loads(a.prior.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print("ROM_P0B_CROSSCHIP_11",json.dumps({
  "examined":result["examined_remaining"],"other_document_matches":result["other_source_exact_address_matches"],
  "no_match_in_four_sources":result["remaining_no_exact_matches_in_four_sources"],
  "independent_C3_new_semantics":result["independently_verified_C3_new_semantics"]},sort_keys=True))
if __name__=="__main__":main()
