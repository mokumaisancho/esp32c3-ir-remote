#!/usr/bin/env python3
"""Cross-check 46 IDF-linker-unmatched ROM names with dated independent catalogs.

A name appearing in a prior symbol catalog is evidence that the NAME is not
new. It is not evidence that the function's behavior was previously understood.
"""
import collections,csv,hashlib,json,pathlib,re,urllib.request
BASE=pathlib.Path(__file__).resolve().parent;OUT=BASE/"output"/"known_prior_catalogs";OUT.mkdir(parents=True,exist_ok=True)
CATALOGS=(
 {"name":"esp32c3_baremetal_2023","repo":"eggfly/esp32c3_baremetal",
  "commit":"6450b1d5d4c66407273301597a808bb76838653","date":"2023-12-20",
  "path":"ref/esp32c3_r3_rom.sym","git_blob_sha1":"e2ea3b05c82b1d92365ab78d68e89e7b7b37eb1f"},
 {"name":"ll_applications_2024","repo":"motokultivator/ll-applications",
  "commit":"6bfd4c96e1d3e917e85bdb740432c92cb7167125","date":"2024-02-10",
  "path":"esp32c3.ld","git_blob_sha1":"b618f3d70b5e55497460147ce8fe520cd2f6d597"},
 {"name":"bnesp32_2026","repo":"psifertex/bnesp32",
  "commit":"bb3baa057a440e1d4c13f7045fee1ccbe04e74b3","date":"2026-02-21",
  "path":"esp32c3_rom_symbols.json","git_blob_sha1":"5944b9ac153c3647c804dc3be8c95265ef58058e"})
def fetch(src):
 url="https://raw.githubusercontent.com/"+src["repo"]+"/"+src["commit"]+"/"+src["path"]
 data=urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"rom-prior-catalog/1"}),timeout=120).read()
 git=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
 if git!=src["git_blob_sha1"]:raise RuntimeError("SOURCE_BLOB_HASH_MISMATCH:"+src["repo"])
 return data.decode("utf-8"),{**src,"url":url,"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)}
def contains_name(content,name,src):
 if src["repo"]=="eggfly/esp32c3_baremetal":
  return bool(re.search(r"(?m)^[0-9a-fA-F]{8}\s+\w\s+"+re.escape(name)+r"\s*$",content))
 if src["repo"]=="psifertex/bnesp32":
  values=json.loads(content)["functions"].values()
  return name in values
 return bool(re.search(r"(?m)^\s*"+re.escape(name)+r"\s*=",content))
def main():
 with (BASE/"output"/"idf_known"/"candidates_reclassified.csv").open(newline="") as f:
  allrows=list(csv.DictReader(f))
 unknown=[x["name"] for x in allrows if x["classification"]=="UNRESOLVED_IN_SELECTED_IDF_SOURCES"]
 if len(allrows)!=88 or len(unknown)!=46:raise RuntimeError("INVENTORY_CHANGED")
 sources=[]
 matches=collections.defaultdict(list)
 for src in CATALOGS:
  content,meta=fetch(src);sources.append(meta)
  for name in unknown:
   if contains_name(content,name,src):matches[name].append(src["name"])
 commented_official="r_lld_scan_start_eco"
 if matches[commented_official]:raise RuntimeError("OFFICIAL_DISABLED_ENTRY_UNEXPECTEDLY_IN_EXTERNAL_CATALOG")
 record=json.loads((BASE/"output"/"disabled_entries"/"rev101_disabled_ble_entry.json").read_text())
 if record["rev101_target_function"]!=commented_official:
  raise RuntimeError("OFFICIAL_DISABLED_ENTRY_EVIDENCE_UNAVAILABLE")
 rows=[]
 for name in unknown:
  m=matches[name]
  label=("KNOWN_OFFICIALLY_COMMENTED_NONEXPORTED" if name==commented_official else
         "PRIOR_PUBLIC_SYMBOL_NAME" if m else "NOT_FOUND_IN_SELECTED_PRIOR")
  rows.append({"name":name,"dated_catalog_evidence":sorted(m),"additional_official_evidence":
    "COMMENTED_OUT_ECO7_LD" if name==commented_official else None,"name_classification":label,
    "functional_novelty":"NOT_CERTIFIED","silicon_execution":"NOT_MEASURED"})
 count_prior=sum(bool(x["dated_catalog_evidence"]) for x in rows)
 if count_prior!=45:raise RuntimeError("DATE_PINNED_CATALOG_MATCHES_UNEXPECTED:"+str(count_prior))
 if sum(x["name_classification"]=="NOT_FOUND_IN_SELECTED_PRIOR" for x in rows):
  raise RuntimeError("UNACCOUNTED_NAMED_FUNCTION")
 report={"schema":"ROM_PRIOR_PUBLISHED_NAME_AUDIT_V1","original_issue_id":"ESP32C3-ROM-001",
  "known_linker_name_count":42,"linker_unmatched_original_names":46,
  "dated_external_catalog_name_matches":count_prior,
  "additional_official_disabled_linker_mentions":1,
  "all_88_name_mentions_covered":True,"sources":sources,"candidate_rows":rows,
  "caution":"Previously published symbol NAMES do not certify prior behavioral descriptions or supported external API.",
  "novel_function_semantics_certified":0}
 (OUT/"prior_catalog_name_match.json").write_text(json.dumps(report,indent=2)+"\n")
 print("ROM_PRIOR_CATALOG_AUDIT",json.dumps({k:v for k,v in report.items() if k!="candidate_rows"},sort_keys=True))
if __name__=="__main__":main()
