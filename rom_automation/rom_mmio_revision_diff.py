#!/usr/bin/env python3
"""ROM-001 P0-B rev-differential exact machine-access triage for all ROM functions.

Inspired by hardware-aware MMIO models in HD-FUZZ 2024/ES-FUZZ 2024,
but produces STATIC evidence only. Known peripheral bases are not the same
as documented registers. Any unsupported RISC-V F instructions fail closed.
"""
import argparse,bisect,collections,hashlib,io,json,pathlib,re,tarfile
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,REVS,require,sha
from rom_fast_graph import make_symbol_index,INVALID_F
from rom_mmio import scan_adjacent
from rom_opcode import csr_number

ROOT=pathlib.Path(__file__).resolve().parents[1]
REG_BASE=ROOT/"research"/"esp32c3_rom_public"/"official_reg_base.h"
def bases(content):
 vals=re.findall(r"(?m)^#define\s+(DR_REG_\w+_BASE)\s+(0x[0-9a-fA-F]+)",content)
 require(len(vals)>30,"INCOMPLETE_PERIPHERAL_BASE_HEADER")
 return {int(v,16):name for name,v in vals}

def scan_revision(blob,rev,graph,baseline):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 elf=ELFFile(io.BytesIO(blob))
 sections,bounds,pairs,owners,entries,_=make_symbol_index(elf)
 dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC);dec.skipdata=True
 per_func={}
 for section in sections:
  base=int(section["sh_addr"]);data=section.data()
  instructions=list(dec.disasm(data,base))
  assert sum(x.size for x in instructions)==len(data)
  starts=[i.address for i in instructions]
  for a,b in pairs:
   if not(base<=a<b<=base+len(data)):continue
   lo=bisect.bisect_left(starts,a);hi=bisect.bisect_left(starts,b)
   seq=instructions[lo:hi];key=f"{a:08x}:{b-a:x}"
   if not seq or seq[0].address!=a or seq[-1].address+seq[-1].size!=b:
    per_func[key]={"status":"UNALIGNED_OR_PARTIAL","mmio":[],"csrs":[]}
    continue
   if any(x.mnemonic in INVALID_F or x.mnemonic==".byte" for x in seq):
    per_func[key]={"status":"UNSUPPORTED_OR_NONCODE","mmio":[],"csrs":[]}
    continue
   mmio=scan_adjacent([(i.address,bytes(i.bytes)) for i in seq])
   csrs=[{"pc":hex(i.address),"csr":hex(x),"bytes":bytes(i.bytes).hex()}
    for i in seq if (x:=csr_number(i.bytes)) is not None]
   # No benign assumption: raw LUI+access patterns only and vendor BASE addresses.
   for x in mmio:
    addr=int(x["address"],16)
    nearby=[(hex(p),name) for p,name in baseline.items() if p<=addr<p+0x1000]
    x["matching_vendor_peripheral_bases"]=nearby
    x["exact_register_defined_by_vendor"]=None
    x["silicon_effect_proven"]=False
   per_func[key]={"status":"STATIC_OPCODE_PATTERNS_ONLY","aliases":entries[key]["aliases"],
     "mmio":mmio,"csrs":csrs}
 require(len(per_func)==len(entries),"MISSED_FUNCTION_EVIDENCE")
 return per_func

def evaluate(rom,graph):
 require(sha(rom)==ROM_SHA,"PINNED_ROM_SHA")
 require(graph["schema"]=="ESP32C3_ALL_ROM_FAST_GRAPH_V1" and graph["rom_source_sha256"]==ROM_SHA,"GRAPH_SOURCE")
 baseline=bases(REG_BASE.read_text())
 observed={}
 with tarfile.open(rom,"r:gz") as t:
  for rev in REVS:
   a=[m for m in t.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   require(len(a)==1,"MISSING_ELF")
   blob=t.extractfile(a[0]).read()
   require(hashlib.sha256(blob).hexdigest()==graph["all_revisions"][rev]["elf_sha256"],"ELF_HASH")
   observed[rev]=scan_revision(blob,rev,graph,baseline)
 # Group by name, across versions. Alias collisions must be retained and marked.
 byname=collections.defaultdict(lambda:collections.defaultdict(list))
 for rev,funcs in observed.items():
  for key,body in funcs.items():
   if body["status"]!="STATIC_OPCODE_PATTERNS_ONLY":continue
   addr_set=sorted({x["address"] for x in body["mmio"]})
   csr_set=sorted({x["csr"] for x in body["csrs"]})
   for name in body["aliases"]:
    byname[name][rev].append({"function_id":key,
      "mmio_addresses":addr_set,"csr_numbers":csr_set,
      "machine_mmio_sites":body["mmio"],
      "machine_csr_sites":body["csrs"]})
 differences=[]
 for name,revs in byname.items():
  if len(revs)<2:continue
  if any(len(xs)!=1 for xs in revs.values()):continue # ambiguous alias/overlap
  sig={rev:(set(v[0]["mmio_addresses"]),set(v[0]["csr_numbers"])) for rev,v in revs.items()}
  if len({(tuple(sorted(a)),tuple(sorted(b))) for a,b in sig.values()})==1:continue
  additions={rev:{"only_mmio_vs_other_revisions":sorted(a-set.union(*(q[0] for n,q in sig.items() if n!=rev))),
    "only_csr_vs_other_revisions":sorted(b-set.union(*(q[1] for n,q in sig.items() if n!=rev)))}
   for rev,(a,b) in sig.items() }
  if not any(a["only_mmio_vs_other_revisions"] or a["only_csr_vs_other_revisions"] for a in additions.values()):
   continue
  differences.append({"function_name":name,"present_in_revisions":sorted(revs),
    "unique_accesses_by_revision":additions,
    "all_static_evidence":dict(revs),
    "is_undocumented":None,"new_hardware_capability_proven":False,
    "priority":sum(len(x["only_mmio_vs_other_revisions"])*5+
                   len(x["only_csr_vs_other_revisions"])*10
                   for x in additions.values())})
 differences.sort(key=lambda x:(-x["priority"],x["function_name"]))
 return {"schema":"ROM001_P0B_MACHINE_MMIO_REV_DIFF_V1",
  "original_issue_id":"ESP32C3-ROM-001","ROM_SHA256":ROM_SHA,
  "vendor_baseline":"research/esp32c3_rom_public/official_reg_base.h",
  "peripheral_bases_count":len(baseline),
  "revisions":{rev:{"function_bodies_analyzed":len(fs),
    "pattern_effect_sites":sum(len(b["mmio"]) for b in fs.values()),
    "CSR_access_sites":sum(len(b["csrs"]) for b in fs.values()),
    "noncode_or_partial_functions":sum(b["status"]!="STATIC_OPCODE_PATTERNS_ONLY" for b in fs.values())}
    for rev,fs in observed.items()},
  "same_named_function_differential_candidates":len(differences),
  "top_twenty":differences[:20],
  "all_differentials":differences,
  "new_unexplained_behavior_certified":0,
  "MMIO_runtime_observed":False,
  "limitations":["This is a revision-differential STATIC OPCODE PATTERN comparison, not unexplained behavior certification.",
   "Vendor base macros do not provide exact register map or expected semantics.",
   "Changed compiler code can produce differing register accesses without any new hardware feature.",
   "Only adjacent LUI[/ADDI]+LOAD/STORE and CSR literals analyzed; no computed addresses or transitive call effects.",
   "Prior-art independent exact field-level assessment and matched-chip non-destructive confirmation required."]}

def main():
 p=argparse.ArgumentParser()
 for x in ("rom","graph","out"):p.add_argument("--"+x,required=True,type=pathlib.Path)
 a=p.parse_args();r=evaluate(a.rom,json.loads(a.graph.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(r,sort_keys=True,separators=(",",":"))+"\n")
 print("ROM_P0B_REVISION_MMIO",json.dumps({"pattern_differences":r["same_named_function_differential_candidates"],
  "by_rev":r["revisions"],"certified_new":0},sort_keys=True))
if __name__=="__main__":main()
