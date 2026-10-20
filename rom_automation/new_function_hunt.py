#!/usr/bin/env python3
"""ROM-001 exploratory census beyond the register-access-selected original 88.

Finds (1) ELF STT_FUNC names absent from selected dated prior catalogs and
(2) direct machine-byte control targets in executable but STT_FUNC-uncovered
ranges. Neither is proof of previously unknown executable behavior. This
script never changes the independent-semantic approval gate.
"""
import argparse,bisect,collections,hashlib,io,json,pathlib,re,sys,tarfile,zipfile
from elftools.elf.elffile import ELFFile
from decision_gate import REVS,MACHINE_SHA,ROM_SHA,require,sha

PUBLIC=pathlib.Path(__file__).resolve().parents[1]/"research"/"esp32c3_rom_public"
sys.path.insert(0,str(PUBLIC))
from prior_catalog_name_audit import CATALOGS,fetch,contains_name
from rom_opcode import jal,compressed_jump,auipc_jalr

def name_inventory(text,source):
 if source["repo"]=="psifertex/bnesp32":
  funcs=json.loads(text)["functions"]
  require(isinstance(funcs,dict),"BAD_PRIOR_SYMBOL_JSON")
  return {x for x in funcs.values() if isinstance(x,str) and x}
 if source["repo"]=="eggfly/esp32c3_baremetal":
  return set(re.findall(r"(?m)^[0-9a-fA-F]{8}\s+\w\s+(\w+)\s*$",text))
 if source["repo"]=="motokultivator/ll-applications":
  return set(re.findall(r"(?m)^\s*([A-Za-z_]\w*)\s*=",text))
 raise RuntimeError("UNKNOWN_CATALOG_PARSER")

def get_catalogs():
 catalog={};meta={}
 for src in CATALOGS:
  content,receipt=fetch(src)
  names=name_inventory(content,src)
  # Catch regex/corpus parser drift against the legacy exact name checker.
  for probe in ("r_lld_scan_start_eco","r_lld_cca_set_thresh",
                "rom_tsens_code_read","spi_slave_rom_init_hw"):
   require((probe in names)==contains_name(content,probe,src),
           "CATALOG_PARSER_MISMATCH:"+src["name"]+":"+probe)
  require(bool(names),"EMPTY_PRIOR_CATALOG")
  catalog[src["name"]]=names
  meta[src["name"]]={**receipt,"name_count":len(names)}
 return catalog,meta

def merged(pairs):
 out=[]
 for a,b in sorted(pairs):
  require(a<b,"INVALID_ELF_FUNCTION_RANGE")
  if out and a<=out[-1][1]:out[-1]=(out[-1][0],max(out[-1][1],b))
  else:out.append((a,b))
 return out

def lookup(intervals,addr):
 i=bisect.bisect_right([a for a,b in intervals],addr)-1
 return i>=0 and addr<intervals[i][1]

def clipped_coverage(exec_ranges,func_ranges):
 intersections=[]
 for a,b in func_ranges:
  for p,q in exec_ranges:
   lo,hi=max(a,p),min(b,q)
   if lo<hi:intersections.append((lo,hi))
 return merged(intersections)

def decode_elf(blob,rev,original,catalogs,max_witness=8):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 elf=ELFFile(io.BytesIO(blob))
 require(elf["e_machine"]=="EM_RISCV" and elf.elfclass==32,"NOT_RV32_ELF")
 require(elf.little_endian,"NOT_LITTLE_ENDIAN_ROM")
 sections=[s for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS"
           and int(s["sh_flags"])&4 and int(s["sh_size"])>0]
 require(bool(sections),"NO_EXECUTABLE_SECTIONS")
 exec_ranges=merged([(int(s["sh_addr"]),int(s["sh_addr"])+int(s["sh_size"])) for s in sections])
 funcs=[];names=collections.defaultdict(list);label_ranges=[]
 for symtab in elf.iter_sections():
  if symtab["sh_type"]!="SHT_SYMTAB":continue
  for symbol in symtab.iter_symbols():
   name=symbol.name
   if not name or symbol["st_info"]["type"]!="STT_FUNC":continue
   addr=int(symbol["st_value"]);size=int(symbol["st_size"])
   if size<=0:continue
   if not lookup(exec_ranges,addr):continue
   if addr+size>max(b for a,b in exec_ranges):
    raise RuntimeError("ELF_FUNCTION_OVERFLOW")
   funcs.append((addr,addr+size));names[name].append({"address":hex(addr),"size":size})
   label_ranges.append((addr,addr+size,name))
 require(len(names)>88,"SUSPICIOUS_INCOMPLETE_FUNCTION_SYMBOL_TABLE")
 covered=clipped_coverage(exec_ranges,funcs)
 starts=[a for a,b in covered]
 def is_covered(addr):
  i=bisect.bisect_right(starts,addr)-1
  return i>=0 and addr<covered[i][1]
 label_ranges.sort()
 label_starts=[x[0] for x in label_ranges]
 def nearest_owner(addr):
  i=bisect.bisect_right(label_starts,addr)-1
  if i>=0 and addr<label_ranges[i][1]:return label_ranges[i][2]
  return None
 decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 decoder.skipdata=True
 seen_code=set();all_target_hits=collections.defaultdict(list)
 all_direct=collections.Counter();unknown_indirect=0;undecodable=0
 section_items=[]
 for s in sections:
  data=s.data();base=int(s["sh_addr"])
  insns=list(decoder.disasm(data,base))
  require(sum(x.size for x in insns)==len(data),"DISASSEMBLER_LOST_BYTES")
  section_items.append((base,base+len(data),data,insns))
  good={i.address:i for i in insns if i.mnemonic!=".byte"}
  seen_code.update(good)
  for inst in insns:
   if inst.mnemonic==".byte":
    undecodable+=inst.size;continue
   if inst.mnemonic in ("jalr","c.jr","c.jalr","jr"):unknown_indirect+=1
   raw=bytes(inst.bytes)
   target=jal(raw,inst.address)
   kind="JAL_RAW" if target is not None else None
   if target is None:
    target=compressed_jump(raw,inst.address)
    if target is not None:kind="COMPRESSED_JUMP_RAW"
   if target is None and inst.mnemonic=="auipc":
    follow=good.get(inst.address+4)
    if follow is not None and follow.size==4:
     target=auipc_jalr(raw+bytes(follow.bytes),inst.address)
     if target is not None:kind="AUIPC_JALR_RAW"
   if target is None:continue
   all_direct[kind]+=1
   if not any(a<=target<b for a,b in exec_ranges):continue
   if is_covered(target):continue
   rd=(int.from_bytes(raw,"little")>>7)&31 if kind=="JAL_RAW" else (
     (int.from_bytes(raw,"little")>>12)&1 if kind=="COMPRESSED_JUMP_RAW" else 1)
   link=bool(rd)
   all_target_hits[target].append({
    "source":hex(inst.address),"source_function":nearest_owner(inst.address),
    "source_in_STT_FUNC_size_coverage":is_covered(inst.address),
    "opcode":inst.mnemonic,"kind":kind,"link_instruction":link,
    "source_raw_bytes":raw.hex()})
 anonymous=[]
 for target,hits in sorted(all_target_hits.items()):
  landing=None
  for a,b,data,insns in section_items:
   if a<=target<b:
    indexed={ins.address:ins for ins in insns if ins.mnemonic!=".byte"}
    cursor=target;contiguous=0;sample=[]
    for _ in range(6):
     ins=indexed.get(cursor)
     if ins is None:break
     if ins.mnemonic in ("unimp","c.unimp","c.ebreak","ebreak","ecall"):break
     sample.append({"address":hex(ins.address),"mnemonic":ins.mnemonic,"bytes":bytes(ins.bytes).hex()})
     contiguous+=1;cursor+=ins.size
    landing={"decoded_contiguous_instructions":contiguous,
      "first_instruction":sample[0] if sample else None,"sample":sample}
    break
  require(landing is not None,"GAP_TARGET_NOT_IN_SECTION")
  unique_sources={x["source"] for x in hits}
  named_callers={x["source_function"] for x in hits if x["source_function"]}
  link_count=sum(bool(x["link_instruction"]) for x in hits)
  # Fail-closed anti-data gate. ESP32-C3 implements RV32IMC, not F/D.
  unsupported_f={"c.fsw","c.flw","c.fld","c.fsd","flw","fsw","fld","fsd"}
  contains_unsupported_f=any(x["mnemonic"] in unsupported_f
                              for x in landing["sample"][:3])
  known_code_source=any(x["source_in_STT_FUNC_size_coverage"] for x in hits)
  evidence_level=("ENTRY_LIKE_UNVERIFIED" if landing["decoded_contiguous_instructions"]>=2
                    and link_count and known_code_source and not contains_unsupported_f
                    else "UNRESOLVED_RAW_LINEAR_DECODE")
  rejection_reasons=[]
  if not known_code_source:rejection_reasons.append("NO_NAMED_FUNCTION_SOURCE")
  if contains_unsupported_f:rejection_reasons.append("UNSUPPORTED_RV32IMC_F_EXTENSION")
  if not link_count:rejection_reasons.append("NO_CALL_LINK_BIT")
  if landing["decoded_contiguous_instructions"]<2:rejection_reasons.append("INSUFFICIENT_VALID_LANDING_BYTES")
  anonymous.append({
   "revision":rev,"entry":hex(target),"evidence_level":evidence_level,
   "direct_incoming_instructions":len(unique_sources),
   "linked_call_instructions":link_count,
   "known_caller_functions":sorted(named_callers),
   "source_in_STT_FUNC_size_coverage":known_code_source,
   "landing_has_unsupported_F_extension":contains_unsupported_f,
   "rejection_reasons":rejection_reasons,
   "landing":landing,"incoming_witnesses":hits[:max_witness],
   "is_symbol_size_gap":True,"function_boundary_verified":False,
   "novel_function_verified":False,"priority":(
    100*int(evidence_level=="ENTRY_LIKE_UNVERIFIED")
     +10*min(5,len(unique_sources))
     +5*len(named_callers))
  })
 anonymous.sort(key=lambda x:(-x["priority"],int(x["entry"],16)))
 unmatched=[]
 for name,entries in names.items():
  sources=[tag for tag,known in catalogs.items() if name in known]
  if name in original:continue
  if not sources:
   unmatched.append({"name":name,"revision":rev,"instances":entries,
       "source":"OFFICIAL_ROM_ELF_STT_FUNC","selected_prior_catalog_matches":[],
       "status":"NOT_FOUND_IN_THREE_SELECTED_CATALOGS",
       "novel_api_proven":False})
 unmatched.sort(key=lambda x:x["name"])
 total=sum(b-a for a,b in exec_ranges)
 covered_bytes=sum(b-a for a,b in covered)
 require(total>=covered_bytes,"FUNCTION_COVERAGE_EXCEEDS_EXECUTABLE")
 return {
  "revision":rev,"elf_sha256":hashlib.sha256(blob).hexdigest(),
  "executable_bytes":total,"symbol_size_covered_bytes":covered_bytes,
  "symbol_size_gap_bytes":total-covered_bytes,
  "all_named_ELF_functions":len(names),
  "original_88_names_present":len(set(names)&original),
  "names_covered_by_selected_prior_catalogs":sum(any(name in known for known in catalogs.values()) for name in names),
  "not_in_three_selected_prior_catalogs_count":len(unmatched),
  "unmatched_named_candidates":unmatched,
  "direct_instruction_counts":dict(all_direct),
  "indirect_control_instructions_unresolved":unknown_indirect,
  "undecoded_linear_bytes":undecodable,
  "direct_targets_in_symbol_size_gaps_count":len(anonymous),
  "gap_target_entry_like_count":sum(x["evidence_level"]=="ENTRY_LIKE_UNVERIFIED" for x in anonymous),
  "gap_targets_without_symbol_covered_sources":sum(not x["source_in_STT_FUNC_size_coverage"] for x in anonymous),
  "gap_targets_with_unsupported_F_in_first_three":sum(x["landing_has_unsupported_F_extension"] for x in anonymous),
  "gap_target_candidates":anonymous,
  "limits":["ELF names and direct targets are not independently proven novel.",
   "Catalog not-found means not found in only three dated catalogs, not unpublished worldwide.",
   "A direct branch into symbol-uncovered bytes might be a local label, vector stub or embedded data.",
   "Linear instruction decoding may interpret noncode bytes as instructions.",
   "Indirect targets, address-table entries, alternate-entry roots and full CFG remain unresolved."]}

def is_compiler_local_name(name):
 # Do not interpret GCC check_condCOUNTER.<number> local labels as new functions.
 return bool(re.fullmatch(r"check_condCOUNTER\.\d+",name))

def evaluate(rom_tar,machine_zip,catalogs,meta):
 require(sha(rom_tar)==ROM_SHA,"OFFICIAL_ELF_ARCHIVE_SHA")
 require(sha(machine_zip)==MACHINE_SHA,"CANONICAL_88_SOURCE_SHA")
 with zipfile.ZipFile(machine_zip) as m:
  doc=json.loads(m.read("output/internal_function_candidates.json"))
 names={c["elf_function_name"] for c in doc["all_candidates"]}
 require(doc["candidate_count"]==len(names)==88,"ORIGINAL_88_INVENTORY_MISMATCH")
 per={}
 with tarfile.open(rom_tar,mode="r:gz") as tar:
  for rev in REVS:
   members=[x for x in tar.getmembers() if x.isfile()
            and pathlib.PurePosixPath(x.name).name==rev]
   require(len(members)==1,"ELF_MISSING_OR_DUPLICATE:"+rev)
   per[rev]=decode_elf(tar.extractfile(members[0]).read(),rev,names,catalogs)
 all_missing=collections.defaultdict(list)
 for rev,item in per.items():
  for v in item["unmatched_named_candidates"]:
   all_missing[v["name"]].append({"revision":rev,"address":v["instances"][0]["address"]})
 result={"schema":"ESP32C3_ROM_NEW_FUNCTION_EXPLORATION_V1",
  "original_issue_id":"ESP32C3-ROM-001",
  "official_elf_source_sha256":ROM_SHA,
  "original_88_source_sha256":MACHINE_SHA,
  "original_88_candidate_names_count":len(names),
  "selected_prior_catalogs":meta,
  "unique_ELF_names_not_in_selected_prior":len(all_missing),
  "compiler_local_labels_excluded_from_feature_queue":sum(is_compiler_local_name(name) for name in all_missing),
  "named_candidates_for_prior_art_followup":sum(not is_compiler_local_name(name) for name in all_missing),
  "all_missing_names":dict(sorted(all_missing.items())),
  "revisions":per,
  "novel_function_proven":0,"independent_semantic_review_proven":0,
  "hardware_silicon_verified":0,"new_usable_capability_proven":0,
  "new_discovery_exploration_allowed":True,
  "certification_gate_unchanged":True,
  "status":"EXPLORATORY_NOT_NOVELTY_CERTIFICATION",
  "next_actions":[
   "For unmatched named functions independently search broader published source, symbol aliases, source provenance and historical revisions.",
   "For symbol-gap direct targets resolve whether true callee entry, interior branch, table target, or decoder false-positive.",
   "Review functions with no direct edges using referenced data tables and additional image roots.",
   "Only certify behavior with independent real-silicon evidence and prior-art counterexamples."
  ]}
 return result

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--rom",required=True,type=pathlib.Path)
 p.add_argument("--machine",required=True,type=pathlib.Path)
 p.add_argument("--out",required=True,type=pathlib.Path)
 a=p.parse_args()
 catalogs,meta=get_catalogs()
 result=evaluate(a.rom,a.machine,catalogs,meta)
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print("ROM_NEW_FUNCTION_HUNT",json.dumps({
  "known_original_88":result["original_88_candidate_names_count"],
  "named_absent_from_three_catalogs":result["unique_ELF_names_not_in_selected_prior"],
  "compiler_generated_names":result["compiler_local_labels_excluded_from_feature_queue"],
  "needs_broader_prior_art":result["named_candidates_for_prior_art_followup"],
  "named_by_revision":{r:d["all_named_ELF_functions"] for r,d in result["revisions"].items()},
  "symbol_gap_targets_by_revision":{r:d["direct_targets_in_symbol_size_gaps_count"] for r,d in result["revisions"].items()},
  "entry_like_by_revision":{r:d["gap_target_entry_like_count"] for r,d in result["revisions"].items()},
  "certified_new_functions":0
 },sort_keys=True))
if __name__=="__main__":main()
