#!/usr/bin/env python3
"""ROM-001 R3: consistency/falsification gate across previously SHA-pinned ROM scans.

This does not generate a NEW dynamic trace or establish novel callable APIs.
It checks the immutable 3-revision artifact bundle for mutually consistent
rooted boot-strap gap CFG and multiple negative entrypoint search approaches.
"""
import argparse,hashlib,json,pathlib,zipfile

ARTIFACT_SHA256="685cd51f50fddd43ba2aa94bcdee778a9ebd4850d9efee96d573a4df94bee27a"
ROM_SHA256="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
EVIDENCE={
 "bootstrap":"P0A_official_ROM_entry_jump_chains.json",
 "gap_direct":"P0A_RV32IMC_gap_branch_WIS.json",
 "indirect":"P0A_verified_static_indirect_into_gaps.json",
 "cfg":"P0A_CFG_local_register_provenance.json",
 "roots":"P0A_indirect_gap_roots.json",
 "vectors":"P0A_exact_32_vector_dispatch.json",
 "traps":"P0A_trap_vector_mtvec_mtvt_roots.json",
}
def require(cond,message):
 if not cond:raise ValueError(message)

def load_artifact(raw):
 digest=hashlib.sha256(raw).hexdigest()
 require(digest==ARTIFACT_SHA256,"ARTIFACT_HASH_DRIFT")
 import io
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  files=set(z.namelist())
  require(len(files)==len(z.namelist()),"DUPLICATE_ZIP_NAMES")
  require(set(EVIDENCE.values())<=files,"REQUIRED_EVIDENCE_MISSING")
  bundle={kind:json.loads(z.read(name)) for kind,name in EVIDENCE.items()}
 return bundle

def evaluate(bundle):
 require(set(bundle)==set(EVIDENCE),"EVIDENCE_SUBSET_DRIFT")
 for kind,ev in bundle.items():
  require(set(ev["revisions"])==set(REVS),"REVISION_CENSUS_DRIFT:"+kind)
  pointer=ev.get("ROM_SHA256",ev.get("ROM_sha256",
    ev.get("ROM_source_sha256",ev.get("ROM_archive_SHA256",
     ev.get("source_ROM_sha256",ev.get("source_ROM_sha256",ev.get("ROM_SHA256")))))))
  if pointer:require(pointer==ROM_SHA256,"ROM_PROVENANCE_DRIFT:"+kind)
  for k,v in ev.items():
   if (k in ("confirmed_new_functions","globally_proven_targets",
        "new_function_proven","verified_new_functions") and isinstance(v,int)):
    require(v==0,"NONZERO_CLAIM_REQUIRES_REVIEW:"+kind+":"+k)
 results=[];prefixes=[]
 for rev in REVS:
  b=bundle["bootstrap"]["revisions"][rev]
  roots=bundle["roots"]["revisions"][rev]
  strict=bundle["indirect"]["revisions"][rev]
  cfg=bundle["cfg"]["revisions"][rev]
  direct=bundle["gap_direct"]["revisions"][rev]
  vectors=bundle["vectors"]["revisions"][rev]
  traps=bundle["traps"]["revisions"][rev]
  chain=b["root_jump_chain"]
  require(len(chain)>=2 and chain[0]["pc"]=="0x40000000","MISSING_ELF_RESET_ROOT:"+rev)
  require(chain[0]["direct_trampoline_verified_from_ELF_image"] is True,"RESET_BRANCH_NOT_BYTE_PROVEN:"+rev)
  require(chain[1]["in_unclassified_exec_gap"] is True,"RESET_LANDING_NOT_GAP:"+rev)
  require(chain[0]["unconditional_direct_jump"]==chain[1]["pc"],"BOOT_LINK_DRIFT:"+rev)
  boot=b["bounded_entry_CFG"]
  edges=boot["direct_control_edges"];named=boot["named_function_target_boundaries"]
  require(len(named)==1 and any(e["destination"]==named[0] for e in edges),
          "BOOT_GAP_NEVER_JOINS_NAMED_FUNCTION:"+rev)
  require(boot["unresolved_terminators_count"]==0 and boot["hit_node_limit"] is False,
          "BOOT_TRAVERSAL_INCOMPLETE:"+rev)
  require(boot["visited_gap_instructions"]>=50,"BOOT_GAP_DISASSEMBLY_SHORT:"+rev)
  require(strict["resolved_static_JALR_into_gap"]==0 and len(strict["gap_edges"])==0,
          "DIRECT_JALR_NOVEL_CANDIDATES_REQUIRES_REVIEW:"+rev)
  require(not cfg["candidate_local_constant_edges"],
          "CFG_RESOLVED_NEW_CANDIDATE_REQUIRES_REVIEW:"+rev)
  require(direct["raw_gap_target_count"]==0,
          "NEW_DIRECT_GAP_TARGET_REQUIRES_REVIEW:"+rev)
  require(vectors["new_function_proven"]==0 and vectors["category_counts"]=={"DIRECT_INTO_NAMED":32},
          "VECTOR_NEW_ENTRY_REQUIRES_REVIEW:"+rev)
  require(traps["potential_trap_roots_in_unlabelled_ROM"]==0,
          "TRAP_NEW_ROOT_REQUIRES_REVIEW:"+rev)
  require(all(not r["novelty_proven"] for r in roots["roots"]),
          "ROOT_NOVELTY_REQUIRES_REVIEW:"+rev)
  ins=chain[1]["straightline_sample"]
  require(len(ins)>=10,"BOOT_PREAMBLE_INCOMPLETE:"+rev)
  prefixes.append(tuple((x["opcode"],x["raw_bytes"]) for x in ins[:10]))
  results.append({"revision":rev,"reset_root":"0x40000000",
   "first_direct_boot_target":chain[1]["pc"],
   "first_target_is_symbol_gap":True,
   "first_ten_bootstrap_instructions_match_other_revisions":True,
   "boot_gap_instructions_reachable_in_overapprox":boot["visited_gap_instructions"],
   "boot_cfg_exits_to_named_function":named[0],
   "other_indirect_JALR_seen":strict["indirect_nonreturn_jalr_in_named_functions"],
   "direct_branch_targets_into_symbol_gaps":direct["raw_gap_target_count"],
   "resolved_indirect_branch_into_symbol_gaps":strict["resolved_static_JALR_into_gap"],
   "new_API_entrypoint_proven":False,"physical_boot_observed":False})
 require(len(set(prefixes))==1,"BOOT_PREAMBLE_CROSS_REVISION_DRIFT")
 return {"schema":"ROM001_R3_ALL_THREE_REV_CROSS_ARTIFACT_CONSISTENCY_V1",
    "source_ROM_SHA256":ROM_SHA256,
    "source_artifact_ZIP_SHA256":ARTIFACT_SHA256,
    "revision_count":3,"findings":results,
    "true_symbolless_callable_API_confirmed":0,
    "same_bootstrap_first_ten_machine_instructions_all_three":True,
    "candidate_exclusion":"Known ELF reset boot path is not a proven externally callable new API",
    "R3_gate":"PASS_REPLAY_CROSSCHECK_BUT_FULL_INDEPENDENT_ENTRYPOINT_PROOF_OPEN",
    "limitations":[
      "Archived reports and their SHA are verified; the original ELF byte-analysis code was run in a distinct previous CI, not in this cross-check.",
      "An ELF entry's disassembled jump is proof of a static rooted edge, not that physical silicon booted it.",
      "Zero within explored direct, vector and bounded indirect methods is not exhaustive proof that no callable unnamed ROM routine exists.",
      "A zero new API count is not successful novelty discovery."
    ]}
def main():
 p=argparse.ArgumentParser();p.add_argument("--artifact-zip",required=True,type=pathlib.Path)
 p.add_argument("--output",required=True,type=pathlib.Path)
 a=p.parse_args();out=evaluate(load_artifact(a.artifact_zip.read_bytes()))
 a.output.parent.mkdir(parents=True,exist_ok=True)
 a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
 print("ROM001_R3_GAP_CROSSCHECK",json.dumps({"revisions":3,
  "boot_roots":[r["first_direct_boot_target"] for r in out["findings"]],
  "new_API_certified":0,"silicon_verified":False}))
if __name__=="__main__":main()
