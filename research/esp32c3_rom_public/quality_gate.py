#!/usr/bin/env python3
"""Independent fail-closed evidence gate for structural ROM assertions only.

Do NOT convert CI exit status to semantic API / hardware-function certification.
"""
import hashlib
import json
import pathlib

ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"
SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")

class EvidenceError(ValueError):
    pass

def require(cond, label):
    if not cond:
        raise EvidenceError(label)

def validate(entry, targets, registers):
    require(entry.get("archive_sha256")==SHA,"G1_ENTRY_ARCHIVE_INTEGRITY")
    require(registers.get("source_archive_sha256")==SHA,"G1_REGISTER_ARCHIVE_INTEGRITY")
    for rev in REVS:
        a=entry.get("revisions",{}).get(rev,{})
        t=targets.get("revisions",{}).get(rev,{})
        r=registers.get("revisions",{}).get(rev,{})
        require(a.get("entry_rows")==648,"G1_INCOMPLETE_ENTRY_INVENTORY:"+rev)
        require(a.get("first_instruction_decode_count")==648,"G3_ENTRY_OPCODE_UNDECODED:"+rev)
        require(a.get("classes")=={"JAL":648},"G3_ENTRY_OPCODE_NOT_ALL_JAL:"+rev)
        require(a.get("independent_capstone_offset_agreement")==648,"G3_DISASSEMBLER_DIVERGENCE:"+rev)
        require(t.get("total")==648,"G4_UNVERIFIED_TARGET_COUNT:"+rev)
        stat=t.get("counts",{})
        require(stat.get("valid_exec")==648,"G4_JAL_OUTSIDE_EXECUTABLE:"+rev)
        require(stat.get("exact_STT_FUNC")==648,"G4_JAL_TARGET_NOT_FUNCTION:"+rev)
        require(t.get("structural_verdict")=="PASS","G4_TARGET_STRUCTURAL_GATE_NOT_PASS:"+rev)
        require(t.get("semantic_verdict")=="NOT_CERTIFIED","G4_SEMANTIC_CLAIM_OVERSTATED:"+rev)
        require(a.get("elf_same_name_count")==stat.get("matched_named_function"),"G4_CROSS_SCRIPT_NAME_COUNT_CONFLICT:"+rev)
        missing=t.get("unresolved_name_mismatches",[])
        require(len(missing)+stat.get("matched_named_function",0)==648,"G4_LOST_NAME_MISMATCHES:"+rev)
        require(len(missing)==stat.get("name_mismatch_unresolved"),"G4_UNREPORTED_NAME_MISMATCHES:"+rev)
        require(isinstance(r.get("unique_mmio_addresses"),int),"G1_MMIO_EVIDENCE_MISSING:"+rev)
        require(isinstance(r.get("csr_static_access_count"),int),"G1_CSR_EVIDENCE_MISSING:"+rev)
        require(r.get("elf_sha256")==a.get("sha256"),"G4_INCONSISTENT_ELF_REVISION:"+rev)
    return {"G0":"PASS","G1":"PASS_FOR_STRUCTURAL_EVIDENCE","G2":"PASS_PUBLIC_RUNNER",
            "G3":"PASS_STRUCTURAL_DETERMINISTIC_TESTS",
            "G4":"PASS_FOR_STRUCTURAL_CLAIMS_ONLY",
            "G5":"NOT_MET_SEMANTIC_AND_PRIOR_ART_REMAIN_OPEN"}

def negative_tests(entry, targets, regs):
    # A bad field must cause a fail. Tests never use a real ROM 'expected target'.
    import copy
    for label,change in (
        ("corrupted_opcode",lambda a,t,r:a["revisions"][REVS[0]].update({"classes":{"JAL":647,"OTHER":1}})),
        ("corrupted_target",lambda a,t,r:t["revisions"][REVS[0]]["counts"].update({"valid_exec":647})),
        ("corrupted_revision",lambda a,t,r:r["revisions"][REVS[0]].update({"elf_sha256":"0"*64})),
        ("fake_semantic_pass",lambda a,t,r:t["revisions"][REVS[0]].update({"semantic_verdict":"PASS"})),
    ):
        a,t,r=copy.deepcopy(entry),copy.deepcopy(targets),copy.deepcopy(regs)
        change(a,t,r)
        try:validate(a,t,r)
        except EvidenceError: pass
        else:raise RuntimeError("NEGATIVE_MUTATION_NOT_CAUGHT:"+label)
    return 4

def validate_external_sources(registers, extras):
    exact=extras["official_exact"]
    base=extras["official_base"]
    publication=extras["published_prior"]
    priority=extras["internal_priority"]
    require(exact.get("upstream_git_commit")=="1c42e514c90ae621af33bde3b6ad3dac22edcbfd",
            "G1_UNPINNED_REGISTER_HEADERS")
    require(exact.get("headers_scanned")==28,"G1_INCOMPLETE_VENDOR_HEADERS")
    require(exact.get("simple_register_macros_resolved",0)>0,"G1_NO_VENDOR_REGISTER_MACROS")
    require(publication.get("source",{}).get("year")==2025,"G1_PRIOR_ART_SOURCE_CHANGED")
    require(priority.get("status")=="RESEARCH_PRIORITIZATION_ONLY","G4_INTERNAL_PRIORITY_SEMANTIC_OVERCLAIM")
    require(priority.get("candidate_count",0)>=len(priority.get("top_candidates",[])),
            "G4_CANDIDATE_COUNT_CORRUPTED")
    for rev in REVS:
        u=registers["revisions"][rev].get("unique_mmio_addresses")
        a=exact["revisions"].get(rev,{})
        b=base["revisions"].get(rev,{})
        p=publication["revisions"].get(rev,{})
        require(a.get("unique_rom_mmio_addresses")==u,"G4_EXACT_SOURCE_MMIO_DENOMINATOR:"+rev)
        require(a.get("exact_vendor_register_offsets_matched",0)+a.get("not_matched_to_simple_vendor_macros",0)==u,
                "G4_EXACT_SOURCE_PARTITION_INVALID:"+rev)
        require(b.get("unique_addresses")==u,"G4_BASE_SOURCE_MMIO_DENOMINATOR:"+rev)
        require(p.get("matched_published_addresses",0)+len(p.get("not_seen_strict_scanner",[]))==
                p.get("published_prior_count"),"G4_PUBLISHED_DATASET_PARTITION_INVALID:"+rev)
    return True

def validate_independent_native(entry, extras):
    native=extras["independent_objdump"]
    graph=extras["callgraph"]
    priority=extras["internal_priority"]
    require(native.get("archive_sha256")==SHA,"G1_NATIVE_SOURCE_MISMATCH")
    require(graph.get("archive_sha256")==SHA,"G1_GRAPH_SOURCE_MISMATCH")
    require(native.get("validator","").startswith("GNU binutils"),"G3_INDEPENDENT_ANALYZER_REQUIRED")
    require(graph.get("candidate_count")==priority.get("candidate_count"),"G4_CANDIDATE_TRUNCATION")
    require(priority.get("candidate_count")==len(priority.get("all_candidates",[])),"G4_MISSING_FULL_CANDIDATE_EVIDENCE")
    for rev in REVS:
        a=entry["revisions"][rev]
        n=native.get("revisions",{}).get(rev,{})
        g=graph.get("revisions",{}).get(rev,{})
        require(n.get("total")==648 and n.get("independent_matches")==648 and
                n.get("independent_mismatches")==0,"G3_GNU_TARGET_MISMATCH:"+rev)
        require(n.get("elf_sha256")==a.get("sha256"),"G1_NATIVE_REVISION_SWAP:"+rev)
        require(g.get("elf_sha256")==a.get("sha256"),"G1_GRAPH_REVISION_SWAP:"+rev)
        require(g.get("all_candidate_count")==priority.get("candidate_count"),"G4_GRAPH_CANDIDATE_COUNT:"+rev)
        reachable=g.get("candidate_with_static_public_path")
        unreachable=g.get("candidate_without_direct_path")
        require(isinstance(reachable,int) and isinstance(unreachable,int) and
                reachable>=0 and unreachable>=0 and reachable+unreachable==priority.get("candidate_count"),
                "G4_GRAPH_PARTITION_INVALID:"+rev)
        require(g.get("cross_function_named_edges",0)>0 and g.get("public_root_names")==648,
                "G3_GRAPH_MISSING_REFERENCES:"+rev)
        require(len(g.get("representative_candidates",[]))<=reachable,"G4_GRAPH_WITNESS_COUNT_INVALID:"+rev)
    return True

def negative_independent_native(entry,extras):
    import copy
    altered=copy.deepcopy(extras)
    altered["independent_objdump"]["revisions"][REVS[0]]["independent_matches"]=647
    try:validate_independent_native(entry,altered)
    except EvidenceError:pass
    else:raise RuntimeError("NEGATIVE_NATIVE_TARGET_CORRUPTION_NOT_CAUGHT")
    altered=copy.deepcopy(extras)
    altered["callgraph"]["revisions"][REVS[0]]["candidate_without_direct_path"]=-1
    try:validate_independent_native(entry,altered)
    except EvidenceError:pass
    else:raise RuntimeError("NEGATIVE_GRAPH_NEGATIVE_REACHABILITY_NOT_CAUGHT")
    return 2

def supplemental_negative_tests(registers, extras):
    import copy
    altered=copy.deepcopy(extras)
    rev=REVS[0]
    altered["official_exact"]["revisions"][rev]["unique_rom_mmio_addresses"]=-1
    try:validate_external_sources(registers,altered)
    except EvidenceError:pass
    else:raise RuntimeError("NEGATIVE_SUPPLEMENTAL_DENOMINATOR_NOT_CAUGHT")
    altered=copy.deepcopy(extras)
    altered["official_exact"]["upstream_git_commit"]="0"*40
    try:validate_external_sources(registers,altered)
    except EvidenceError:pass
    else:raise RuntimeError("NEGATIVE_SUPPLEMENTAL_UNPINNED_SOURCE_NOT_CAUGHT")
    return 2

def read(path):
    return json.loads(path.read_text())

def main():
    files={"entry":OUT/"entry_audit"/"entry_audit_summary.json",
           "targets":OUT/"targets"/"summary.json",
           "registers":OUT/"register_access"/"summary.json",
           "official_exact":OUT/"register_access"/"official_exact_offset_comparison.json",
           "official_base":OUT/"register_access"/"official_base_comparison.json",
           "published_prior":OUT/"register_access"/"published_prior_art_comparison.json",
           "internal_priority":OUT/"internal_function_candidates.json",
           "independent_objdump":OUT/"independent_objdump"/"summary.json",
           "callgraph":OUT/"callgraph"/"summary.json"}
    for name,p in files.items():
        if not p.is_file():raise EvidenceError("MISSING_EVIDENCE:"+name)
    sources={k:read(p) for k,p in files.items()}
    ng=negative_tests(sources["entry"],sources["targets"],sources["registers"])
    gates=validate(sources["entry"],sources["targets"],sources["registers"])
    ext={k:v for k,v in sources.items() if k not in ("entry","targets","registers")}
    validate_external_sources(sources["registers"],ext)
    ng+=supplemental_negative_tests(sources["registers"],ext)
    validate_independent_native(sources["entry"],ext)
    ng+=negative_independent_native(sources["entry"],ext)
    proof={"schema":"ROM_QA_GATE_V1","issue_id":"ESP32C3-ROM-001",
        "evidence_sha256":{k:hashlib.sha256(p.read_bytes()).hexdigest() for k,p in files.items()},
        "negative_mutations_caught":ng,
        "gates":gates,
        "ac_verdict":{"AC01":"PASS","AC02":"PASS","AC03":"PARTIAL",
          "AC04":"PARTIAL_STATIC_CANDIDATES_ONLY","AC05":"NOT_MET"},
        "overall":"INCOMPLETE","caution":"Structural gate passing is not proof of ROM semantics or undocumented API."}
    p=OUT/"quality_gate.json";p.write_text(json.dumps(proof,indent=2)+"\n")
    print("QA_GATE_RESULT "+json.dumps(proof,separators=(",",":")))
    return proof

if __name__=="__main__":
    main()
