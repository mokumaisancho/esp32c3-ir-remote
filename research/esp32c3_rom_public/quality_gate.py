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

def read(path):
    return json.loads(path.read_text())

def main():
    files={"entry":OUT/"entry_audit"/"entry_audit_summary.json",
           "targets":OUT/"targets"/"summary.json",
           "registers":OUT/"register_access"/"summary.json"}
    for name,p in files.items():
        if not p.is_file():raise EvidenceError("MISSING_EVIDENCE:"+name)
    sources={k:read(p) for k,p in files.items()}
    ng=negative_tests(sources["entry"],sources["targets"],sources["registers"])
    gates=validate(sources["entry"],sources["targets"],sources["registers"])
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
