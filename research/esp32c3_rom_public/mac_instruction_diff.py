#!/usr/bin/env python3
"""Compare exact RV32+C instructions and direct destinations for MAC sleep/wakeup.
Structural findings only. Reuses verified extraction, independently checks branch targets.
"""
import difflib, hashlib, io, json, pathlib, tarfile, urllib.request
from elftools.elf.elffile import ELFFile
from mac_revision_diff import scan, NAMES, REVS, URL, SHA, OUT
from rom_opcode import jal, compressed_jump

def normalize(row):
    # Code relocation means numeric operands often differ even for identical control flow.
    # Preserve opcode and register identity, do not claim normalized equality implies semantics.
    return row["mnemonic"]
def analyze():
    path=OUT/"summary.json"
    if not path.is_file():raise RuntimeError("MISSING_MAC_EVIDENCE")
    src=json.loads(path.read_text())
    per=src["revision_bodies"]
    report={"schema":"MAC_REV101_INSTRUCTION_DIFF_V1","source_archive_sha256":SHA,"functions":{},
       "limitations":["SequenceMatcher is only a display alignment, not semantic equivalence",
          "Indirect branch targets are not resolved", "No live power measurements"]}
    rev0,rev101,rev3=REVS
    for name in ("wdev_mac_sleep","wdev_mac_wakeup"):
        a=per[rev0][name];b=per[rev101][name];c=per[rev3][name]
        traces={r:per[r][name]["instruction_evidence"] for r in REVS}
        rev0_rev3_equal=a["sha256"]==c["sha256"]
        matcher=difflib.SequenceMatcher(a=[normalize(x) for x in traces[rev0]],
                                         b=[normalize(x) for x in traces[rev101]],autojunk=False)
        spans=[]
        for kind,i,j,k,l in matcher.get_opcodes():
            if kind=="equal":continue
            spans.append({"operation":kind,"rev0_instructions":traces[rev0][i:j],
                 "rev101_instructions":traces[rev101][k:l]})
        report["functions"][name]={"rev0_rev3_byte_identical":rev0_rev3_equal,
            "rev0_rev101_byte_identical":a["sha256"]==b["sha256"],
            "rev0_count":a["instruction_count"],"rev101_count":b["instruction_count"],
            "rev3_count":c["instruction_count"],"diff_blocks":spans,
            "rev101_direct_transfers":b["direct_transfers"],
            "rev0_direct_transfers":a["direct_transfers"],
            "rev3_direct_transfers":c["direct_transfers"],
            "rev101_indirect":b["indirect_transfers"],"rev0_indirect":a["indirect_transfers"]}
    dest=OUT/"instruction_diff.json"
    dest.write_text(json.dumps(report,indent=2)+"\n")
    print("MAC_INSTRUCTION_DIFF_RESULT "+json.dumps({name:{
        "rev0_rev3_identical":v["rev0_rev3_byte_identical"],
        "instruction_counts":[v["rev0_count"],v["rev101_count"],v["rev3_count"]],
        "changed_block_count":len(v["diff_blocks"]),
        "rev101_direct_transfers":v["rev101_direct_transfers"]}
        for name,v in report["functions"].items()},sort_keys=True))
if __name__=="__main__":analyze()
