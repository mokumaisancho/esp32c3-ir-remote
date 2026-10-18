#!/usr/bin/env python3
"""Independent row-level evidence gate. Never infer functional equivalence from a name."""
import csv, json, pathlib

ROOT=pathlib.Path(__file__).resolve().parent
TARGETS=ROOT/"output"/"targets"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
class RowEvidenceError(ValueError): pass
def check(rows, baseline_names, stats):
    if len(baseline_names)!=648 or len(set(baseline_names))!=648:
        raise RowEvidenceError("BASELINE_IDENTITY_INVALID")
    names=[r["known_rom_name"] for r in rows]
    if len(rows)!=648 or len(set(names))!=648 or set(names)!=set(baseline_names):
        raise RowEvidenceError("TARGET_ROW_IDENTITY_OR_COMPLETENESS_INVALID")
    if len(set(r["rom_entry"] for r in rows))!=648:
        raise RowEvidenceError("DUPLICATE_ROM_ENTRY")
    if not all(r["target_executable"] in ("True","true") for r in rows):
        raise RowEvidenceError("TARGET_NOT_EXECUTABLE")
    matched=sum(r["known_rom_name"] in r["elf_function_names"].split(";") for r in rows)
    mismatched=648-matched
    for key,expected in (("matched_named_function",matched),
                         ("name_mismatch_unresolved",mismatched),
                         ("valid_exec",648),("exact_STT_FUNC",648)):
        if stats.get(key)!=expected:
            raise RowEvidenceError("ROW_SUMMARY_CONFLICT:"+key)
    if any(not r["elf_function_names"] for r in rows):
        raise RowEvidenceError("UNNAMED_TARGET")
    return matched,mismatched

def negative_tests():
    baseline=[f"s{i}" for i in range(648)]
    rows=[dict(known_rom_name=f"s{i}",rom_entry=hex(0x40000018+4*i),
       target_executable="True",elf_function_names=f"s{i}") for i in range(648)]
    stats=dict(matched_named_function=648,name_mismatch_unresolved=0,
               valid_exec=648,exact_STT_FUNC=648)
    assert check(rows,baseline,stats)==(648,0)
    tests=[
       ("duplicate",lambda x: x.__setitem__(1,dict(x[0]))),
       ("missing",lambda x:x.pop()),
       ("renamed",lambda x:x[0].update(known_rom_name="injected")),
       ("bad_target",lambda x:x[0].update(target_executable="False")),
       ("bad_address",lambda x:x[0].update(rom_entry=x[1]["rom_entry"])),
       ("summary_lie",lambda x:x[0].update(elf_function_names="unknown"))]
    import copy
    for label,corrupt in tests:
        copy_rows=copy.deepcopy(rows)
        corrupt(copy_rows)
        try:check(copy_rows,baseline,stats)
        except RowEvidenceError:continue
        raise RuntimeError("MUTATION_NOT_CAUGHT:"+label)
    return len(tests)
def main():
    mut=negative_tests()
    with (ROOT/"rom_api_baseline.csv").open(newline="") as f:
        names=[r["symbol"] for r in csv.DictReader(f) if r["type"]=="function"]
    summary=json.loads((TARGETS/"summary.json").read_text())
    report={"schema":"ROM_TARGET_ROW_GATE_V1","negative_mutations_caught":mut,
            "revisions":{},"semantic_verdict":"NOT_CERTIFIED"}
    for rev in REVS:
        with (TARGETS/(rev+".csv")).open(newline="") as f:
            rows=list(csv.DictReader(f))
        stats=summary["revisions"][rev]["counts"]
        a,b=check(rows,names,stats)
        report["revisions"][rev]={"identity_rows":648,"names_matched":a,
                                   "names_unresolved":b,"row_consistency":"PASS"}
    dest=ROOT/"output"/"quality"
    dest.mkdir(parents=True,exist_ok=True)
    (dest/"row_gate.json").write_text(json.dumps(report,indent=2)+"\n")
    print("ROW_GATE_RESULT",json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
