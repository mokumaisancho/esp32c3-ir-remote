#!/usr/bin/env python3
"""Deterministic triage of the original 58 ROM candidates without ISA-effect proof.

This module does not interpret silicon MMIO, claim a novel API, or approve a
semantic review. It distinguishes ordinary return instructions from indirect
calls when prioritizing already-identified functions.
"""
import argparse
import ast
import hashlib
import json
import pathlib
import zipfile
from collections import Counter

from decision_gate import REVS, MACHINE_SHA, require, sha

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = ROOT / "research" / "esp32c3_rom_public"
# Alias mnemonics emitted by Capstone in verified ROM instruction listings.
# The pinned historical candidate ZIP counted only the legacy base list.
LEGACY_BRANCH = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "c.beqz", "c.bnez"}
BRANCH_ALIASES = {"beqz", "bnez", "bltz", "bgez", "bgtz", "blez", "bgt", "ble", "bgtu", "bleu"}
BRANCH = LEGACY_BRANCH | BRANCH_ALIASES
INDIRECT = {"jalr", "c.jalr", "c.jr", "jr"}
DIRECT = {"jal", "j", "c.j", "c.jal"}
READ = {"lw", "lh", "lhu", "lb", "lbu", "c.lw", "c.lwsp"}
WRITE = {"sw", "sh", "sb", "c.sw", "c.swsp"}


def source_literal(file_name, symbol):
    path = SOURCES / file_name
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and any(
            isinstance(x, ast.Name) and x.id == symbol for x in stmt.targets
        ):
            return ast.literal_eval(stmt.value)
    raise RuntimeError("MISSING_SOURCE_LITERAL:" + file_name + ":" + symbol)


def source_literal_local(file_name, symbol):
    path = pathlib.Path(__file__).with_name(file_name)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and any(
            isinstance(x, ast.Name) and x.id == symbol for x in stmt.targets
        ):
            return ast.literal_eval(stmt.value)
    raise RuntimeError("MISSING_LOCAL_LITERAL:" + file_name + ":" + symbol)


def modeled_names():
    prior_leaf = set(source_literal("leaf_isa_effect_differential.py", "NAMES"))
    # New leaf proof lives alongside the deterministic frontier.
    new_leaf = set(source_literal_local("two_linear_effects.py", "NAMES"))
    branch_leaf = set(source_literal_local("bounded_isa_effects.py", "NAMES"))
    agc_leaf = set(source_literal_local("agc_rom_effects.py", "NAMES"))
    spi_leaf = set(source_literal_local("spi_slave_rom_effects.py", "NAMES"))
    rom2_leaf = set(source_literal_local("rom2_wait_effects.py", "NAMES"))
    leaf = prior_leaf | new_leaf | branch_leaf | agc_leaf | spi_leaf | rom2_leaf
    exact = set(source_literal("candidate_mechanisms.py", "CASE"))
    require(len(prior_leaf) == 23 and len(new_leaf) == 2 and len(branch_leaf) == 4 and len(agc_leaf) == 1 and len(spi_leaf) == 1 and len(rom2_leaf) == 1, "LEAF_COUNT_DRIFT")
    require(len(leaf) == 32 and len(exact) == 19, "OPCODE_EFFECT_COUNT_DRIFT")
    require(len(leaf | exact) == 39, "UNION_COUNT_DRIFT")
    return leaf, exact


def is_return(op, args):
    x = args.replace(" ", "").lower()
    return (op in ("c.jr", "jr") and x == "ra") or (
        op == "jalr" and x in {"zero,0(ra)", "x0,0(ra)", "zero,ra,0"}
    )


def analyze_rows(rows):
    counts = Counter()
    if not rows:
        raise RuntimeError("EMPTY_VERIFIED_BODY")
    for row in rows:
        op = row["mnemonic"]
        args = row["operands"]
        counts["instructions"] += 1
        if op in BRANCH:
            counts["conditional_branches"] += 1
            if op in BRANCH_ALIASES:
                counts["branch_aliases_missed_by_legacy_audit"] += 1
        if op in READ:
            counts["memory_loads"] += 1
        if op in WRITE:
            counts["memory_stores"] += 1
        if op in INDIRECT:
            if is_return(op, args):
                counts["returns"] += 1
            else:
                counts["nonreturn_indirect_transfers"] += 1
        if op in DIRECT:
            counts["direct_transfers"] += 1
        if op in ("ecall", "ebreak", "c.ebreak", "c.unimp", "unimp"):
            counts["trap_or_undecoded"] += 1
    return dict(counts)


def build(machine_zip, state):
    require(state.get("schema") == "ROM_RESEARCH_AUTOPILOT_V1", "STATE_SCHEMA")
    require(state.get("candidate_count") == 88, "CANONICAL_88")
    require(state["source_sha256"]["machine"] == MACHINE_SHA, "STATE_SOURCE_HASH")
    require(sha(machine_zip) == MACHINE_SHA, "MACHINE_ARCHIVE_HASH")
    canonical = {x["name"] for x in state["tasks"]}
    require(len(state["tasks"]) == len(canonical) == 88, "STATE_NAME_UNIQUENESS")
    leaf, exact = modeled_names()
    modeled = leaf | exact
    require(modeled <= canonical, "EFFECT_NAMES_NOT_CANONICAL")
    remaining = canonical - modeled
    require(len(remaining) == 49, "PENDING_49_COUNT_DRIFT")
    task_by_name = {x["name"]: x for x in state["tasks"]}
    items = []
    with zipfile.ZipFile(machine_zip) as z:
        revisions = {
            rev: json.loads(z.read("output/candidate_full/" + rev + ".candidate_full.json"))
            for rev in REVS
        }
        for rev, functions in revisions.items():
            require(set(functions) == canonical, "REV_88_NOT_MATCH:" + rev)
        for name in sorted(remaining):
            slices = {}
            for rev, functions in revisions.items():
                f = functions[name]
                if f["status"] == "ABSENT_SYMBOL":
                    continue
                require(f["status"].startswith("FULL_BODY_VERIFIED"), "BODY_NOT_VERIFIED:" + name)
                metrics = analyze_rows(f["instruction_listing"])
                metrics["gnu_unchecked_zero_traps"] = len(f.get("zero_trap_encoding_rows_unchecked_by_gnu", []))
                require(metrics["instructions"] == f["instruction_count"], "INSTRUCTION_COUNT:" + name)
                expected_new = metrics.get("conditional_branches", 0)
                old_count = expected_new - metrics.get("branch_aliases_missed_by_legacy_audit", 0)
                # Historical machine archive is hash-pinned and immutable. It carries
                # undercounted conditional_branch_count. Accept exactly old or corrected
                # count, but always report the corrected count and the legacy delta.
                require(f["conditional_branch_count"] in (old_count, expected_new), "BRANCH_COUNT:" + name)
                metrics["upstream_branch_count_legacy"] = int(f["conditional_branch_count"] == old_count and old_count != expected_new)
                require(
                    metrics.get("nonreturn_indirect_transfers", 0)
                    + metrics.get("returns", 0) == f["indirect_transfer_count"],
                    "INDIRECT_COUNT:" + name
                )
                slices[rev] = {
                    "entry": f["start"],
                    "sha256": f["sha256"],
                    "instruction_metrics": metrics,
                    "machine_instructions": f["instruction_listing"],
                }
            require(bool(slices), "NO_VERIFIED_REVISION:" + name)
            totals = Counter()
            for revision in slices.values():
                totals.update(revision["instruction_metrics"])
            has_nonreturn_indirect = totals["nonreturn_indirect_transfers"] > 0
            has_conditions = totals["conditional_branches"] > 0
            has_direct = totals["direct_transfers"] > 0
            has_traps = totals["trap_or_undecoded"] > 0 or totals["gnu_unchecked_zero_traps"] > 0
            if has_traps:
                category = "TRAP_OR_UNDECODABLE"
            elif has_nonreturn_indirect:
                category = "NONRETURN_INDIRECT_CONTROL"
            elif has_conditions:
                category = "CONDITIONAL_CONTROL"
            elif has_direct:
                category = "DIRECT_CONTROL"
            else:
                category = "LINEAR_NO_CONTROL_TRANSFER_EXCEPT_RETURN"
            # Prioritize bounded effect reconstruction, not purported novelty.
            base = {"LINEAR_NO_CONTROL_TRANSFER_EXCEPT_RETURN": 0,
                    "DIRECT_CONTROL": 1, "CONDITIONAL_CONTROL": 2,
                    "NONRETURN_INDIRECT_CONTROL": 3, "TRAP_OR_UNDECODABLE": 4}[category]
            if base != 0:
                for revision in slices.values():
                    revision.pop("machine_instructions")
            items.append({
                "name": name,
                "task_id": task_by_name[name]["task_id"],
                "idf_linker_name_known": bool(task_by_name[name]["idf_name_known"]),
                "category": category,
                "revision_bodies": slices,
                "aggregate_machine_metrics": dict(totals),
                "priority_bucket": base,
                "novel_api_proven": False,
                "silicon_behavior_proven": False,
                "independently_reviewed": False,
                "next_test": (
                    "Map genuine indirect target and invocation assumptions"
                    if has_nonreturn_indirect else
                    "Derive counterexamples for each control-flow branch"
                    if has_conditions else
                    "Independently reproduce ordered read/write/return effects"
                ),
            })
    items.sort(key=lambda x: (x["priority_bucket"], x["aggregate_machine_metrics"]["instructions"], x["name"]))
    category_counts = dict(Counter(x["category"] for x in items))
    return {
        "schema": "ROM_ORIGINAL_88_SEMANTIC_FRONTIER_V1",
        "original_issue_id": "ESP32C3-ROM-001",
        "candidate_count": 88,
        "effects_proven_static_only": len(modeled),
        "leaf_replays": len(leaf),
        "original_leaf_replays": 23,
        "new_leaf_replays": 2,
        "bounded_branch_replays": 4,
        "agc_net_effect_replays": 1,
        "spi_net_effect_replays": 1,
        "rom2_bounded_wait_replays": 1,
        "other_opcode_witnesses": len(modeled - leaf),
        "awaiting_bounded_effect": len(items),
        "silicon_experiments_run": 0,
        "independent_review_approved": 0,
        "source_sha256": {
            "machine_archive": MACHINE_SHA,
            "leaf_script": sha(SOURCES / "leaf_isa_effect_differential.py"),
            "opcode_script": sha(SOURCES / "candidate_mechanisms.py"),
            "new_effect_script": sha(pathlib.Path(__file__).with_name("two_linear_effects.py")),
            "bounded_branch_script": sha(pathlib.Path(__file__).with_name("bounded_isa_effects.py")),
            "agc_script": sha(pathlib.Path(__file__).with_name("agc_rom_effects.py")),
            "spi_script": sha(pathlib.Path(__file__).with_name("spi_slave_rom_effects.py")),
            "rom2_script": sha(pathlib.Path(__file__).with_name("rom2_wait_effects.py")),
        },
        "category_counts": category_counts,
        "raw_indirect_occurrences_including_returns": sum(
            x["aggregate_machine_metrics"].get("returns", 0)
            + x["aggregate_machine_metrics"].get("nonreturn_indirect_transfers", 0)
            for x in items
        ),
        "nonreturn_indirect_occurrences": sum(
            x["aggregate_machine_metrics"].get("nonreturn_indirect_transfers", 0)
            for x in items
        ),
        "branch_aliases_missed_in_historical_machine_audit": sum(
            x["aggregate_machine_metrics"].get("branch_aliases_missed_by_legacy_audit", 0)
            for x in items
        ),
        "names_affected_by_branch_aliases": sum(
            x["aggregate_machine_metrics"].get("branch_aliases_missed_by_legacy_audit", 0) > 0
            for x in items
        ),
        "historical_upstream_branch_counters_stale": sum(
            x["aggregate_machine_metrics"].get("upstream_branch_count_legacy", 0)
            for x in items
        ),
        "next_batch": [x["name"] for x in items[:8]],
        "items": items,
        "limitations": [
            "Return opcode is not evidence of an indirect hardware callback.",
            "Counts are machine-code structure, not ISA semantic certification.",
            "Historical pinned machine archive omits Capstone branch aliases; corrected by independent full-instruction traversal.",
            "Memory load/store counts do not distinguish RAM, stack, or MMIO.",
            "No device execution, novelty assertion or review closure is performed.",
            "Only original 88 candidates are enumerated.",
        ],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--machine", type=pathlib.Path, required=True)
    p.add_argument("--state", type=pathlib.Path, required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    args = p.parse_args()
    result = build(args.machine, json.loads(args.state.read_text()))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    for item in result["items"]:
        if item["category"] == "LINEAR_NO_CONTROL_TRANSFER_EXCEPT_RETURN":
            print("ROM_LINEAR_MACHINE", json.dumps({
                "name": item["name"],
                "revisions": {
                    rev: [(r["pc"], r["word"], r["mnemonic"], r["operands"])
                          for r in v["machine_instructions"]]
                    for rev, v in item["revision_bodies"].items()
                },
            }, sort_keys=True))
    print("ROM_SEMANTIC_FRONTIER", json.dumps({
        "awaiting_bounded_effect": result["awaiting_bounded_effect"],
        "category_counts": result["category_counts"],
        "next_batch": result["next_batch"],
        "nonreturn_indirect_occurrences": result["nonreturn_indirect_occurrences"],
        "branch_aliases_corrected": result["branch_aliases_missed_in_historical_machine_audit"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
