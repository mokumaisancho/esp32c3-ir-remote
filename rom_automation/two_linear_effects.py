#!/usr/bin/env python3
"""Two newly reconstructed straight-line ISA effects from the original ROM 88.

A separate operation interpreter is checked against independently specified
word-level formulas and ordered stores on boundary and held-out seeded inputs.
This is static RV32IC behavior, NOT hardware-register causal evidence.
"""
import argparse
import copy
import json
import pathlib
import random
import re
import zipfile
from decision_gate import REVS, MACHINE_SHA, require, sha

NAMES = ("r_lld_cca_set_thresh", "r_bt_bb_restart_hw_recorrect")
MASK = 0xffffffff
ADDRESSES = (0x600110b8, 0x60011868)


def integer(x):
    return int(x, 0)


def execute(rows, memory, argument):
    registers = {"zero": 0, "a0": argument & MASK}
    m = dict(memory)
    writes = []
    get = lambda reg: 0 if reg == "zero" else registers.get(reg, 0)
    for row in rows:
        op = row["mnemonic"]
        parts = [x.strip() for x in row["operands"].split(",")]
        if op == "c.jr" and parts == ["ra"]:
            return get("a0"), m, writes
        if op in ("lui", "c.lui"):
            registers[parts[0]] = (integer(parts[1]) << 12) & MASK
        elif op == "addi":
            registers[parts[0]] = (get(parts[1]) + integer(parts[2])) & MASK
        elif op == "c.slli":
            registers[parts[0]] = (get(parts[0]) << integer(parts[1])) & MASK
        elif op == "andi":
            registers[parts[0]] = get(parts[1]) & (integer(parts[2]) & MASK)
        elif op in ("c.and", "c.or"):
            registers[parts[0]] = (get(parts[0]) & get(parts[1]) if op == "c.and"
                                   else get(parts[0]) | get(parts[1])) & MASK
        elif op in ("lw", "sw"):
            match = re.fullmatch(r"(-?(?:0x[0-9a-f]+|[0-9]+))\((\w+)\)", parts[1])
            require(bool(match), "INVALID_MEMORY_OPERAND")
            location = (get(match.group(2)) + integer(match.group(1))) & MASK
            require(location in ADDRESSES, "UNRECOGNIZED_MEMORY_ADDRESS")
            if op == "lw":
                registers[parts[0]] = m[location]
            else:
                m[location] = get(parts[0])
                writes.append((location, m[location]))
        else:
            raise RuntimeError("UNSUPPORTED_LINEAR_ISA:" + op)
    raise RuntimeError("MISSING_RETURN")


def reference(name, mem, a0):
    original = mem[ADDRESSES[0]] if name == NAMES[0] else mem[ADDRESSES[1]]
    if name == NAMES[0]:
        new = (original & 0xfffffe01) | ((a0 << 1) & 0x1fe)
        return new & MASK, {**mem, ADDRESSES[0]: new & MASK}, [(ADDRESSES[0], new & MASK)]
    if name == NAMES[1]:
        first = original & 0xffffe7df
        second = first | 0x1820
        return a0 & MASK, {**mem, ADDRESSES[1]: second & MASK}, [
            (ADDRESSES[1], first & MASK), (ADDRESSES[1], second & MASK)]
    raise RuntimeError("UNKNOWN_EFFECT_NAME")


def cases():
    boundary = (0, 1, 2, 0xa5, 0x1fe, 0x1ff, 0xffffe7df, 0x1820,
                0x80000000, 0xffffffff, 0xaaaaaaaa, 0x55555555, 0xdeadbeef)
    for index, v in enumerate(boundary):
        yield {ADDRESSES[0]: v, ADDRESSES[1]: (v ^ 0x695a3c17) & MASK}, (v << index) & MASK
    rng = random.Random(0xC3A2026)
    for _ in range(117):
        yield {address: rng.getrandbits(32) for address in ADDRESSES}, rng.getrandbits(32)


def verify(name, rows):
    first_writes = None
    for index, (memory, a0) in enumerate(cases()):
        actual = execute(rows, memory, a0)
        expected = reference(name, memory, a0)
        require(actual == expected, "DIFFERENTIAL_OR_STORE_ORDER:" + name + ":" + str(index))
        if index == 0:
            first_writes = [{"address": hex(addr), "value": hex(value)}
                            for addr, value in actual[2]]
    return first_writes


def mutation_check(name, rows, needle, replacement):
    changed = copy.deepcopy(rows)
    targets = [x for x in changed if x["operands"] == needle]
    require(len(targets) == 1, "MUTATION_NOT_UNIQUE")
    targets[0]["operands"] = replacement
    try:
        verify(name, changed)
    except RuntimeError as error:
        require("DIFFERENTIAL_OR_STORE_ORDER" in str(error), "WRONG_MUTATION_FAILURE")
        return True
    raise RuntimeError("MUTATION_ESCAPED_DETECTION:" + name)


def evaluate(machine):
    require(sha(machine) == MACHINE_SHA, "ORIGINAL_MACHINE_HASH")
    evidence = {}
    with zipfile.ZipFile(machine) as z:
        blobs = {rev: json.loads(z.read("output/candidate_full/" + rev + ".candidate_full.json"))
                 for rev in REVS}
    for name in NAMES:
        revisions = {}
        for rev in REVS:
            f = blobs[rev][name]
            if f["status"] == "ABSENT_SYMBOL":
                continue
            require(f["status"].startswith("FULL_BODY_VERIFIED"), "MACHINE_CODE_NOT_VERIFIED")
            require(not f.get("zero_trap_encoding_rows_unchecked_by_gnu"), "GNU_UNCHECKED_TRAP")
            rows = f["instruction_listing"]
            require(f["instruction_count"] == len(rows), "INSTRUCTION_COUNT")
            writes = verify(name, rows)
            revisions[rev] = {"entry": f["start"], "sha256": f["sha256"],
                              "vector_count": 130, "example_store_sequence": writes}
        require(revisions, "FUNCTION_ABSENT_ALL_REVISIONS:" + name)
        evidence[name] = revisions
    # Genuine ISA operand mutations must violate independently specified effects.
    a = blobs["esp32c3_rev101_rom.elf"][NAMES[0]]["instruction_listing"]
    b = blobs["esp32c3_rev101_rom.elf"][NAMES[1]]["instruction_listing"]
    require(mutation_check(NAMES[0], a, "a0, 1", "a0, 2"), "MUTATION1")
    require(mutation_check(NAMES[1], b, "a3, a3, -0x7e0", "a3, a3, -0x7e1"), "MUTATION2")
    return {
        "schema": "ROM_2_ADDITIONAL_LINEAR_ISA_EFFECTS_V1",
        "original_issue_id": "ESP32C3-ROM-001",
        "new_static_effect_names": list(NAMES),
        "static_effects": {
            NAMES[0]: "mem32[0x600110b8] = (old & 0xfffffe01) | ((a0 << 1) & 0x1fe); return new",
            NAMES[1]: "write mem32[0x60011868] = old & 0xffffe7df; re-read; write |= 0x1820",
        },
        "revision_function_bodies": sum(len(r) for r in evidence.values()),
        "differential_vectors": sum(130 * len(r) for r in evidence.values()),
        "negative_operand_mutations_caught": 2,
        "source_machine_sha256": MACHINE_SHA,
        "revisions": evidence,
        "silicon_effect_verified": False,
        "independent_review_approved": False,
        "novel_api_verified": False,
        "limitations": [
            "Hardware memory-mapped registers may change between consecutive reads.",
            "Actual peripheral state, function call reachability, and revision of owned ESP32-C3 are unknown.",
            "ISA interpreter and expected formulas share the source binary, not independent hardware ground truth.",
            "No new ROM candidate added or independently reviewed."
        ],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--machine", required=True, type=pathlib.Path)
    p.add_argument("--out", required=True, type=pathlib.Path)
    a = p.parse_args()
    result = evaluate(a.machine)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2) + "\n")
    print("ROM_2_NEW_LINEAR_EFFECTS", json.dumps({
        "names": result["new_static_effect_names"],
        "revision_bodies": result["revision_function_bodies"],
        "vectors": result["differential_vectors"],
        "negative_mutations": result["negative_operand_mutations_caught"],
        "silicon_effect_verified": False
    }, sort_keys=True))


if __name__ == "__main__":
    main()
