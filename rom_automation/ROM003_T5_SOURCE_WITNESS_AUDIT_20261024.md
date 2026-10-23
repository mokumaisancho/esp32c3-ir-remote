# ROM-003 T5: independent control-flow witness audit — 2026-10-24

Original issue: **ESP32C3-ROM-001**. Current executable work: [ROM-003 Epic #6](https://github.com/mokumaisancho/esp32c3-ir-remote/issues/6).

## Question and stopping criteria

Do any of the **252 possible function entrypoints outside positive-sized ELF function extents** have an independently validated control-flow transfer from already-established ROM code?

This work does **not** re-rank known symbol names, conflate undecoded gap bytes with function starts, claim new ABI/callability, or infer new silicon behavior. It tests the raw machine-call *sources* rather than only code-looking *targets*.

## Verified evidence and CI

- Source archive: Espressif official three-ROM release, SHA256 `caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46`.
- Candidate acquisition: [E0 raw-byte-only/ELF-oracle separation](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/rom_boundary_source_seal.py); E1 scanner runs in different CI runner from evaluator. [E1 original source](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/rom_boundary_byte_frontier.py).
- Machine source audit: [`rom_unclaimed_source_attestation.py`](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/rom_unclaimed_source_attestation.py) + [11 falsification tests](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/test_rom_unclaimed_source_attestation.py).
- **[CI run #40028774232, all three jobs PASS](https://github.com/mokumaisancho/esp32c3-ir-remote/actions/runs/40028774232)**. E1 14 test cases, E2 exact-entry evaluation 11, ELF extent triage 6, and independent source attestation 11 = **42 tests PASS**. ROM-001 original source and binary hashes are fixed. No physical devices accessed.
- Results artifact: GitHub Actions artifact ID `12533239278`, digest SHA256 `47e152475a48244ef26f3cd917d4ab7504c3bb54d5ff66d2d9dcb41b59d4d4b7`. The artifact contains `independent_source_attestation.json`, 260 individual source-witness assessments with ROM raw machine bytes, Capstone exact opcode length, source PC, candidate PC, and typed classification.

### Raw-link source attestation results

| Revision | Unclaimed candidate PCs | Raw apparent incoming calls | Source inside named ELF function, **mid-word** | Source outside all named ELF functions | Independently rooted new entry |
|---|---:|---:|---:|---:|---:|
| rev0 | 81 | 81 | 3 | 78 | 0 |
| rev101 | 76 | 77 | 5 | 72 | 0 |
| rev3 | 95 | 102 | 3 | 99 | 0 |
| **Total** | **252** | **260** | **11** | **249** | **0** |

The **11** apparent `C.JAL` call-source addresses inside known ELF function extents are on the **second halfword of a four-byte instruction** when decoded from that function's start (Capstone RV32IC plus independent encoding-length witness). They do not constitute proven call instructions on that ordinary function-local instruction stream; an unproven alternative overlapping execution entry is still possible and is explicitly **UNKNOWN**.

The remaining **249** raw-call source addresses are outside currently named ELF function extents and have no independent established rooted execution witness. Neither raw decoded `C.JAL` bytes nor destination-looking machine instructions prove they are executed.

### Repeated evidence, not independent discoveries

Two false pseudo-call sequences reappear after ROM address relocation in all three revisions:

1. `_interrupt_handler` source raw halfword `1934` at rev0 `0x40001d46`, rev101 `0x40002046`, rev3 `0x40001e46`. Their pseudo-targets `0x4000174c`, `0x40001a4c`, `0x4000184c`.
2. `r_rw_crypto_aes_ccm` source raw halfword `4530` at rev0 `0x400021f2`, rev101 `0x400024f2`, rev3 `0x400022f2`. Their pseudo-targets `0x40001a92`, `0x40001d92`, `0x40001b92`.

Do not count these as six independent candidate APIs.

### Cross-check against prior, already-performed independent static approaches

Previously SHA-pinned `P0A_RV32IMC_gap_branch_WIS.json` found **0** machine-decoded direct branches into positive-STT_FUNC-size gaps in all three revisions. `P0A_verified_static_indirect_into_gaps.json` found **0** resolved locally provable indirect JALR into such gaps (after inspecting 5169 / 5422 / 5128 non-return JALRs). `P0A_CFG_local_register_provenance.json` also showed **0** local constant CFG edges into gaps, and `P0A_trap_vector_mtvec_mtvt_roots.json` gave **0** trap roots inside unlabelled ROM across all three. The independent read-only pointer candidate report `P0A_indirect_gap_roots.json` found two non-executing pointer-word matches per ROM, but **none** intersects the current 252 entrypoint candidates. These are *bounded existing-method negative results*, not an exhaustive mathematical proof no entry can exist.

Original independently archived evidence ZIP SHA256 `685cd51f50fddd43ba2aa94bcdee778a9ebd4850d9efee96d573a4df94bee27a`.

## Acceptance Criteria verdict

- **T6-AC1 PASS:** every one of 260 potential raw-call source byte sequences is matched to the SHA-pinned ROM executable input, and each source's encoded target is recomputed.
- **T6-AC2 PASS:** 11 in-named-extents pseudo call sources are shown to straddle four-byte instructions on the ordinary named function decode path, with mutation tests.
- **T6-AC3 PASS:** all 249 unclaimed source cases are preserved as `UNKNOWN`, not falsely marked DATA or CODE, and no false novel API is recorded.
- **T6-AC4 PASS:** evaluator alone imports function symbols, candidate job does not; output is reason-coded, reproducible, and archived.
- **Original AC-E4 BLOCKED:** zero independently verified transfers into an unclaimed executable function entry. No callable novel ROM API proven; no silicon execution tested.

## Exact remaining dependency

**The next decision-changing input** is independent rooted executable instruction evidence for *one of the remaining 249 unclaimed source locations*, e.g. a Capstone/Ghidra CFG path rooted in a verified boot/interrupt function that reaches that source **without using the raw `C.JAL` itself as the starting root**, or a revised, correctly proven indirect dispatch/table dereference leading to that address. Alternatively, an authorized revision-matched runtime trace showing the guest PC actually at that machine address, without unsafe RF/MMIO writes.

Once it exists: source PC and raw bytes → confirm true transfer into a candidate PC → function vs branch block boundary → official/dated prior-art check → callable ABI and safe silicon causal evidence. Until then do **not** mine high-scoring far-distance gaps as presumed APIs; final original issue remains BLOCKED rather than COMPLETE.
