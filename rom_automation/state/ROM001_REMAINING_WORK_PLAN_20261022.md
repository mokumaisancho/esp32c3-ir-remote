# ROM-001: Remaining Work / Acceptance Criteria / Timeboxed Plan
Updated: 2026-10-22 JST. Planning baseline, NOT a promise of later autonomous execution.

## Goal and current baseline
Original goal: independently verify genuinely new, *usable* ESP32-C3 ROM API or unknown silicon capability. A deterministic zero-new-findings conclusion is valid for the timeboxed exploration, but must not be labeled as "new API discovered".
- Complete: original 152 symbol candidates screened. 128 active official linker names, 16 official commented-out documented names, eight names with separate public sources. Reproducible negative controls 7/7 PASS (GitHub Actions [39777111796](https://github.com/mokumaisancho/esp32c3-ir-remote/actions/runs/39777111796)).
- Complete: pinned machine-byte static semantics of `rom2_temp_to_power1`, but the name is already in official ECO7 and not novel.
- Open: two unexplained C3 MMIO register bitfields, provable symbolless ROM entrypoint, revision-matched device observation, usable novel capability.
- Out of scope: separate ESP32-C3 IR receive/flash issue #1.

## Calendar & workload assumptions
Start 2026-10-23; estimated 3–4 focused effort-hours on working days with GitHub CI available. Dates are indicative and require re-estimation if external sources or device access are blocked. Estimated core execution effort 20–34 focused hours for R1–R5, plus 1–2 hours of setup R0 (21–36 hours in total), excluding major new findings and external waits. We do not run this work in the background.

| Work ID | Priority | Work / measurable acceptance criteria | Dependencies | Effort | Target | Done evidence |
|---|---|---|---|---:|---|---|
| R0 | P0 | Freeze pinned artifacts/revisions and negative controls; confirm issue #2 scope, reason-coded unknown, novelty gate and exit policy; no unqualified PASS | Current source and CI verified | 1–2h | 2026-10-23 | Machine-readable source provenance and AC crosswalk |
| R1 | P0 | Classify `0x600061c4` in `rom_phy_xpd_rf` rev0: RMW input/output, exact ROM PC, address-block ownership, field semantic evidence or explicit unresolved statement; no speculative RF writes | R0 | 4–6h | 2026-10-26 | Version-pinned RMW trace, source correlation, falsification tests |
| R2 | P0 | Classify `0x60033c00` in `wdev_mac_wakeup` rev101: verify `OLD | 0xf0`, establish field source evidence or explicit unresolved statement; guard against unrelated ESP32/QEMU evidence | R0 | 4–6h | 2026-10-28 | Revision-pinned trace, documented source limits, negative controls |
| R3 | P0 | Search real symbolless function entries across rev0/rev101/rev3 with rooted CFG, direct/indirect, vector and table evidence; reject code-data coincidences and entrypoint aliases; report exact proofs or a defensible zero | R0; can run parallel with R1/R2 | 6–10h | 2026-10-30 | Candidate evidence matrix with byte-level witnesses, regression tests, zero/positive case |
| R4 | P0 | For surviving candidates, define safe read-only, hardware-revision-specific causal validation; collect firmware SHA, chip revision and actual receipt if authorized connected silicon is available; do NOT issue unvalidated RF write or unknown ROM call | R1/R2/R3 plus available authorized C3 | 4–8h | 2026-11-04 (conditional) | Actual-device receipt or explicit BLOCKED |
| R5 | P0 | Classify candidate as VERIFIED_NEW_USABLE, KNOWN_BEHAVIOR, STATIC_ONLY, FALSIFIED, or UNDETERMINED; every AC linked to exact evidence; explicitly retain 0 if no proof | R1/R2/R3; R4 if accessible | 2–4h | 2026-11-06 | Machine-readable go/no-go and final evidence report |

## Practical critical path
R0 -> [R1 and R2 in parallel] -> R4 -> R5.
R0 -> R3 independently -> R4 -> R5.
Novel behavior is not guaranteed; official source non-matches do not imply novelty. An exhaustive proof that no undocumented API exists is not feasible in this timebox.

## Stage gates
**Gate 1 (2026-10-30: static phase):** R0/R1/R2/R3 each PASS, NEGATIVE, or UNDETERMINED with version, hashes, exact witnesses and falsification tests. All ambiguity reason-coded. If no candidate survives, close *timeboxed exploratory MVP* as completed with ZERO new usable APIs, but do **not** mark discovery-success AC as PASS.

**Gate 2 (2026-11-04: device phase, conditional):** If there is an authorized, connected C3 and a safe observational test, collect actual silicon evidence. If Mac/ESP remains offline, mark R4 BLOCKED and do not fabricate or reclassify a simulated test as a hardware PASS.

**Gate 3 (2026-11-06: conclusion):** Commit final report, linked CI logs, exact artifact hashes, all AC statuses, regressions and false-positive audit. Recommend whether to pursue deeper reverse engineering with a newly scoped hypothesis; stop circular name searches.

## Risks & mitigation
- Unknown/peripheral silicon semantics may not be externally documented: timebox source matching; unresolved is legitimate outcome, not a presumed new device function.
- Registered ROM names may refer to trampoline addresses rather than internal ELF implementation: compare name semantics and version, do not treat address difference as novelty.
- Device unavailable or revision mismatch: safe observation stays BLOCKED; static analysis can still close by 2026-10-30 if evidence checks pass.
- Unexpected bugs invalidate evidence: stop promotion, root-cause, rerun negative controls and record revisions in GitHub.
- Research exceeds timebox: re-scope with actual blockers and measured effort instead of silently extending.

## Evidence links
- [Issue #2](https://github.com/mokumaisancho/esp32c3-ir-remote/issues/2)
- [2026-10-22 prior-art handoff JSON](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/state/ROM001_20261022_PRIOR_ART.json)
- [Prior-art gate CI](https://github.com/mokumaisancho/esp32c3-ir-remote/actions/runs/39777111796)
- [ROM machine-byte RMW decoder](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/rom_p0b_two_rmw_bits.py)
- [Bounded CFG register provenance](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/rom_p0a_cfg_defuse.py)
