# ROM-003 B1: RV32C pre-disassembly superset-CFG POC verified

Date: 2026-10-24 JST. Original objective: discover an independently callable, previously unpublished ESP32-C3 ROM function/capability. **This document does not claim discovery.**

## Reused information / provenance

- Authoritative existing execution queue: [ROM003_EXECUTION_QUEUE_V2.json](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/state/ROM003_EXECUTION_QUEUE_V2.json).
- Espressif three-revision ROM image SHA256 `caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46`; same E0 byte-only raw candidate and E2 sealed ELF ground truth, independent GitHub Actions jobs.
- Previous exact witness audit: 252 unclaimed target PCs, 260 raw call-source records; 11 records at the second halfword of actual 32-bit named code, 249 outside known STT_FUNC extents; 0 previously authenticated call paths.
- **Research**: Nguyen et al., [*Analyzing Bytes: Pre-Disassembly Static Binary Analysis*, PACMPL PLDI 2026](https://doi.org/10.1145/3808292), [source](https://github.com/nhuhuan/amace). The public Amace implementation/benchmark assumes x86-64, 16 GiB RAM and 100 GiB storage and is **not an RV32C implementation**. We did not download its Docker artifact. RISC-V [C ISA compressed instruction specification](https://docs.riscv.org/reference/isa/unpriv/c-st-ext) documents independent halfword instruction alignment and RV32-only C.JAL.

## Implemented bounded POC

- [rom_rv32c_superset_reverse_poc.py](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/rom_rv32c_superset_reverse_poc.py) constructs a decode at **every 16-bit boundary** of the E0 publicly extractable executable sections, not just prior named ELF function starts. It builds a superset of local direct machine-control transfers and source predecessor pointers; unknown indirect jumps and privileged trap/return jumps have no invented targets. CSRRS and CSRRW, in contrast, fall through normally.
- Boot-root and separately evaluator-only sealed STT_FUNC entrypoint-seeded graph reachability are computed, **distinguishing verified machine edges from merely conditional named-function-root assumptions**. For each of the 260 exact machine byte CALL references a reversed predecessor chain is reconstructed only if one exists. The E1 candidate job does NOT receive sealed symbols.
- Explicit negative regression tests include: 32-bit-instruction midpoint containing an apparently decodable C.JAL, return barrier, CSR normal fallthrough versus MRET stop, wrong source raw, wrong ROM rev, fake symbol leaks, speculative symbol-root paths vs boot-root paths. 12/12 B1 tests PASS.
- **Scope limitation:** This is a **minimal Amace-inspired superset CFG plus predecessor-path analysis**. We did NOT port the Amace global backward SP-depth, callee-saved register preservation or invalid dereference analyses. We do NOT claim its O(n) complexity or accuracy. Superset edges can include code-looking data; graph reachability is a static overapproximation, not actual silicon execution. A missing path is a bounded negative result only.

## Three-revision actual CI measurements

**[Final GitHub Actions run 40091304811 — PASS](https://github.com/mokumaisancho/esp32c3-ir-remote/actions/runs/40091304811)**

| Measurement | rev0 | rev101 | rev3 |
|---|---:|---:|---:|
| Candidate halfword instruction nodes | 164,070 | 167,340 | 165,261 |
| Superset directed edges | 170,299 | 173,715 | 171,568 |
| Boot-rooted static reachable nodes | 4,753 | 4,743 | 4,746 |
| Named-function-entry-seeded potential reachable nodes | 62,477 | 64,417 | 64,087 |
| Number of raw candidate source witnesses | 81 | 77 | 102 |
| Witness source PCs with newly supported boot-rooted path | **0** | **0** | **0** |
| Witness source PCs with newly supported named-symbol-rooted static path | **0** | **0** | **0** |

Total witness source records **260**, supported new paths **0**. Number of independently proven new callable ROM APIs **0**.

CI tests: E1 **14**, E2 strict boundary **11**, extent triage **6**, previous source witness audit **11**, B1 **12**: **54/54 PASS**. Additional automated integrity gate verifies 260 conserved source records and boot-graph reachability greater than 4,000, avoiding the initial false-short boot graph.

GitHub Actions artifact **12558309102**, sha256 **69d976260c31edcdc48a3b62b13489e28b3ca5aac25c714b38ead91c04a0f0c2**, includes `rv32c_superset_reverse.json` with **all 260 source decisions** plus SHA logs.

### Found and corrected an important model error

First POC run [40090932547](https://github.com/mokumaisancho/esp32c3-ir-remote/actions/runs/40090932547) traversed only **2 nodes** from boot per ROM: the initial model incorrectly treated **all CSR instructions** as terminal. RISC-V CSRRW/CSRRS/CSRRC are normally sequential; only privileged transfer/trap encodings are barriers in this local model. Corrected and tested separately; final boot reach **4,753 / 4,743 / 4,746**, identical to the earlier E1 decoder counts, and 12 test controls passed. Full three-job CI rerun PASS.

## Evaluation / decision

**GO for POC reproducibility, NO-GO for additional distance/CFG scoring on these same 260 witnesses.** The new conservative superset graph constructs no independently rooted **incoming edge** to any of the unclassified raw-link sources; the previously unknown direct-edge graph coverage is the actual limitation.

The Amace backward SP/register consistency checks can invalidate implausible paths, but cannot by themselves produce a missing independent JALR target, exception/callback entry or actual hardware execution proof. Without a new edge or an authorized runtime PC trace, a full Amace port is high cost and cannot improve the current target-reachability coverage.

### Next evidence dependency (not claimed executed)

A genuinely new entry route must derive from **indirect dispatch/interrupt/external callable ROM entry** not yet modeled. For an emulation-based route, Espressif [esp-emulator](https://github.com/espressif/esp-emulator) supports ESP32-C3 and explicit `--rom` overrides, GDB port and a Perfetto task trace, **but its README notes ROM-function stubs/intercepts**. Thus a launch or task-timeline alone cannot independently verify execution of a particular ROM machine PC; the appropriate minimal POC requires verified ROM-CPU-PC tracing with HLE interception either disabled/identified or excluded from claims. Firmware image and runtime instrumentation compatibility remain unverified.

**Stop status:** original ESP32C3-ROM-001 stays BLOCKED, 0 novel usable ROM API; freeze new shortest/longest distance heuristics until independent edges or a silicon-/emulator-verified guest-PC source appear. Do not treat Amace superset as a successful ROM API discovery.
