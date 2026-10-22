# ROM-002: ESP32-C3 ROM RMW trace oracle — software-model compatibility

Original ROM API discovery task: [ROM-001](https://github.com/mokumaisancho/esp32c3-ir-remote/issues/2). New emulator-oriented implementation: [ROM-002](https://github.com/mokumaisancho/esp32c3-ir-remote/issues/4).

## Why pivot

The ROM-001 snapshot of 152 initially unlisted function names yielded **128 official active linker names, 16 official documented-but-commented names, and eight matches in other public sources**. No newly usable ROM APIs are independently certified. Two pin-specific RF/Wi-Fi register functions are known only to the *static machine-code RMW effect* level, not actual device field semantics.

Therefore, speculative *new silicon feature* hunting is stopped in favor of **reusable ROM-to-emulator differential compatibility testing**. The full 3-revision ELF scan and hashes remain in git and GitHub Action archives. This change does not mean the absence of any undocumented C3 function was proven.

Espressif's `esp-emulator` already supports C3 ROM selection and some ROM function stubs. The Espressif QEMU fork can load a ROM via `-bios`. Both could benefit from concrete register effects and revision-specific regression data, but the oracle does **not** automatically integrate with their current trace formats.

References:
- https://github.com/espressif/esp-emulator/blob/main/README.md
- https://github.com/espressif/esp-toolchain-docs/blob/main/qemu/esp32c3/README.md
- https://github.com/espressif/esp-rom-elfs

## New executable MVP

```sh
python -m unittest discover -s rom_automation -p 'test_rom_mmio_trace_oracle.py' -v

python rom_automation/rom_mmio_trace_oracle.py \
  --strict \
  --trace rom_automation/fixtures/rom_mmio_synthetic_trace_v1.json \
  --output /tmp/rom002_verdict.json
```

This runs with Python standard library only. No RISC-V compiler, hardware, emulator, API keys, or Mac storage required.

### Input contract

`ROM002_MMIO_PAIR_TRACE_V1`, strict keys only:

```json
{
  "schema": "ROM002_MMIO_PAIR_TRACE_V1",
  "source_kind": "synthetic",
  "samples": [
    {
      "sample_id": "rev101_wifi_example",
      "case": "rev101_wifi",
      "events": [
        {"op": "read", "pc": "0x40045474", "address": "0x60033c00", "value": "0x12345678"},
        {"op": "write", "pc": "0x4004547c", "address": "0x60033c00", "value": "0x123456f8"}
      ]
    }
  ]
}
```

There are two cases, which **must not be used interchangeably**:

| Case | ROM revision | Observed ROM function | MMIO address | Read PC | Write PC | Expected new register value |
|---|---|---|---|---|---|---|
| `rev0_fe` | rev0 | `rom_phy_xpd_rf` | `0x600061c4` | `0x4003ba76` | `0x4003ba88` | `(OLD & 0xffff0000) | 0x5555` |
| `rev101_wifi` | rev101 | `wdev_mac_wakeup` | `0x60033c00` | `0x40045474` | `0x4004547c` | `OLD | 0xf0` |

Only these *specific read/write pairs*, not the whole containing firmware function, are currently modeled. An imported capture with a different PC, revision, address, event order or 32-bit range fails closed. A read/write pair with incorrect resulting bits is marked `TRACE_CONTRADICTS_ROM_RMW`. Pass `--strict` to return exit code 2 on contradictions, or exit code 3 for invalid JSON/schema. The tool always writes its decision/report for valid event collections.

`source_kind` (synthetic, emulator, silicon, other) is **untrusted metadata**. Even if a user puts `"silicon"`, output fields `input_source_kind_independently_attested`, `hardware_behavior_verified` and `actual_emulator_execution_verified` remain `false`. Real-hardware attribution must be established independently through signed/validated capture provenance and a genuine paired trace, not a JSON claim.

### How to integrate a real emulator later

1. Run firmware under a revision-matched emulator whose MMIO event trace can expose guest ROM PC, address, operand value and read/write order. Some emulators may need instrumented trace hooks; a Perfetto task-timeline alone does not satisfy this event schema.
2. Transform *real* emulator events into the strict JSON pairs above, recording which emulator build, ROM ELF digest, firmware digest and extraction method produced the trace in a separate authenticated manifest. Do not insert model-predicted values into the observed values.
3. Check the transformed capture with `--strict`; compare raw events, preserving capture, parser and oracle hashes as CI artifacts.
4. Inject an independent wrong-value / swapped-revision trace to ensure the test can fail. Count emulator E2E PASS only after the real emulator run and extraction are actually demonstrated.

## Completed tests and reproduction

- [GitHub Actions ROM-002 pass, 20 isolated tests and four synthetic events](https://github.com/mokumaisancho/esp32c3-ir-remote/actions/runs/39866163538)
- [Oracle implementation](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/rom_mmio_trace_oracle.py)
- [Regression/negative cases](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/test_rom_mmio_trace_oracle.py)
- [Synthetic inputs](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/fixtures/rom_mmio_synthetic_trace_v1.json)
- Verified reference: [machine-byte RMW decoder](https://github.com/mokumaisancho/esp32c3-ir-remote/blob/main/rom_automation/rom_p0b_two_rmw_bits.py)

**Present limits:** 0 new silicon APIs, 0 physical device tests, 0 real emulator MMIO capture imports; only 2 precisely delimited ROM RMW sites and an input schema validated. ROM-002 demonstrates a *new software validation capability*, not a new capability of the ESP32-C3 chip.
