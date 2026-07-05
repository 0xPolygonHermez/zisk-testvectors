# RISCOF compliance tests

This directory holds the [RISCOF](https://github.com/riscv-software-src/riscof)
architectural-compliance test vectors for ZisK. `riscof_work/` is the
**generated output** of a RISCOF run: for every test it contains the compiled
DUT ELF (`dut/my.elf`) plus the reference signature produced by the Sail RISC-V
model (`ref/Reference-sail_c_simulator.signature`).

The ZisK CI (`pr_emulator.yml` → `tools/emulate_all.sh` in the `zisk` repo)
**consumes** these files; it does not regenerate them. For each `my.elf` it runs:

```sh
ziskemu -e <test>/dut/my.elf -i <empty> -f   # stdout = signature (riscof format)
```

and `diff`s the output against `<test>/ref/Reference-sail_c_simulator.signature`.
Any mismatch fails the job.

Current set: **654 tests** (`rv32i_m/{D,F}`, `rv64i_m/{A,C,D,F,I,M}`).
`rv64i_m/privilege` and `rv64i_m/C/.../cebreak-01` are intentionally excluded /
disabled because ZisK does not implement the traps they exercise
(misaligned-access / `ebreak` / `ecall`).

## Memory-layout dependency (important)

The DUT ELFs are **not** built with `cargo-zisk`. They are compiled from the
`riscv-arch-test` assembly sources with `riscv64-unknown-elf-gcc`, a linker
script (`link.ld`, entry `0x80000000`), and the ZisK compliance macros
(`model_test.h`). Two absolute addresses are baked into `model_test.h` and
**must match the ZisK emulator's memory map** (`zisk` repo, `core/src/mem.rs`):

| Purpose | Constant (`core/src/mem.rs`) | Value | Used in `model_test.h` |
|---|---|---|---|
| ZisK arch-id marker | `ARCH_ID_CSR_ADDR = CSR_ADDR + ARCH_ID_CSR*8` | `0xa040f890` | `RVMODEL_HALT` reads it and compares to `ARCH_ID_ZISK` to choose the `ecall` exit path |
| Signature output | `OUTPUT_ADDR = SYS_ADDR + SYS_SIZE` | `0xa0410000` | `RVMODEL_HALT` copies the signature region here; `ziskemu -f` reads it back |

These values move whenever `SYS_ADDR` changes. `SYS_ADDR = RAM_ADDR +
STACK_SIZE`, so introducing/resizing the stack region shifts both. When they
drift, the tests fall through to the QEMU-style halt (`sw` to `0x100000`), which
is outside the ZisK writable section and **panics the emulator** — every test
then fails. If you change the memory map in `zisk`, recompute the two addresses
and regenerate (below).

> The public `hermeznetwork/ziskof:latest` image ships an outdated
> `model_test.h` (arch-id `0xa0008f12`) and a `RV64IMA`-only `zisk_isa.yaml`.
> The patched copies used to generate this set live in [`env/`](env/); the diffs
> against the image are in [`patches/`](patches/).

## How to regenerate

Prerequisites: Docker, and a checkout of the `zisk` repo.

1. Build the emulator that will produce the DUT signatures (with float support):

   ```sh
   cd <zisk>
   cargo build --release --features float      # -> target/release/ziskemu
   ```

2. Run RISCOF in the ziskof container, overriding the env with the patched files
   from [`env/`](env/) and mounting the freshly built `ziskemu` as `/program`.
   Point the output at a scratch dir (the container writes as root):

   ```sh
   RISCOF=<this-dir>          # zisk-testvectors/riscof
   OUT=/tmp/riscof_regen
   mkdir -p "$OUT"

   docker run --rm \
     -v <zisk>/target/release/ziskemu:/program:ro \
     -v "$RISCOF/env/model_test.h:/workspace/zisk/env/model_test.h:ro" \
     -v "$RISCOF/env/zisk_isa.yaml:/workspace/zisk/zisk_isa.yaml:ro" \
     -v "$OUT:/workspace/output" \
     hermeznetwork/ziskof:latest
   ```

   RISCOF's own DUT-vs-reference report will show many `Failed` lines — that is a
   formatting mismatch of RISCOF's internal comparison and is **not** what the CI
   checks. Verify with the emulator instead (next step).

3. Prune the tests ZisK does not support, matching the committed scope:

   ```sh
   rm -rf "$OUT/riscof_work/rv64i_m/privilege"
   # keep cebreak-01 but disable it so emulate_all.sh (find -name my.elf) skips it:
   mv "$OUT/riscof_work/rv64i_m/C/src/cebreak-01.S/dut/my.elf" \
      "$OUT/riscof_work/rv64i_m/C/src/cebreak-01.S/dut/my.elf.disabled"
   # the newer suite emits ref disassembly files the repo does not track:
   find "$OUT/riscof_work" -name '*.disass' -delete
   ```

4. Verify every ELF passes exactly as the CI does, then copy over `riscof_work/`:

   ```sh
   cd <zisk>
   cargo build --features float                 # debug build, as CI uses
   bash ./tools/emulate_all.sh "$OUT/riscof_work"   # expect: 654 passed, 0 failed
   rm -rf "$RISCOF/riscof_work" && cp -r "$OUT/riscof_work" "$RISCOF/riscof_work"
   ```

## The patches

See [`patches/`](patches/) for the unified diffs, and [`env/`](env/) for the
full patched files that step 2 mounts.

- [`patches/model_test.h.patch`](patches/model_test.h.patch)
  - signature destination `la t2, tohost` → `li t2, 0xa0410000` (`OUTPUT_ADDR`)
  - arch-id read `li t1, 0xa0008f12` → `li t1, 0xa040f890` (`ARCH_ID_CSR_ADDR`)
- [`patches/zisk_isa.yaml.patch`](patches/zisk_isa.yaml.patch)
  - `ISA: RV64IMA` → `RV64IMAFDCZicsr` (adds C/D/F coverage)
  - `misa.reset-val 0x80001101` → `0x8000112D`, extension bitmask `0x0001101` → `0x000112D`

For a fix that survives future layout changes, prefer reading the arch-id via
`csrr` (from `marchid`) and deriving the output address relative to a known
symbol, so neither address is hardcoded.

Long term these patches should be upstreamed into the `hermeznetwork/ziskof`
image source so the published image regenerates a correct set out of the box.
