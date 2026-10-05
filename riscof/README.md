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

Current set: **704 tests** (`rv32i_m/{D,F}`, `rv64i_m/{A,B,C,D,F,I,K,M}`).
`rv64i_m/B` (44 tests) covers the bit-manipulation extensions **Zba, Zbb, Zbc,
Zbs**; `rv64i_m/K` (6 tests: `brev8`, `pack`, `packh`, `packw`, `xperm4`,
`xperm8`) covers the bit-manipulation-for-crypto extensions **Zbkb, Zbkc, Zbkx**.
The remaining `rv64i_m/K` crypto tests (AES/SHA/SM3/SM4) are not selected because
ZisK does not implement those extensions.
`rv64i_m/privilege` and `rv64i_m/C/.../cebreak-01` are intentionally excluded /
disabled because ZisK does not implement the traps they exercise
(misaligned-access / `ebreak` / `ecall`).

## Program headers: the code segment is `PF_X` only

The ELFs carry two `PT_LOAD` segments: the code at `0x80000000` (`PF_X`, no
`PF_R`) and the data at `0xa0010000` (`PF_RW`). ZisK loads a `PF_X | PF_R`
("execute-and-read") code segment **twice** — transpiled as instructions, and
again as ROM read-only data — and prints a warning that `PF_X`-only is faster.
None of these tests keep read-only data in ROM (test data, the signature area
and `.tohost` all live in RAM; no ELF has a `.rodata` section, and no ELF has a
data symbol in the ROM window), so an execute-and-not-read code segment is both
correct and cheaper.

This comes from the `PHDRS` block in [`env/link.ld`](env/link.ld) (flag values
follow ZisK's own `ziskbuild/zisk_linker_script.ld`: `1 = X`, `4 = R`, `6 = RW`).
Because the script assigns `.rodata` to the X-only segment, it also asserts that
`.rodata` is empty — a future test that emits read-only data must be given its
own `PT_LOAD FLAGS(4)` segment rather than reading zeros at run time.

The committed set was retrofitted rather than relinked, with
[`tools/elf_x_only.py`](tools/elf_x_only.py), which clears `PF_R` on the
executable `PT_LOAD` of each `my.elf` and touches nothing else (one byte per
file). A fresh RISCOF run with `env/link.ld` produces the same ELFs directly:
relinking a test both ways yields images that differ only in that `p_flags`
byte, and identical signatures.

## Exit code: `RVMODEL_HALT` exits with 0

ZisK ends an execution as failed when its exit call (`ecall` with `a7 = 93`)
carries a nonzero exit code in `a0`, and refuses to prove it. The ZisK exit path
of `RVMODEL_HALT` used to leave `a0` as the test left it, so most tests ended as
failed; [`env/model_test.h`](env/model_test.h) now sets `li a0, 0` before the
`ecall`.

The committed set was retrofitted with
[`tools/elf_exit_code_zero.py`](tools/elf_exit_code_zero.py) rather than
regenerated. In each ELF, the `j loop` that follows the QEMU exit store (never
reached under QEMU, since that store ends the run) becomes `li a0, 0` of the same
size, and the `beq` that selects the ZisK path is retargeted to it, so ZisK runs
`li a0, 0; li a7, 93; ecall`. Nothing moves and no other byte changes; the
reference signatures are unaffected. A fresh RISCOF run with `env/model_test.h`
puts the `li a0, 0` at the start of `zisk_exit` instead, with the same effect.

## Memory-layout dependency (important)

The DUT ELFs are **not** built with `cargo-zisk`. They are compiled from the
`riscv-arch-test` assembly sources with `riscv64-unknown-elf-gcc`, a linker
script ([`env/link.ld`](env/link.ld), entry `0x80000000`), and the ZisK
compliance macros (`model_test.h`). Two absolute addresses are baked into
`model_test.h` and
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
> `model_test.h` (arch-id `0xa0008f12`), a `RV64IMA`-only `zisk_isa.yaml`, and a
> `link.ld` without a `PHDRS` block (so its code segment comes out `PF_X | PF_R`).
> The patched copies used to generate this set live in [`env/`](env/); the diffs
> against the image are in [`patches/`](patches/). The `zisk_isa.yaml` ISA string
> now enables the bit-manipulation extensions
> (`RV64IMAFDCZicsr_Zba_Zbb_Zbc_Zbkb_Zbkc_Zbkx_Zbs`), which is what makes RISCOF
> select the `rv64i_m/{B,K}` tests.

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
     -v "$RISCOF/env/link.ld:/workspace/zisk/env/link.ld:ro" \
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
   # sanity check: with env/link.ld mounted the code segments are already PF_X
   # only, so this must report "0 modified" (it retrofits them otherwise):
   "$RISCOF/tools/elf_x_only.py" $(find "$OUT/riscof_work" -name 'my.elf*')
   # likewise, with env/model_test.h mounted RVMODEL_HALT already exits with 0,
   # so this must report "0 modified" too:
   "$RISCOF/tools/elf_exit_code_zero.py" $(find "$OUT/riscof_work" -name 'my.elf*')
   ```

4. Verify every ELF passes exactly as the CI does, then copy over `riscof_work/`:

   ```sh
   cd <zisk>
   cargo build --features float                 # debug build, as CI uses
   bash ./tools/emulate_all.sh "$OUT/riscof_work"   # expect: 704 passed, 0 failed
   rm -rf "$RISCOF/riscof_work" && cp -r "$OUT/riscof_work" "$RISCOF/riscof_work"
   ```

   To run `ziskemu` over the `rv64i_m/{B,K}` ELFs, build it with the
   bit-manipulation feature enabled (`--features float,zbxx_soft` or
   `--features float,zbxx_native`); a plain `--features float` build panics with
   `found invalid riscv_instruction.inst_name=add.uw`.

### Note: regenerating the bit-manipulation (`rv64i_m/{B,K}`) tests

The stock `hermeznetwork/ziskof:latest` image cannot produce these tests as-is.
The `rv64i_m/{B,K}` set in this repo was generated by running RISCOF against a
local `ziskof` checkout with three adjustments; fold the same changes into the
image (or a local run) to reproduce them:

- **Toolchain:** the Zb* instructions need `riscv*-gcc` **≥ 11** (GCC 10 reports
  `unsupported ISA subset 'z'`). The Sail reference model must likewise be built
  with bit-manipulation support (recent `sail-riscv` enables it by default).
- **`ziskof` DUT and Reference plugins:** the compile `-march` is taken verbatim
  from each test's `RVTEST_ISA`, e.g. `RV64IZbb_Zbkb`. GCC needs an underscore
  between the base ISA and the first `Z` extension (`rv64i_zbb_zbkb`), so insert
  one before the march is passed to the compiler:
  `march = re.sub(r'(?<=[a-z0-9])(z)', r'_\1', march)`.
- **`riscof` suite:** the committed set was generated from `riscv-arch-test`
  commit `b91f98f3` (see `commit_id` in `test_list.yaml`); the `B`/`K` sources at
  that commit were used so the new tests match the rest of the set.

## The patches

See [`patches/`](patches/) for the unified diffs, and [`env/`](env/) for the
full patched files that step 2 mounts.

- [`patches/model_test.h.patch`](patches/model_test.h.patch)
  - signature destination `la t2, tohost` → `li t2, 0xa0410000` (`OUTPUT_ADDR`)
  - arch-id read `li t1, 0xa0008f12` → `li t1, 0xa040f890` (`ARCH_ID_CSR_ADDR`)
  - `li a0, 0` before the ZisK exit `ecall`, so the exit code is 0 (see above)
- [`patches/link.ld.patch`](patches/link.ld.patch)
  - adds a `PHDRS` block so the code segment is `PF_X` only instead of
    `PF_X | PF_R` (see the program-headers section above), plus the `.rodata`
    emptiness assert
- [`patches/zisk_isa.yaml.patch`](patches/zisk_isa.yaml.patch)
  - `ISA: RV64IMA` → `RV64IMAFDCZicsr_Zba_Zbb_Zbc_Zbkb_Zbkc_Zbkx_Zbs` (adds C/D/F
    and the Zb* bit-manipulation coverage)
  - `misa.reset-val 0x80001101` → `0x800000000000112D`, extension bitmask
    `0x0001101` → `0x000112D`. The reset value must carry `MXL=2` in bits
    `[63:62]` for RV64 (the old `0x8000112D` put it in bit 31, RV32-style, which
    newer `riscv-config` correctly rejects); the Zb* extensions add no `misa`
    bits, so the `[25:0]` bitmask is unchanged.

For a fix that survives future layout changes, prefer reading the arch-id via
`csrr` (from `marchid`) and deriving the output address relative to a known
symbol, so neither address is hardcoded.

Long term these patches should be upstreamed into the `hermeznetwork/ziskof`
image source so the published image regenerates a correct set out of the box.
