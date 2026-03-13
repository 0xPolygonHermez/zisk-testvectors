# Zisk Test Vectors

Test vectors, benchmark programs, and tooling for the [Zisk zkVM](https://github.com/0xPolygonHermez/zisk).

## Prerequisites

- Rust (stable toolchain)
- [ZisK](https://github.com/0xPolygonHermez/zisk) for building guest programs

## Building

### Guest Programs

```bash
cd zisk-programs

cargo-zisk build --release
```

This produces ELF binaries in `target/riscv64ima-zisk-zkvm-elf/release/`.

### Host Tools

```bash
cargo build --release
```

## Running Tests

Use the Zisk emulator to run guest programs:

```bash
cd zisk-programs

ziskemu --elf target/riscv64ima-zisk-zkvm-elf/release/keccak \
        --inputs keccak/inputs/input_keccakf_1.bin -X
```

## Tools

### program_gen

Generates test programs for precompiles (arith_eq, keccak, sha256, etc.):

```bash
cargo run --release -p program_gen -- --help
```

### prover_killers

Generates stress tests from JSON input files (e.g., modexp edge cases):

```bash
cargo run --release -p prover_killers -- --help
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.