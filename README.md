# ZisK Test Vectors

Test vectors, benchmark programs, and tooling for the [ZisK zkVM](https://github.com/0xPolygonHermez/zisk).

## Structure

```
zisk-testvectors/
├── zisk-programs/ # Guest programs (run inside zkVM)
│ ├── keccak/ # Keccak hash tests
│ ├── sha256/ # SHA256 tests
│ ├── bn254/ # BN254 pairing tests
│ ├── bls12_381/ # BLS12-381 tests
│ ├── secp256k1/ # ECDSA/Schnorr tests
│ └── ...
├── tools/
│ └── testgen/ # Generates syscall test programs
├── eth-client/ # Ethereum client test vectors
└── pessimistic-proof/ # Pessimistic proof tests
```

## Prerequisites

- Rust (stable toolchain)
- [ZisK](https://github.com/0xPolygonHermez/zisk) for building guest programs

## Quick Start

### Build Guest Programs

```bash
cd zisk-programs
cargo-zisk build --release
```

Produces ELF binaries in `target/elf/riscv64ima-zisk-zkvm-elf/release/`.

### Run Tests with Emulator

Use the ZisK emulator to run guest programs:
```bash
cd zisk-programs
ziskemu --elf target/elf/riscv64ima-zisk-zkvm-elf/release/keccak \
        --inputs keccak/inputs/input_keccakf_1.bin -X
```

## Tools

### testgen

Generates comprehensive test programs for ZisK syscalls:

```bash
# Generate all tests (full suite)
cargo run --release -p testgen

# Generate minimal test set (faster)
cargo run --release -p testgen -- --minimal

# Limit tests per category
cargo run --release -p testgen -- -n 10

# Custom output directory
cargo run --release -p testgen -- -o /path/to/output
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.