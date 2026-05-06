# ZisK Test Vectors

Test vectors and benchmark programs for the [ZisK zkVM](https://github.com/0xPolygonHermez/zisk).

## Structure

```
zisk-testvectors/
├── host/              # Host runner
├── guests/            # Guest programs (run inside ZisK)
├── tools/
│   └── testgen/       # Generates syscall test programs
├── eth-client/        # Ethereum client test vectors
└── pessimistic-proof/ # Pessimistic proof tests
```

## Prerequisites

- [Rust](https://rust-lang.org/tools/install/) (stable toolchain)
- [ZisK](https://github.com/0xPolygonHermez/zisk) installed for guest builds

## Quick Start

The [`host`](host/) crate is the main entry point. It compiles every guest
under [`guests/`](guests/) and runs them against their inputs.

```bash
# Run every guest under the assembly backend
cargo run -p host --release

# Run only blake2 + keccak under the emulator
cargo run -p host --release -- -l -i blake2,keccak

# Verify constraints (proving key required)
cargo run -p host --release -- \
    -a verify-constraints \
    -k /path/to/proving-key
```

See [`host/README.md`](host/README.md) for the full CLI reference and
the per-program input convention.

To skip rebuilding guests when iterating on host code:

```bash
SKIP_GUEST_BUILD=1 cargo build -p host
```

## Tools

### testgen

Generates test programs for ZisK syscalls:

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
