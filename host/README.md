# Host

CLI for running ZisK guest programs against their test inputs. Supports two
actions: `emulate` (run in the executor) and `verify-constraints` (run the
constraint checker).

## Build

```bash
cargo build -p host --release
```

The build script in [`build.rs`](build.rs) compiles each guest crate under
[`../guests/`](../guests/) into a ZisK ELF. To skip rebuilding guests when
iterating on host code only:

```bash
SKIP_GUEST_BUILD=1 cargo build -p host
```

## Usage

```bash
cargo run -p host --release -- [OPTIONS]
```

### Options

| Flag                         | Default    | Description                                                          |
| ---------------------------- | ---------- | -------------------------------------------------------------------- |
| `-a, --action <ACTION>`      | `emulate`  | `emulate` or `verify-constraints`                                    |
| `-i, --include-programs <P>` | all        | Comma-separated programs to include                                  |
| `-x, --exclude-programs <P>` | none       | Comma-separated programs to exclude (applied after include)          |
| `-l, --emulator`             | off        | Use the emulator backend instead of assembly                         |
| `-k, --proving-key <PATH>`   | SDK default | Path to the proving key (required for `verify-constraints`)         |
| `--unlock-mapped-memory`     | off        | Unlock mapped memory for the asm backend (ignored with `--emulator`) |
| `--gpu`                      | off        | Use GPU acceleration (`verify-constraints` only)                     |

### Programs

`blake2`, `bls12_381`, `bn254`, `diagnostic`, `keccak`, `modexp`, `poseidon2`,
`revm`, `secp256k1`, `secp256r1`, `sha256`, `uint256`.

## Inputs

Each program looks for inputs in `../guests/<program>/inputs/*.bin`. If the
directory exists and contains `.bin` files, every file is run; if it doesn't
exist (or is empty), the program runs once with empty stdin.

| Has inputs                          | No inputs                                                  |
| ----------------------------------- | ---------------------------------------------------------- |
| `blake2`, `keccak`, `poseidon2`, `sha256` | `bls12_381`, `bn254`, `diagnostic`, `modexp`, `revm`, `secp256k1`, `secp256r1`, `uint256` |

## Examples

Emulate everything:

```bash
cargo run -p host --release
```

Emulate two programs:

```bash
cargo run -p host --release -- -i blake2,keccak
```

Verify constraints for everything except `revm`:

```bash
cargo run -p host --release -- \
  -a verify-constraints \
  -k /path/to/proving-key \
  -x revm
```

Use the emulator backend:

```bash
cargo run -p host --release -- -l
```

## Exit codes

`0` if every (program, input) pair passed; `1` if any failed. The summary line
at the end reports `passed`/`failed` counts.