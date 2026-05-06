use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// ZisK Testvectors Host — runs guest programs against an input.
#[derive(Parser, Debug)]
#[command(name = "host")]
#[command(about = "Emulate or verify-constraints for ZisK testvectors guest programs")]
#[command(version)]
pub struct Cli {
    /// Action to perform
    #[arg(short, long, value_enum, default_value = "emulate")]
    pub action: Action,

    /// Programs to include (comma-separated). Defaults to all.
    #[arg(short = 'i', long, value_enum, value_delimiter = ',')]
    pub include_programs: Vec<Program>,

    /// Programs to exclude (comma-separated). Applied after include.
    #[arg(short = 'x', long, value_enum, value_delimiter = ',')]
    pub exclude_programs: Vec<Program>,

    /// Use emulator backend instead of assembly.
    #[arg(short = 'l', long, default_value_t = false)]
    pub emulator: bool,

    /// Override path to the proving key.
    #[arg(short = 'k', long)]
    pub proving_key: Option<PathBuf>,

    /// Unlock mapped memory for asm backend (ignored if --emulator).
    #[arg(long, conflicts_with = "emulator", default_value_t = false)]
    pub unlock_mapped_memory: bool,

    /// Use GPU acceleration (verify-constraints only)
    #[arg(long, default_value_t = false)]
    pub gpu: bool,
}

impl Cli {
    /// Resolve the set of programs to run from `--include-programs` / `--exclude-programs`.
    ///
    /// Empty include = all. Excludes are applied after includes.
    pub fn resolve_programs(&self) -> Vec<Program> {
        let base: Vec<Program> = if self.include_programs.is_empty() {
            Program::ALL.to_vec()
        } else {
            self.include_programs.clone()
        };
        base.into_iter().filter(|p| !self.exclude_programs.contains(p)).collect()
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, serde::Serialize)]
pub enum Action {
    /// Run the program in the executor.
    Emulate,
    /// Verify constraints for the given input.
    VerifyConstraints,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Program {
    Blake2,
    #[value(name = "bls12_381")]
    Bls12_381,
    Bn254,
    Diagnostic,
    Keccak,
    Modexp,
    Poseidon2,
    Revm,
    Secp256k1,
    Secp256r1,
    Sha256,
    Uint256,
}

impl Program {
    pub const ALL: &'static [Program] = &[
        Program::Blake2,
        Program::Bls12_381,
        Program::Bn254,
        Program::Diagnostic,
        Program::Keccak,
        Program::Modexp,
        Program::Poseidon2,
        Program::Revm,
        Program::Secp256k1,
        Program::Secp256r1,
        Program::Sha256,
        Program::Uint256,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Program::Blake2 => "blake2",
            Program::Bls12_381 => "bls12_381",
            Program::Bn254 => "bn254",
            Program::Diagnostic => "diagnostic",
            Program::Keccak => "keccak",
            Program::Modexp => "modexp",
            Program::Poseidon2 => "poseidon2",
            Program::Revm => "revm",
            Program::Secp256k1 => "secp256k1",
            Program::Secp256r1 => "secp256r1",
            Program::Sha256 => "sha256",
            Program::Uint256 => "uint256",
        }
    }

    /// Convention path: `<workspace>/guests/<name>/inputs`.
    pub fn inputs_dir(self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("guests")
            .join(self.name())
            .join("inputs")
    }
}