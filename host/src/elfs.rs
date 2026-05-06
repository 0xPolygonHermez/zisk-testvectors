use zisk_sdk::{load_program, GuestProgram};

use crate::cli::Program;

// Statically load the ELF binaries for the guest programs
pub(crate) const ELF_BLAKE2: GuestProgram = load_program!("blake2");
pub(crate) const ELF_BLS12_381: GuestProgram = load_program!("bls12_381");
pub(crate) const ELF_BN254: GuestProgram = load_program!("bn254");
pub(crate) const ELF_DIAGNOSTIC: GuestProgram = load_program!("diagnostic");
pub(crate) const ELF_KECCAK: GuestProgram = load_program!("keccak");
pub(crate) const ELF_MODEXP: GuestProgram = load_program!("modexp");
pub(crate) const ELF_POSEIDON2: GuestProgram = load_program!("poseidon2");
pub(crate) const ELF_REVM: GuestProgram = load_program!("revm");
pub(crate) const ELF_SECP256K1: GuestProgram = load_program!("secp256k1");
pub(crate) const ELF_SECP256R1: GuestProgram = load_program!("secp256r1");
pub(crate) const ELF_SHA256: GuestProgram = load_program!("sha256");
pub(crate) const ELF_UINT256: GuestProgram = load_program!("uint256");
// Add more ELF constants here as needed

pub(crate) fn elf_for(program: Program) -> GuestProgram {
    match program {
        Program::Blake2 => ELF_BLAKE2,
        Program::Bls12_381 => ELF_BLS12_381,
        Program::Bn254 => ELF_BN254,
        Program::Diagnostic => ELF_DIAGNOSTIC,
        Program::Keccak => ELF_KECCAK,
        Program::Modexp => ELF_MODEXP,
        Program::Poseidon2 => ELF_POSEIDON2,
        Program::Revm => ELF_REVM,
        Program::Secp256k1 => ELF_SECP256K1,
        Program::Secp256r1 => ELF_SECP256R1,
        Program::Sha256 => ELF_SHA256,
        Program::Uint256 => ELF_UINT256,
    }
}
