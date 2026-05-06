use zisk_sdk::build_program;

fn main() {
    // List of guest programs to build
    let programs = [
        "../guests/blake2/program",
        "../guests/bls12_381",
        "../guests/bn254",
        "../guests/diagnostic/program",
        "../guests/keccak/program",
        "../guests/modexp",
        "../guests/poseidon2/program",
        "../guests/revm",
        "../guests/secp256k1",
        "../guests/secp256r1",
        "../guests/sha256/program",
        "../guests/uint256",
        // Add more program paths here as needed
    ];
    // Build the guest programs
    for p in programs {
        build_program(p);
    }
}
