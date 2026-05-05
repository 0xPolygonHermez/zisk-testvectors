use zisk_sdk::build_program;

fn main() {
    // Build the guest programs
    let programs = [
        "./blake2/program",
        "./bls12_381",
        "./bn254",
        "./diagnostic/program",
        "./keccak/program",
        "./modexp",
        "./poseidon2/program",
        "./revm",
        "./secp256k1",
        "./secp256r1",
        "./sha256/program",
        "./uint256",
    ];
    for p in programs {
        build_program(p);
    }
}
