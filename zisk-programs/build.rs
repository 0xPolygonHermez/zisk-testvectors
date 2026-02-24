use zisk_sdk::build_program;

fn main() {
    build_program("add256/program");
    build_program("arith_eq_384_gen/program");
    build_program("arith_eq_gen/program");
    build_program("bls12_381/program");
    build_program("bn254/program");
    build_program("fcall/program");
    build_program("fcall_msb/program");
    build_program("keccak/program");
    build_program("modexp/program");
    build_program("prover_killers/program");
    build_program("sha256/program");
    build_program("poseidon2/program");
    // build_program("revm/program");
    build_program("secp256k1/program");
    build_program("secp256r1/program");

}
