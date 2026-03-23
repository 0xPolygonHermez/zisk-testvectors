#![no_main]
ziskos::entrypoint!(main);

mod blake2f;
mod bls12_381;
mod bn254;
mod common;
mod keccak256;
mod modexp;
mod secp256k1;
mod secp256r1;
mod sha256;

use blake2f::blake2f_tests;
use bls12_381::{
    bls12_381_g1_add_tests, bls12_381_g1_msm_tests, bls12_381_g1_mul_tests, bls12_381_g2_add_tests,
    bls12_381_g2_msm_tests, bls12_381_g2_mul_tests, bls12_381_map_fp2_to_g2_tests,
    bls12_381_map_fp_to_g1_tests, bls12_381_pairing_tests, bls12_381_point_evaluation_tests,
};
use bn254::{ecadd_tests, ecmul_tests, ecpairing_tests};
use keccak256::keccak256_tests;
use modexp::modexp_tests;
use secp256k1::{ecrecover_precompile_tests, ecrecover_tx_tests};
use secp256r1::p256_verify_tests;
use sha256::sha256_tests;

use guest_reth::CustomEvmCrypto;

// TODO: Add non-precompile testsdata

fn main() {
    let crypto = CustomEvmCrypto::default();

    // Hashes
    blake2f_tests(&crypto);
    sha256_tests(&crypto);
    keccak256_tests();

    // Modular exponentiation
    modexp_tests(&crypto);

    // Secp256k1
    ecrecover_tx_tests(&crypto);
    ecrecover_precompile_tests(&crypto);

    // Secp256r1
    p256_verify_tests(&crypto);

    // BN254
    ecadd_tests(&crypto);
    ecmul_tests(&crypto);
    ecpairing_tests(&crypto);

    // BLS12-381
    bls12_381_g1_add_tests(&crypto);
    bls12_381_g1_mul_tests(&crypto);
    bls12_381_g1_msm_tests(&crypto);
    bls12_381_g2_add_tests(&crypto);
    bls12_381_g2_mul_tests(&crypto);
    bls12_381_g2_msm_tests(&crypto);
    bls12_381_map_fp_to_g1_tests(&crypto);
    bls12_381_map_fp2_to_g2_tests(&crypto);
    bls12_381_pairing_tests(&crypto);
    bls12_381_point_evaluation_tests(&crypto);
}
