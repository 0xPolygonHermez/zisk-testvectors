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
mod u256;

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
use u256::{add_tests, div_tests, modular_tests, mul_tests, pow_tests};

use guest_reth::CustomEvmCrypto;

// TODO: Add non-precompile testsdata

fn main() {
    let reth_crypto = CustomEvmCrypto::default();

    // TODO: It does not work with hints [Not Implemented]
    // U256
    add_tests();
    div_tests();
    modular_tests();
    mul_tests();
    pow_tests();

    // Hashes
    blake2f_tests(&reth_crypto);
    sha256_tests(&reth_crypto);
    keccak256_tests();

    // Modular exponentiation
    modexp_tests(&reth_crypto);

    // Secp256k1
    ecrecover_tx_tests(&reth_crypto);
    ecrecover_precompile_tests(&reth_crypto);

    // Secp256r1
    p256_verify_tests(&reth_crypto);

    // BN254
    ecadd_tests(&reth_crypto);
    ecmul_tests(&reth_crypto);
    ecpairing_tests(&reth_crypto); // TODO: It does not work with hints [Hints too large]

    // BLS12-381
    bls12_381_g1_add_tests(&reth_crypto);
    bls12_381_g1_mul_tests(&reth_crypto);
    bls12_381_g1_msm_tests(&reth_crypto); // TODO: It does not work with hints [Hints too large]
    bls12_381_g2_add_tests(&reth_crypto);
    bls12_381_g2_mul_tests(&reth_crypto);
    bls12_381_g2_msm_tests(&reth_crypto); // TODO: It does not work with hints [Hints too large]
    bls12_381_map_fp_to_g1_tests(&reth_crypto);
    bls12_381_map_fp2_to_g2_tests(&reth_crypto);
    bls12_381_pairing_tests(&reth_crypto); // TODO: It does not work with hints [Hints too large]
    bls12_381_point_evaluation_tests(&reth_crypto);
}
