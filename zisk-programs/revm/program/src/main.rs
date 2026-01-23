#![no_main]
ziskos::entrypoint!(main);

mod bls12_381;
mod bn254;
mod modexp;
mod secp256k1;
mod sha256;

use bls12_381::bls12_381_tests;
use bn254::bn254_tests;
use modexp::modexp_tests;
use secp256k1::secp256k1_tests;
use sha256::sha256_tests;

use crypto::CustomEvmCrypto;

fn main() {
    let crypto = CustomEvmCrypto::default();

    bls12_381_tests(&crypto);
    bn254_tests(&crypto);
    modexp_tests(&crypto);
    secp256k1_tests(&crypto);
    sha256_tests(&crypto);
}
