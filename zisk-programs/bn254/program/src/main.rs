#![no_main]
#![cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
ziskos::entrypoint!(main);

mod constants;
mod cyclotomic;
mod ecadd;
mod ecmul;
mod ecpairing;
mod final_exp;
mod fp;
mod fp12;
mod fp2;
mod fp6;
mod pairing;
mod twist;

use cyclotomic::cyclotomic_tests;
use ecadd::{ecadd_invalid_tests, ecadd_valid_tests};
use ecmul::{ecmul_invalid_tests, ecmul_valid_tests};
use ecpairing::{ecpairing_invalid_tests, ecpairing_valid_tests};
use final_exp::final_exp_tests;
use fp::fp_tests;
use fp12::fp12_tests;
use fp2::fp2_tests;
use fp6::fp6_tests;
use pairing::{pairing_invalid_tests, pairing_valid_tests};
use twist::twist_tests;

fn main() {
    // Ecadd
    ecadd_valid_tests();
    ecadd_invalid_tests();

    // Ecmul
    ecmul_valid_tests();
    ecmul_invalid_tests();

    // Ecpairing
    ecpairing_valid_tests();
    ecpairing_invalid_tests();

    // Fp
    fp_tests();

    // Fp2
    fp2_tests();

    // Fp6
    fp6_tests();

    // Fp12
    fp12_tests();

    // Twist
    twist_tests();

    // Cyclotomic
    cyclotomic_tests();

    // Final exponentiation
    final_exp_tests();

    // Pairing
    pairing_valid_tests();
    pairing_invalid_tests();
}
