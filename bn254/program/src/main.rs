#![no_main]
ziskos::entrypoint!(main);

mod constants;
mod cyclotomic;
mod ecadd;
mod ecmul;
mod fp;
mod fp12;
mod fp2;
mod fp6;
mod twist;

use cyclotomic::cyclotomic_tests;
use ecadd::{ecadd_invalid_tests, ecadd_valid_tests};
use ecmul::{ecmul_invalid_tests, ecmul_valid_tests};
use fp::fp_tests;
use fp12::fp12_tests;
use fp2::fp2_tests;
use fp6::fp6_tests;
use twist::twist_tests;

fn main() {
    // Ecadd
    ecadd_valid_tests();
    ecadd_invalid_tests();

    // Ecmul
    ecmul_valid_tests();
    ecmul_invalid_tests();

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
}
