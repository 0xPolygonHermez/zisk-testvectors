#![no_main]
ziskos::entrypoint!(main);

mod constants;
mod ecadd;
mod ecmul;

use ecadd::{ecadd_invalid_tests, ecadd_valid_tests};
use ecmul::{ecmul_invalid_tests, ecmul_valid_tests};

fn main() {
    // Ecadd
    ecadd_valid_tests();
    ecadd_invalid_tests();

    // Ecmul
    ecmul_valid_tests();
    ecmul_invalid_tests();
}
