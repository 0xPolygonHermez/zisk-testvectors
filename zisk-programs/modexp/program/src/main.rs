#![no_main]
#![cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
ziskos::entrypoint!(main);

// TODO: Fix tests when modexp version is final

// mod array_arith;
mod constants;
mod modexp;
// mod square;

// use array_arith::array_arith_tests;
use modexp::modexp_tests;
// use square::square_tests;

fn main() {
    // array_arith_tests();

    // square_tests();

    modexp_tests();
}
