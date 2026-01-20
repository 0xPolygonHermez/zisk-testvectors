#![no_main]
#![cfg_attr(not(all(target_os = "zkvm", target_vendor = "zisk")), allow(unused))]
ziskos::entrypoint!(main);

mod arith_eq_384_tests;
mod arith_eq_tests;
mod bigint_tests;
mod fcall;
mod keccakf_tests;
mod riscv_c;
mod riscv_fd;
mod riscv_ima;
mod sha256f_tests;

#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
fn main() {}

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
fn main() {
    //riscv_ima::diagnostic_riscv_ima_combinations();
    riscv_ima::diagnostic_riscv_ima();
    riscv_c::diagnostic_riscv_c();
    riscv_fd::diagnostic_riscv_fd();
    // fcall::diagnostic_fcall(); //TODO: Fix rom-setup issue
    arith_eq_tests::test_arith_eq();
    arith_eq_384_tests::test_arith_eq_384();
    bigint_tests::test_bigint();
    keccakf_tests::test_keccakf();
    // sha256f_tests::test_sha256f(); //TODO: Fix rom-setup issue
    println!("Success");
}
