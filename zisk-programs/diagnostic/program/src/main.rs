#![no_main]

ziskos::entrypoint!(main);

mod arith_eq;
mod arith_eq_384;
mod bigint;
mod fcall;
mod keccakf;
mod riscv_c;
mod riscv_fd;
mod riscv_ima;
mod sha256f;

#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
fn main() {}

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
fn main() {
    //riscv_ima::diagnostic_riscv_ima_combinations();
    riscv_ima::diagnostic_riscv_ima();
    riscv_c::diagnostic_riscv_c();
    riscv_fd::diagnostic_riscv_fd();
    fcall::diagnostic_fcall();
    arith_eq::test_arith_eq();
    arith_eq_384::test_arith_eq_384();
    bigint::test_bigint();
    keccakf::test_keccakf();
    sha256f::test_sha256f();
    println!("Success");
}
