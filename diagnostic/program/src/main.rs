#![no_main]
#![cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
ziskos::entrypoint!(main);

mod fcall;
mod riscv_fd;
mod riscv_ima;

use fcall::diagnostic_fcall;
use riscv_fd::diagnostic_riscv_fd;
use riscv_ima::diagnostic_riscv_ima;

// use ziskos::{
//     fcall2_secp256k1_fn_inv, fcall2_secp256k1_fp_inv, fcall2_secp256k1_fp_sqrt,
//     fcall_secp256k1_fn_inv, fcall_secp256k1_fp_inv, fcall_secp256k1_fp_sqrt, ziskos_fcall_get,
// };

fn main() {
    diagnostic_riscv_ima();
    diagnostic_riscv_fd();
    diagnostic_fcall();
    println!("Success");
}
