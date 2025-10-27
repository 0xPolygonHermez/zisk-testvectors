#![cfg(all(target_os = "zkvm", target_vendor = "zisk"))]

pub fn diagnostic_riscv_fd() {
    {
        let a = 1.1;
        let b = 2.2;
        let c = a + b;
        assert!(c > 3.2 && c < 3.4);
    }
    println!("diagnostic_riscv_fd() success");
}
