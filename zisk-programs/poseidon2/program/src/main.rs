#![no_main]
ziskos::entrypoint!(main);

use ziskos::syscalls::{syscall_poseidon2};


fn main() {
    // Get the input from ziskos
    let mut poseidon2_input: [u64; 16] = ziskos::io::read();

    println!("Computing the full poseidon2...");
    println!("Input values: {:?}", poseidon2_input);

    unsafe {
        syscall_poseidon2(&mut poseidon2_input);
    }
    println!("Output: {:?}", poseidon2_input);
    
    ziskos::io::commit(&poseidon2_input);
}
