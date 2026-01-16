#![no_main]
ziskos::entrypoint!(main);

use byteorder::ByteOrder;
use ziskos::{read_input, set_output};

use ziskos::syscalls::{syscall_poseidon2};


fn main() {
    // Get the input from ziskos
    let input: Vec<u8> = read_input();

    println!("Computing the full poseidon2...");
    let poseidon2_input = bytemuck::cast_slice::<u8, u64>(&input);
    println!("Input values: {:?}", poseidon2_input);

    let mut poseidon2_array: [u64; 16] = poseidon2_input.try_into().expect("Input must be exactly 16 u64 values (128 bytes)");
    syscall_poseidon2(&mut poseidon2_array);

    println!("Output: {:?}", poseidon2_array);
    
    // Write the output using ziskos
    for i in 0..8 {
        let output_bytes = bytemuck::cast_slice::<u64, u8>(&poseidon2_array);
        let val = byteorder::BigEndian::read_u32(&output_bytes[i * 4..i * 4 + 4]);
        set_output(i, val);
    }
}
