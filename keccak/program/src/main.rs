
#![no_main]
ziskos::entrypoint!(main);

use tiny_keccak::{Hasher, Keccak, keccakf};
use std::convert::TryInto;
use ziskos::{read_input, set_output};
use byteorder::ByteOrder;

fn main() {
    // Get the input from ziskos
    let input: Vec<u8> = read_input();

    let full_keccak = input[8] == 1;
    if full_keccak {
        println!("Computing the full keccak...");

        let keccak_input = input[..8].to_vec();
        let input_number = u64::from_le_bytes(input[..8].try_into().expect("Input should be at least 8 bytes"));
        println!("Number to hash:  0x{:X}", input_number);

        let mut output = full_keccak_hash(&keccak_input);

        let output_number: String = output.iter().map(|byte| format!("{:02x}", byte)).collect();
        println!("Output: 0x{}", output_number);
    
        // Write the output using ziskos
        for i in 0..8 {
            let val = byteorder::BigEndian::read_u32(&mut output[i*4..i*4+4]);
            set_output(i, val);
        }
    } else {
        let num_keccaks = usize::from_le_bytes(input[9..17].try_into().expect("Input should be at least 8 bytes"));
        println!("Number of keccakf to compute: {:?}", num_keccaks);
        for _ in 0..num_keccaks {
            keccakf_apply();
        }
    }
}

fn full_keccak_hash(input: &[u8]) -> [u8; 32] {
    // Define the output
    let mut output = [0u8; 32];

    let mut keccak = Keccak::v256();
    keccak.update(input);
    keccak.finalize(&mut output);
    output
}

fn keccakf_apply() {
    // Take any number and apply the keccakf function
    let mut input_array = [0u64; 25];
    for i in 0..25 {
        input_array[i] = i as u64;
    }

    keccakf(&mut input_array);
}
