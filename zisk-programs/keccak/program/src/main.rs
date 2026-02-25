#![no_main]
ziskos::entrypoint!(main);

use rand::Rng;
use tiny_keccak::{keccakf, Hasher, Keccak};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct HashInput {
    hash: u64,
    full_keccak: bool,
    num_keccaks: u64,
}

fn main() {
    // Get the input from ziskos
    let hash_input: HashInput = ziskos::io::read();

    let full_keccak = hash_input.full_keccak;
    if full_keccak {
        println!("Computing the full keccak...");

        let keccak_input = hash_input.hash.to_le_bytes().to_vec();
        let input_number = hash_input.hash;
        println!("Number to hash:  0x{:X}", input_number);

        let output = full_keccak_hash(&keccak_input);

        let output_number: String = output.iter().map(|byte| format!("{:02x}", byte)).collect();
        println!("Output: 0x{}", output_number);

        // Write the output using ziskos
        ziskos::io::commit(&output);
    } else {
        let mut rng = rand::thread_rng();

        let num_keccaks = hash_input.num_keccaks as usize;
        println!("Number of keccakf to compute: {:?}", num_keccaks);
        for _ in 0..num_keccaks {
            keccakf_apply(&mut rng);
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

fn keccakf_apply(rng: &mut rand::rngs::ThreadRng) {
    // Take any number and apply the keccakf function
    let mut input_array = [0u64; 25];
    for i in 0..25 {
        input_array[i] = rng.gen();
    }

    keccakf(&mut input_array);
}
