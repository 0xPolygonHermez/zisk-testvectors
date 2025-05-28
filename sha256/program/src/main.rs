#![no_main]
ziskos::entrypoint!(main);

use ziskos::{
    read_input,
    sha256f::{syscall_sha256_f, SyscallSha256Params},
};

use generic_array::{typenum::U64, GenericArray};
use rand::Rng;
use sha2::compress256;

// Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
pub const SHA256_INITIAL_HASH_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn main() {
    // Get the input from ziskos
    let input: Vec<u8> = read_input();

    let mut rng = rand::thread_rng();

    let num_sha256fs =
        usize::from_le_bytes(input[..8].try_into().expect("Input should be at least 8 bytes"));
    println!("Number of sha256f to compute: {:?}", num_sha256fs);
    for _ in 0..num_sha256fs {
        sha256f_apply(&mut rng);
    }
}

fn sha256f_apply(rng: &mut rand::rngs::ThreadRng) {
    // Take any number and apply the sha256f function
    let mut state = [0u64; 4];
    for i in 0..4 {
        state[i] = rng.gen();
    }

    let mut input = [0u64; 8];
    for i in 0..8 {
        input[i] = rng.gen();
    }

    let state_copy = state.clone();

    let mut params = SyscallSha256Params { state: &mut state, input: &input };
    syscall_sha256_f(&mut params);

    // Compare against an audited sha256f implementation
    let mut state_u32 = convert_u64_to_u32_be_words(&state_copy);
    let block: GenericArray<u8, U64> = u64s_to_generic_array_be(&input);
    let blocks = &[block];
    compress256(&mut state_u32, blocks);
    let expected_result = convert_u32s_back_to_u64_be(&state_u32);

    assert_eq!(state, expected_result, "SHA256F state mismatch");
}

fn convert_u64_to_u32_be_words(input: &[u64; 4]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, &word) in input.iter().enumerate() {
        let bytes = word.to_be_bytes();
        out[2 * i] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        out[2 * i + 1] = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    }
    out
}

fn u64s_to_generic_array_be(input: &[u64; 8]) -> GenericArray<u8, U64> {
    let mut out = [0u8; 64];
    for (i, word) in input.iter().enumerate() {
        let bytes = word.to_be_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    GenericArray::<u8, U64>::clone_from_slice(&out)
}

fn convert_u32s_back_to_u64_be(words: &[u32; 8]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        let high = words[2 * i].to_be_bytes();
        let low = words[2 * i + 1].to_be_bytes();
        out[i] = u64::from_be_bytes([
            high[0], high[1], high[2], high[3], low[0], low[1], low[2], low[3],
        ]);
    }
    out
}
