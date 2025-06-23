#![no_main]
ziskos::entrypoint!(main);

use ziskos::{
    read_input,
    sha256f::{syscall_sha256_f, SyscallSha256Params},
};

use generic_array::{typenum::U64, GenericArray};
use rand::Rng;
use sha2::compress256;

const ACTIVATE_CONSISTENCY_TEST: bool = false;

fn main() {
    if ACTIVATE_CONSISTENCY_TEST {
        run_consistency_test();
        return;
    }

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
    let mut state_u32 = convert_u64_to_u32(&state_copy);
    let block: GenericArray<u8, U64> = convert_u64_to_generic_array_bytes(&input);
    compress256(&mut state_u32, &[block]);
    let expected_result = convert_u32_to_u64(&state_u32);

    assert_eq!(state, expected_result, "SHA256F state mismatch");
}

fn run_consistency_test() {
    println!("Running consistency test for SHA256F...");

    const SHA256_INITIAL_HASH_STATE: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut state = convert_u32_to_u64(&SHA256_INITIAL_HASH_STATE);

    let mut input = [0u64; 8];
    input[0] = 1 << 63;

    let mut params = SyscallSha256Params { state: &mut state, input: &input };
    syscall_sha256_f(&mut params);

    const EXPECTED_RESULT: [u32; 8] = [
        0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b,
        0x7852b855,
    ];
    let expected_result = convert_u32_to_u64(&EXPECTED_RESULT);

    assert_eq!(state, expected_result, "SHA256F state mismatch");
}

fn convert_u64_to_u32(input: &[u64; 4]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, &word) in input.iter().enumerate() {
        out[2 * i] = (word >> 32) as u32;
        out[2 * i + 1] = (word & 0xFFFFFFFF) as u32;
    }
    out
}

fn convert_u64_to_generic_array_bytes(input: &[u64; 8]) -> GenericArray<u8, U64> {
    let mut out = [0u8; 64];
    for (i, word) in input.iter().enumerate() {
        for j in 0..8 {
            out[i * 8 + j] = (word >> (56 - j * 8)) as u8;
        }
    }
    GenericArray::<u8, U64>::clone_from_slice(&out)
}

fn convert_u32_to_u64(words: &[u32; 8]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = ((words[2 * i] as u64) << 32) | (words[2 * i + 1] as u64);
    }
    out
}
