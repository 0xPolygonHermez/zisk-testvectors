#![no_main]
ziskos::entrypoint!(main);

use ziskos::sha256f::syscall_sha256_f;

// Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
pub const SHA256_INITIAL_HASH_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// RUST_BACKTRACE=full ../zisk/target/release/ziskemu -x -e target/riscv64ima-polygon-ziskos-elf/release/sha256
fn main() {
    let mut state = [0u64; 4];
    for i in 0..4 {
        let lo = SHA256_INITIAL_HASH_STATE[2 * i] as u64;
        let hi = SHA256_INITIAL_HASH_STATE[2 * i + 1] as u64;
        state[i] = (hi << 32) | lo;
    }

    let mut input = [0u64; 8];
    input[0] = 0x0000_0001_0000_0000;
    syscall_sha256_f(&mut state, &input);

    // Expected Sha256f
    let expected_hash: [u64; 4] =
        [0x98FC1C14E3B0C442, 0x996FB9249AFBF4C8, 0x649B934C27AE41E4, 0x7852B855A495991B];
    assert_eq!(state[..], expected_hash[..]);
}
