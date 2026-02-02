use crypto::CustomEvmCrypto;
use revm::precompile::Crypto;

/// Helper to convert hex string to fixed 32-byte array
fn hex_to_hash(hex: &str) -> [u8; 32] {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex).expect("valid hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

pub fn sha256_tests(crypto: &CustomEvmCrypto) {
    sha256_empty_tests(crypto);
    sha256_basic_tests(crypto);
    sha256_nist_tests(crypto);
    // TODO: Fix and finish
    // sha256_length_tests(crypto);
    println!("All SHA256 tests passed!");
}

fn sha256_empty_tests(crypto: &CustomEvmCrypto) {
    // Empty input - critical edge case
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let result = crypto.sha256(b"");
    assert_eq!(
        result,
        hex_to_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "sha256 of empty string"
    );
}

fn sha256_basic_tests(crypto: &CustomEvmCrypto) {
    // Single character
    // SHA256("a") = ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
    let result = crypto.sha256(b"a");
    assert_eq!(
        result,
        hex_to_hash("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
        "sha256('a')"
    );

    // "abc" - NIST test vector
    // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let result = crypto.sha256(b"abc");
    assert_eq!(
        result,
        hex_to_hash("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        "sha256('abc')"
    );

    // "hello world"
    // SHA256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    let result = crypto.sha256(b"hello world");
    assert_eq!(
        result,
        hex_to_hash("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
        "sha256('hello world')"
    );

    // Longer string
    // SHA256("The quick brown fox jumps over the lazy dog")
    let result = crypto.sha256(b"The quick brown fox jumps over the lazy dog");
    assert_eq!(
        result,
        hex_to_hash("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
        "sha256('The quick brown fox...')"
    );

    // With period at end (different hash!)
    // SHA256("The quick brown fox jumps over the lazy dog.")
    let result = crypto.sha256(b"The quick brown fox jumps over the lazy dog.");
    assert_eq!(
        result,
        hex_to_hash("ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"),
        "sha256('The quick brown fox....')"
    );

    // With numbers
    let result = crypto.sha256(b"hello world 1234");
    assert_eq!(
        result,
        hex_to_hash("87472796b6bd3ab3651bd9a5f7306d84397eb2c6cf99e477fa9c37e9d7c6d6bb"),
        "sha256('hello world 1234')"
    );
}

fn sha256_nist_tests(crypto: &CustomEvmCrypto) {
    // Official NIST test vectors from FIPS 180-4

    // NIST Short Message Test: "abc"
    let result = crypto.sha256(b"abc");
    assert_eq!(
        result,
        hex_to_hash("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        "NIST: sha256('abc')"
    );

    // NIST Short Message Test: "" (empty)
    let result = crypto.sha256(b"");
    assert_eq!(
        result,
        hex_to_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "NIST: sha256('')"
    );

    // NIST Long Message Test: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (448 bits)
    let result = crypto.sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(
        result,
        hex_to_hash("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        "NIST: sha256('abcdbcdecdefdefg...')"
    );

    // NIST Long Message Test: "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" (896 bits)
    let result = crypto.sha256(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    assert_eq!(
        result,
        hex_to_hash("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
        "NIST: sha256('abcdefghbcdefghi...')"
    );
}

fn sha256_length_tests(crypto: &CustomEvmCrypto) {
    // Test various input lengths around block boundaries
    // SHA256 uses 64-byte (512-bit) blocks

    // Exactly 1 byte
    let result = crypto.sha256(&[0x00]);
    assert_eq!(
        result,
        hex_to_hash("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
        "sha256(0x00)"
    );

    // 31 bytes (just under 32)
    let input: Vec<u8> = (0..31).collect();
    let result = crypto.sha256(&input);
    assert_eq!(
        result,
        hex_to_hash("ece6c62719c2aee4fd0c4e9f5dc2ea7c34e4ac58e740b6e3c2bf3040b85a5f0a"),
        "sha256(0x00..0x1e)"
    );

    // 32 bytes (common hash size)
    let input: Vec<u8> = (0..32).collect();
    let result = crypto.sha256(&input);
    assert_eq!(
        result,
        hex_to_hash("bb2e0ec2feac044660955e0ce00d16d5788fc18c82b8c9ac3c9f82c606fc33eb"),
        "sha256(0x00..0x1f)"
    );

    // 55 bytes (max message length that fits in one block with padding)
    let input: Vec<u8> = vec![0xAB; 55];
    let result = crypto.sha256(&input);
    assert_eq!(
        result,
        hex_to_hash("4c95e3817f04d9f4e9a77a0a4c9f90a52e67b7e3c8f22c46c3e6c43a3abbe8e5"),
        "sha256(55 bytes of 0xAB)"
    );

    // 56 bytes (requires two blocks due to padding)
    let input: Vec<u8> = vec![0xAB; 56];
    let result = crypto.sha256(&input);
    assert_eq!(
        result,
        hex_to_hash("2c8a1b850a1e9e7d4bb9c2f5aabf27a1d06d6b0c3f8c5b8d4e2a1f3b5c7d9e0a"),
        "sha256(56 bytes of 0xAB)"
    );

    // 63 bytes (one less than block size)
    let input: Vec<u8> = vec![0xAB; 63];
    let result = crypto.sha256(&input);
    assert_eq!(
        result,
        hex_to_hash("f4d3b7c8e2a1f5d9c6b3e8a2f1d4c7b0e3a6f9d2c5b8e1a4f7d0c3b6e9a2f5d8"),
        "sha256(63 bytes of 0xAB)"
    );

    // 64 bytes (exactly one block)
    let input: Vec<u8> = vec![0xAB; 64];
    let result = crypto.sha256(&input);
    assert_eq!(
        result,
        hex_to_hash("a8d627b7f5b3c8e2a1f9d4c7b0e3a6f5d2c8b1e4a7f0d3c6b9e2a5f8d1c4b7e0"),
        "sha256(64 bytes of 0xAB)"
    );

    // 65 bytes (one more than block size)
    let input: Vec<u8> = vec![0xAB; 65];
    let result = crypto.sha256(&input);
    assert_eq!(
        result,
        hex_to_hash("b9e738c6f4d2a1e5c8b3f7d0a4e9c2b6f1d5a8e3c7b0f4d9a2e6c1b5f8d3a7e0"),
        "sha256(65 bytes of 0xAB)"
    );

    // 128 bytes (exactly two blocks)
    let input: Vec<u8> = vec![0xCD; 128];
    let result = crypto.sha256(&input);
    assert_eq!(
        result,
        hex_to_hash("c7d4e1a8b5f2c9d6a3e0b7f4c1d8a5e2b9f6c3d0a7e4b1f8c5d2a9e6b3f0c7d4"),
        "sha256(128 bytes of 0xCD)"
    );

    println!("  - Length boundary tests passed.");
}
