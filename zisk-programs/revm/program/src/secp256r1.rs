use guest_reth::CustomEvmCrypto;
use revm::precompile::Crypto;

/// Convert hex string (without 0x prefix) to 32-byte array
fn hex_to_32(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).expect("valid hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

/// Build signature from r and s hex strings (32 bytes each, big-endian)
fn build_sig(r: &str, s: &str) -> [u8; 64] {
    let mut sig = [0u8; 64];
    let r_bytes = hex::decode(r).expect("valid hex");
    let s_bytes = hex::decode(s).expect("valid hex");
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s_bytes);
    sig
}

/// Build public key from x and y hex strings (32 bytes each, big-endian)
fn build_pk(x: &str, y: &str) -> [u8; 64] {
    let mut pk = [0u8; 64];
    let x_bytes = hex::decode(x).expect("valid hex");
    let y_bytes = hex::decode(y).expect("valid hex");
    pk[..32].copy_from_slice(&x_bytes);
    pk[32..].copy_from_slice(&y_bytes);
    pk
}

pub fn secp256r1_tests(crypto: &CustomEvmCrypto) {
    // Test 1: incomplete data
    let msg = hex_to_32("0000000000000000000000000000000000000000000000000000000000000000");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 2 failed");
    let msg = hex_to_32("0000000000000000000000000000000000000000000000000000000000000000");
    let sig = build_sig(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 3 failed");
    // Tests from https://github.com/ulerdogan/go-ethereum/blob/ulerdogan-secp256r1/core/vm/testdata/precompiles/p256Verify.json
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "4cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 4 failed");
    // same test but with the s = n - s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 5 failed");
    // 2] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #3: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 6 should fail");
    // 3] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #5: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "d45c5741946b2a137f59262ee6f5bc91001af27a5e1117a64733950642a3d1e8",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 7 should fail");
    // 4] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #8: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "4cd60b865d442f5a3c7b11eb6c4e0ae79578ec6353a20bf783ecb4b6ea97b825",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 8 should fail");
    // 5] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #9: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 9 should fail");
    // 6] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #10: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 10 should fail");
    // 7] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #11: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 11 should fail");
    // 8] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #12: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 12 should fail");
    // 9] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #13: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 13 should fail");
    // 10] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #14: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 14 should fail");
    // 11] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #15: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 15 should fail");
    // 12] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #16: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 16 should fail");
    // 13] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #17: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 17 should fail");
    // 14] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #18: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 18 should fail");
    // 15] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #19: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 19 should fail");
    // 16] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #20: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 20 should fail");
    // 17] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #21: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 21 should fail");
    // 18] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #22: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 22 should fail");
    // 19] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #23: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 23 should fail");
    // 20] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #24: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 24 should fail");
    // 21] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #25: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 25 should fail");
    // 22] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #26: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 26 should fail");
    // 23] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #27: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 27 should fail");
    // 24] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #28: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 28 should fail");
    // 25] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #29: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 29 should fail");
    // 26] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #30: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 30 should fail");
    // 27] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #31: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 31 should fail");
    // 28] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #32: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 32 should fail");
    // 29] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #33: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 33 should fail");
    // 30] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #34: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 34 should fail");
    // 31] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #35: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 35 should fail");
    // 32] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #36: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 36 should fail");
    // 33] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #37: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 37 should fail");
    // 34] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #38: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 38 should fail");
    // 35] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #39: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 39 should fail");
    // 36] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #40: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 40 should fail");
    // 37] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #41: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 41 should fail");
    // 38] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #42: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 42 should fail");
    // 39] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #43: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 43 should fail");
    // 40] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #44: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 44 should fail");
    // 41] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #45: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 45 should fail");
    // 42] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #46: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 46 should fail");
    // 43] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #47: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 47 should fail");
    // 44] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #48: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 48 should fail");
    // 45] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #49: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 49 should fail");
    // 46] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #50: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 50 should fail");
    // 47] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #51: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 51 should fail");
    // 48] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #52: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 52 should fail");
    // 49] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #53: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 53 should fail");
    // 50] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #54: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 54 should fail");
    // 51] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #55: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 55 should fail");
    // 52] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #56: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 56 should fail");
    // 53] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #57: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 57 should fail");
    // 54] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #58: Edge case for Shamir multiplication
    let msg = hex_to_32("70239dd877f7c944c422f44dea4ed1a52f2627416faf2f072fa50c772ed6f807");
    let sig = build_sig(
        "64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e",
        "6af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 58 failed");
    // 55] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #59: special case hash
    let msg = hex_to_32("00000000690ed426ccf17803ebe2bd0884bcd58a1bb5e7477ead3645f356e7a9");
    let sig = build_sig(
        "16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf266",
        "252cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 59 failed");
    // 56] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #60: special case hash
    let msg = hex_to_32("7300000000213f2a525c6035725235c2f696ad3ebb5ee47f140697ad25770d91");
    let sig = build_sig(
        "9cc98be2347d469bf476dfc26b9b733df2d26d6ef524af917c665baccb23c882",
        "093496459effe2d8d70727b82462f61d0ec1b7847929d10ea631dacb16b56c32",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 60 failed");
    // 57] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #61: special case hash
    let msg = hex_to_32("ddf2000000005e0be0635b245f0b97978afd25daadeb3edb4a0161c27fe06045");
    let sig = build_sig(
        "73b3c90ecd390028058164524dde892703dce3dea0d53fa8093999f07ab8aa43",
        "2f67b0b8e20636695bb7d8bf0a651c802ed25a395387b5f4188c0c4075c88634",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 61 failed");
    // 58] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #62: special case hash
    let msg = hex_to_32("67ab1900000000784769c4ecb9e164d6642b8499588b89855be1ec355d0841a0");
    let sig = build_sig(
        "bfab3098252847b328fadf2f89b95c851a7f0eb390763378f37e90119d5ba3dd",
        "bdd64e234e832b1067c2d058ccb44d978195ccebb65c2aaf1e2da9b8b4987e3b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 62 failed");
    // 59] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #63: special case hash
    let msg = hex_to_32("a2bf09460000000076d7dbeffe125eaf02095dff252ee905e296b6350fc311cf");
    let sig = build_sig(
        "204a9784074b246d8bf8bf04a4ceb1c1f1c9aaab168b1596d17093c5cd21d2cd",
        "51cce41670636783dc06a759c8847868a406c2506fe17975582fe648d1d88b52",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 63 failed");
    // 60] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #64: special case hash
    let msg = hex_to_32("3554e827c700000000e1e75e624a06b3a0a353171160858129e15c544e4f0e65");
    let sig = build_sig(
        "ed66dc34f551ac82f63d4aa4f81fe2cb0031a91d1314f835027bca0f1ceeaa03",
        "99ca123aa09b13cd194a422e18d5fda167623c3f6e5d4d6abb8953d67c0c48c7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 64 failed");
    // 61] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #65: special case hash
    let msg = hex_to_32("9b6cd3b812610000000026941a0f0bb53255ea4c9fd0cb3426e3a54b9fc6965c");
    let sig = build_sig(
        "060b700bef665c68899d44f2356a578d126b062023ccc3c056bf0f60a237012b",
        "8d186c027832965f4fcc78a3366ca95dedbb410cbef3f26d6be5d581c11d3610",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 65 failed");
    // 62] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #66: special case hash
    let msg = hex_to_32("883ae39f50bf0100000000e7561c26fc82a52baa51c71ca877162f93c4ae0186");
    let sig = build_sig(
        "9f6adfe8d5eb5b2c24d7aa7934b6cf29c93ea76cd313c9132bb0c8e38c96831d",
        "b26a9c9e40e55ee0890c944cf271756c906a33e66b5bd15e051593883b5e9902",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 66 failed");
    // 63] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #67: special case hash
    let msg = hex_to_32("a1ce5d6e5ecaf28b0000000000fa7cd010540f420fb4ff7401fe9fce011d0ba6");
    let sig = build_sig(
        "a1af03ca91677b673ad2f33615e56174a1abf6da168cebfa8868f4ba273f16b7",
        "20aa73ffe48afa6435cd258b173d0c2377d69022e7d098d75caf24c8c5e06b1c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 67 failed");
    // 64] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #68: special case hash
    let msg = hex_to_32("8ea5f645f373f580930000000038345397330012a8ee836c5494cdffd5ee8054");
    let sig = build_sig(
        "fdc70602766f8eed11a6c99a71c973d5659355507b843da6e327a28c11893db9",
        "3df5349688a085b137b1eacf456a9e9e0f6d15ec0078ca60a7f83f2b10d21350",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 68 failed");
    // 65] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #69: special case hash
    let msg = hex_to_32("660570d323e9f75fa734000000008792d65ce93eabb7d60d8d9c1bbdcb5ef305");
    let sig = build_sig(
        "b516a314f2fce530d6537f6a6c49966c23456f63c643cf8e0dc738f7b876e675",
        "d39ffd033c92b6d717dd536fbc5efdf1967c4bd80954479ba66b0120cd16fff2",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 69 failed");
    // 66] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #70: special case hash
    let msg = hex_to_32("d0462673154cce587dde8800000000e98d35f1f45cf9c3bf46ada2de4c568c34");
    let sig = build_sig(
        "3b2cbf046eac45842ecb7984d475831582717bebb6492fd0a485c101e29ff0a8",
        "4c9b7b47a98b0f82de512bc9313aaf51701099cac5f76e68c8595fc1c1d99258",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 70 failed");
    // 67] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #71: special case hash
    let msg = hex_to_32("bd90640269a7822680cedfef000000000caef15a6171059ab83e7b4418d7278f");
    let sig = build_sig(
        "30c87d35e636f540841f14af54e2f9edd79d0312cfa1ab656c3fb15bfde48dcf",
        "47c15a5a82d24b75c85a692bd6ecafeb71409ede23efd08e0db9abf6340677ed",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 71 failed");
    // 68] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #72: special case hash
    let msg = hex_to_32("33239a52d72f1311512e41222a00000000d2dcceb301c54b4beae8e284788a73");
    let sig = build_sig(
        "38686ff0fda2cef6bc43b58cfe6647b9e2e8176d168dec3c68ff262113760f52",
        "067ec3b651f422669601662167fa8717e976e2db5e6a4cf7c2ddabb3fde9d67d",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 72 failed");
    // 69] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #73: special case hash
    let msg = hex_to_32("b8d64fbcd4a1c10f1365d4e6d95c000000007ee4a21a1cbe1dc84c2d941ffaf1");
    let sig = build_sig(
        "44a3e23bf314f2b344fc25c7f2de8b6af3e17d27f5ee844b225985ab6e2775cf",
        "2d48e223205e98041ddc87be532abed584f0411f5729500493c9cc3f4dd15e86",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 73 failed");
    // 70] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #74: special case hash
    let msg = hex_to_32("01603d3982bf77d7a3fef3183ed092000000003a227420db4088b20fe0e9d84a");
    let sig = build_sig(
        "2ded5b7ec8e90e7bf11f967a3d95110c41b99db3b5aa8d330eb9d638781688e9",
        "7d5792c53628155e1bfc46fb1a67e3088de049c328ae1f44ec69238a009808f9",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 74 failed");
    // 71] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #75: special case hash
    let msg = hex_to_32("9ea6994f1e0384c8599aa02e6cf66d9c000000004d89ef50b7e9eb0cfbff7363");
    let sig = build_sig(
        "bdae7bcb580bf335efd3bc3d31870f923eaccafcd40ec2f605976f15137d8b8f",
        "f6dfa12f19e525270b0106eecfe257499f373a4fb318994f24838122ce7ec3c7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 75 failed");
    // 72] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #76: special case hash
    let msg = hex_to_32("d03215a8401bcf16693979371a01068a4700000000e2fa5bf692bc670905b18c");
    let sig = build_sig(
        "50f9c4f0cd6940e162720957ffff513799209b78596956d21ece251c2401f1c6",
        "d7033a0a787d338e889defaaabb106b95a4355e411a59c32aa5167dfab244726",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 76 failed");
    // 73] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #77: special case hash
    let msg = hex_to_32("307bfaaffb650c889c84bf83f0300e5dc87e000000008408fd5f64b582e3bb14");
    let sig = build_sig(
        "f612820687604fa01906066a378d67540982e29575d019aabe90924ead5c860d",
        "3f9367702dd7dd4f75ea98afd20e328a1a99f4857b316525328230ce294b0fef",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 77 failed");
    // 74] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #78: special case hash
    let msg = hex_to_32("bab5c4f4df540d7b33324d36bb0c157551527c00000000e4af574bb4d54ea6b8");
    let sig = build_sig(
        "9505e407657d6e8bc93db5da7aa6f5081f61980c1949f56b0f2f507da5782a7a",
        "c60d31904e3669738ffbeccab6c3656c08e0ed5cb92b3cfa5e7f71784f9c5021",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 78 failed");
    // 75] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #79: special case hash
    let msg = hex_to_32("d4ba47f6ae28f274e4f58d8036f9c36ec2456f5b00000000c3b869197ef5e15e");
    let sig = build_sig(
        "bbd16fbbb656b6d0d83e6a7787cd691b08735aed371732723e1c68a40404517d",
        "9d8e35dba96028b7787d91315be675877d2d097be5e8ee34560e3e7fd25c0f00",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 79 failed");
    // 76] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #80: special case hash
    let msg = hex_to_32("79fd19c7235ea212f29f1fa00984342afe0f10aafd00000000801e47f8c184e1");
    let sig = build_sig(
        "2ec9760122db98fd06ea76848d35a6da442d2ceef7559a30cf57c61e92df327e",
        "7ab271da90859479701fccf86e462ee3393fb6814c27b760c4963625c0a19878",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 80 failed");
    // 77] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #81: special case hash
    let msg = hex_to_32("8c291e8eeaa45adbaf9aba5c0583462d79cbeb7ac97300000000a37ea6700cda");
    let sig = build_sig(
        "54e76b7683b6650baa6a7fc49b1c51eed9ba9dd463221f7a4f1005a89fe00c59",
        "2ea076886c773eb937ec1cc8374b7915cfd11b1c1ae1166152f2f7806a31c8fd",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 81 failed");
    // 78] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #82: special case hash
    let msg = hex_to_32("0eaae8641084fa979803efbfb8140732f4cdcf66c3f78a000000003c278a6b21");
    let sig = build_sig(
        "5291deaf24659ffbbce6e3c26f6021097a74abdbb69be4fb10419c0c496c9466",
        "65d6fcf336d27cc7cdb982bb4e4ecef5827f84742f29f10abf83469270a03dc3",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 82 failed");
    // 79] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #83: special case hash
    let msg = hex_to_32("e02716d01fb23a5a0068399bf01bab42ef17c6d96e13846c00000000afc0f89d");
    let sig = build_sig(
        "207a3241812d75d947419dc58efb05e8003b33fc17eb50f9d15166a88479f107",
        "cdee749f2e492b213ce80b32d0574f62f1c5d70793cf55e382d5caadf7592767",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 83 failed");
    // 80] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #84: special case hash
    let msg = hex_to_32("9eb0bf583a1a6b9a194e9a16bc7dab2a9061768af89d00659a00000000fc7de1");
    let sig = build_sig(
        "6554e49f82a855204328ac94913bf01bbe84437a355a0a37c0dee3cf81aa7728",
        "aea00de2507ddaf5c94e1e126980d3df16250a2eaebc8be486effe7f22b4f929",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 84 failed");
    // 81] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #85: special case hash
    let msg = hex_to_32("62aac98818b3b84a2c214f0d5e72ef286e1030cb53d9a82b690e00000000cd15");
    let sig = build_sig(
        "a54c5062648339d2bff06f71c88216c26c6e19b4d80a8c602990ac82707efdfc",
        "e99bbe7fcfafae3e69fd016777517aa01056317f467ad09aff09be73c9731b0d",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 85 failed");
    // 82] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #86: special case hash
    let msg = hex_to_32("3760a7f37cf96218f29ae43732e513efd2b6f552ea4b6895464b9300000000c8");
    let sig = build_sig(
        "975bd7157a8d363b309f1f444012b1a1d23096593133e71b4ca8b059cff37eaf",
        "7faa7a28b1c822baa241793f2abc930bd4c69840fe090f2aacc46786bf919622",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 86 failed");
    // 83] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #87: special case hash
    let msg = hex_to_32("0da0a1d2851d33023834f2098c0880096b4320bea836cd9cbb6ff6c800000000");
    let sig = build_sig(
        "5694a6f84b8f875c276afd2ebcfe4d61de9ec90305afb1357b95b3e0da43885e",
        "0dffad9ffd0b757d8051dec02ebdf70d8ee2dc5c7870c0823b6ccc7c679cbaa4",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 87 failed");
    // 84] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #88: special case hash
    let msg = hex_to_32("ffffffff293886d3086fd567aafd598f0fe975f735887194a764a231e82d289a");
    let sig = build_sig(
        "a0c30e8026fdb2b4b4968a27d16a6d08f7098f1a98d21620d7454ba9790f1ba6",
        "5e470453a8a399f15baf463f9deceb53acc5ca64459149688bd2760c65424339",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 88 failed");
    // 85] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #89: special case hash
    let msg = hex_to_32("7bffffffff2376d1e3c03445a072e24326acdc4ce127ec2e0e8d9ca99527e7b7");
    let sig = build_sig(
        "614ea84acf736527dd73602cd4bb4eea1dfebebd5ad8aca52aa0228cf7b99a88",
        "737cc85f5f2d2f60d1b8183f3ed490e4de14368e96a9482c2a4dd193195c902f",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 89 failed");
    // 86] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #90: special case hash
    let msg = hex_to_32("a2b5ffffffffebb251b085377605a224bc80872602a6e467fd016807e97fa395");
    let sig = build_sig(
        "bead6734ebe44b810d3fb2ea00b1732945377338febfd439a8d74dfbd0f942fa",
        "6bb18eae36616a7d3cad35919fd21a8af4bbe7a10f73b3e036a46b103ef56e2a",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 90 failed");
    // 87] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #91: special case hash
    let msg = hex_to_32("641227ffffffff6f1b96fa5f097fcf3cc1a3c256870d45a67b83d0967d4b20c0");
    let sig = build_sig(
        "499625479e161dacd4db9d9ce64854c98d922cbf212703e9654fae182df9bad2",
        "42c177cf37b8193a0131108d97819edd9439936028864ac195b64fca76d9d693",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 91 failed");
    // 88] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #92: special case hash
    let msg = hex_to_32("958415d8ffffffffabad03e2fc662dc3ba203521177502298df56f36600e0f8b");
    let sig = build_sig(
        "08f16b8093a8fb4d66a2c8065b541b3d31e3bfe694f6b89c50fb1aaa6ff6c9b2",
        "9d6455e2d5d1779748573b611cb95d4a21f967410399b39b535ba3e5af81ca2e",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 92 failed");
    // 89] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #93: special case hash
    let msg = hex_to_32("f1d8de4858ffffffff1281093536f47fe13deb04e1fbe8fb954521b6975420f8");
    let sig = build_sig(
        "be26231b6191658a19dd72ddb99ed8f8c579b6938d19bce8eed8dc2b338cb5f8",
        "e1d9a32ee56cffed37f0f22b2dcb57d5c943c14f79694a03b9c5e96952575c89",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 93 failed");
    // 90] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #94: special case hash
    let msg = hex_to_32("0927895f2802ffffffff10782dd14a3b32dc5d47c05ef6f1876b95c81fc31def");
    let sig = build_sig(
        "15e76880898316b16204ac920a02d58045f36a229d4aa4f812638c455abe0443",
        "e74d357d3fcb5c8c5337bd6aba4178b455ca10e226e13f9638196506a1939123",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 94 failed");
    // 91] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #95: special case hash
    let msg = hex_to_32("60907984aa7e8effffffff4f332862a10a57c3063fb5a30624cf6a0c3ac80589");
    let sig = build_sig(
        "352ecb53f8df2c503a45f9846fc28d1d31e6307d3ddbffc1132315cc07f16dad",
        "1348dfa9c482c558e1d05c5242ca1c39436726ecd28258b1899792887dd0a3c6",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 95 failed");
    // 92] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #96: special case hash
    let msg = hex_to_32("c6ff198484939170ffffffff0af42cda50f9a5f50636ea6942d6b9b8cd6ae1e2");
    let sig = build_sig(
        "4a40801a7e606ba78a0da9882ab23c7677b8642349ed3d652c5bfa5f2a9558fb",
        "3a49b64848d682ef7f605f2832f7384bdc24ed2925825bf8ea77dc5981725782",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 96 failed");
    // 93] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #97: special case hash
    let msg = hex_to_32("de030419345ca15c75ffffffff8074799b9e0956cc43135d16dfbe4d27d7e68d");
    let sig = build_sig(
        "eacc5e1a8304a74d2be412b078924b3bb3511bac855c05c9e5e9e44df3d61e96",
        "7451cd8e18d6ed1885dd827714847f96ec4bb0ed4c36ce9808db8f714204f6d1",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 97 failed");
    // 94] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #98: special case hash
    let msg = hex_to_32("6f0e3eeaf42b28132b88fffffffff6c8665604d34acb19037e1ab78caaaac6ff");
    let sig = build_sig(
        "2f7a5e9e5771d424f30f67fdab61e8ce4f8cd1214882adb65f7de94c31577052",
        "ac4e69808345809b44acb0b2bd889175fb75dd050c5a449ab9528f8f78daa10c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 98 failed");
    // 95] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #99: special case hash
    let msg = hex_to_32("cdb549f773b3e62b3708d1ffffffffbe48f7c0591ddcae7d2cb222d1f8017ab9");
    let sig = build_sig(
        "ffcda40f792ce4d93e7e0f0e95e1a2147dddd7f6487621c30a03d710b3300219",
        "79938b55f8a17f7ed7ba9ade8f2065a1fa77618f0b67add8d58c422c2453a49a",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 99 failed");
    // 96] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #100: special case hash
    let msg = hex_to_32("2c3f26f96a3ac0051df4989bffffffff9fd64886c1dc4f9924d8fd6f0edb0484");
    let sig = build_sig(
        "81f2359c4faba6b53d3e8c8c3fcc16a948350f7ab3a588b28c17603a431e39a8",
        "cd6f6a5cc3b55ead0ff695d06c6860b509e46d99fccefb9f7f9e101857f74300",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 100 failed");
    // 97] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #101: special case hash
    let msg = hex_to_32("ac18f8418c55a2502cb7d53f9affffffff5c31d89fda6a6b8476397c04edf411");
    let sig = build_sig(
        "dfc8bf520445cbb8ee1596fb073ea283ea130251a6fdffa5c3f5f2aaf75ca808",
        "048e33efce147c9dd92823640e338e68bfd7d0dc7a4905b3a7ac711e577e90e7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 101 failed");
    // 98] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #102: special case hash
    let msg = hex_to_32("4f9618f98e2d3a15b24094f72bb5ffffffffa2fd3e2893683e5a6ab8cf0ee610");
    let sig = build_sig(
        "ad019f74c6941d20efda70b46c53db166503a0e393e932f688227688ba6a5762",
        "93320eb7ca0710255346bdbb3102cdcf7964ef2e0988e712bc05efe16c199345",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 102 failed");
    // 99] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #103: special case hash
    let msg = hex_to_32("422e82a3d56ed10a9cc21d31d37a25ffffffff67edf7c40204caae73ab0bc75a");
    let sig = build_sig(
        "ac8096842e8add68c34e78ce11dd71e4b54316bd3ebf7fffdeb7bd5a3ebc1883",
        "f5ca2f4f23d674502d4caf85d187215d36e3ce9f0ce219709f21a3aac003b7a8",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 103 failed");
    // 100] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #104: special case hash
    let msg = hex_to_32("7075d245ccc3281b6e7b329ff738fbb417a5ffffffffa0842d9890b5cf95d018");
    let sig = build_sig(
        "677b2d3a59b18a5ff939b70ea002250889ddcd7b7b9d776854b4943693fb92f7",
        "6b4ba856ade7677bf30307b21f3ccda35d2f63aee81efd0bab6972cc0795db55",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 104 failed");
    // 101] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #105: special case hash
    let msg = hex_to_32("3c80de54cd9226989443d593fa4fd6597e280ebeffffffffc1847eb76c217a95");
    let sig = build_sig(
        "479e1ded14bcaed0379ba8e1b73d3115d84d31d4b7c30e1f05e1fc0d5957cfb0",
        "918f79e35b3d89487cf634a4f05b2e0c30857ca879f97c771e877027355b2443",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 105 failed");
    // 102] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #106: special case hash
    let msg = hex_to_32("de21754e29b85601980bef3d697ea2770ce891a8cdffffffffc7906aa794b39b");
    let sig = build_sig(
        "43dfccd0edb9e280d9a58f01164d55c3d711e14b12ac5cf3b64840ead512a0a3",
        "1dbe33fa8ba84533cd5c4934365b3442ca1174899b78ef9a3199f49584389772",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 106 failed");
    // 103] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #107: special case hash
    let msg = hex_to_32("8f65d92927cfb86a84dd59623fb531bb599e4d5f7289ffffffff2f1f2f57881c");
    let sig = build_sig(
        "5b09ab637bd4caf0f4c7c7e4bca592fea20e9087c259d26a38bb4085f0bbff11",
        "45b7eb467b6748af618e9d80d6fdcd6aa24964e5a13f885bca8101de08eb0d75",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 107 failed");
    // 104] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #108: special case hash
    let msg = hex_to_32("6b63e9a74e092120160bea3877dace8a2cc7cd0e8426cbfffffffffafc8c3ca8");
    let sig = build_sig(
        "5e9b1c5a028070df5728c5c8af9b74e0667afa570a6cfa0114a5039ed15ee06f",
        "b1360907e2d9785ead362bb8d7bd661b6c29eeffd3c5037744edaeb9ad990c20",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 108 failed");
    // 105] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #109: special case hash
    let msg = hex_to_32("fc28259702a03845b6d75219444e8b43d094586e249c8699ffffffffe852512e");
    let sig = build_sig(
        "0671a0a85c2b72d54a2fb0990e34538b4890050f5a5712f6d1a7a5fb8578f32e",
        "db1846bab6b7361479ab9c3285ca41291808f27fd5bd4fdac720e5854713694c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 109 failed");
    // 106] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #110: special case hash
    let msg = hex_to_32("1273b4502ea4e3bccee044ee8e8db7f774ecbcd52e8ceb571757ffffffffe20a");
    let sig = build_sig(
        "7673f8526748446477dbbb0590a45492c5d7d69859d301abbaedb35b2095103a",
        "3dc70ddf9c6b524d886bed9e6af02e0e4dec0d417a414fed3807ef4422913d7c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 110 failed");
    // 107] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #111: special case hash
    let msg = hex_to_32("08fb565610a79baa0c566c66228d81814f8c53a15b96e602fb49ffffffffff6e");
    let sig = build_sig(
        "7f085441070ecd2bb21285089ebb1aa6450d1a06c36d3ff39dfd657a796d12b5",
        "249712012029870a2459d18d47da9aa492a5e6cb4b2d8dafa9e4c5c54a2b9a8b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 111 failed");
    // 108] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #112: special case hash
    let msg = hex_to_32("d59291cc2cf89f3087715fcb1aa4e79aa2403f748e97d7cd28ecaefeffffffff");
    let sig = build_sig(
        "914c67fb61dd1e27c867398ea7322d5ab76df04bc5aa6683a8e0f30a5d287348",
        "fa07474031481dda4953e3ac1959ee8cea7e66ec412b38d6c96d28f6d37304ea",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 112 failed");
    // 109] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #113: k*G has a large x-coordinate
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "000000000000000000000000000000004319055358e8617b0c46353d039cdaab",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
    );
    let pk = build_pk(
        "0ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103",
        "c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 113 failed");
    // 110] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #114: r too large
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
    );
    let pk = build_pk(
        "0ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103",
        "c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 114 should fail");
    // 111] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #115: r,s are large
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
    );
    let pk = build_pk(
        "ab05fd9d0de26b9ce6f4819652d9fc69193d0aa398f0fba8013e09c582204554",
        "19235271228c786759095d12b75af0692dd4103f19f6a8c32f49435a1e9b8d45",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 115 failed");
    // 112] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #116: r and s^-1 have a large Hamming weight
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "909135bdb6799286170f5ead2de4f6511453fe50914f3df2de54a36383df8dd4",
    );
    let pk = build_pk(
        "80984f39a1ff38a86a68aa4201b6be5dfbfecf876219710b07badf6fdd4c6c56",
        "11feb97390d9826e7a06dfb41871c940d74415ed3cac2089f1445019bb55ed95",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 116 failed");
    // 113] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #117: r and s^-1 have a large Hamming weight
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "27b4577ca009376f71303fd5dd227dcef5deb773ad5f5a84360644669ca249a5",
    );
    let pk = build_pk(
        "4201b4272944201c3294f5baa9a3232b6dd687495fcc19a70a95bc602b4f7c05",
        "95c37eba9ee8171c1bb5ac6feaf753bc36f463e3aef16629572c0c0a8fb0800e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 117 failed");
    // 114] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #118: small r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000005",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957",
        "5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 118 failed");
    // 115] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #120: small r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000005",
        "0000000000000000000000000000000000000000000000000000000000000003",
    );
    let pk = build_pk(
        "6627cec4f0731ea23fc2931f90ebe5b7572f597d20df08fc2b31ee8ef16b1572",
        "6170ed77d8d0a14fc5c9c3c4c9be7f0d3ee18f709bb275eaf2073e258fe694a5",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 119 failed");
    // 116] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #122: small r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000005",
        "0000000000000000000000000000000000000000000000000000000000000005",
    );
    let pk = build_pk(
        "5a7c8825e85691cce1f5e7544c54e73f14afc010cb731343262ca7ec5a77f5bf",
        "ef6edf62a4497c1bd7b147fb6c3d22af3c39bfce95f30e13a16d3d7b2812f813",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 120 failed");
    // 117] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #124: small r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000005",
        "0000000000000000000000000000000000000000000000000000000000000006",
    );
    let pk = build_pk(
        "cbe0c29132cd738364fedd603152990c048e5e2fff996d883fa6caca7978c737",
        "70af6a8ce44cb41224b2603606f4c04d188e80bff7cc31ad5189d4ab0d70e8c1",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 121 failed");
    // 118] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #126: r is larger than n
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632556",
        "0000000000000000000000000000000000000000000000000000000000000006",
    );
    let pk = build_pk(
        "cbe0c29132cd738364fedd603152990c048e5e2fff996d883fa6caca7978c737",
        "70af6a8ce44cb41224b2603606f4c04d188e80bff7cc31ad5189d4ab0d70e8c1",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 122 should fail");
    // 119] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #127: s is larger than n
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000005",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc75fbd8",
    );
    let pk = build_pk(
        "4be4178097002f0deab68f0d9a130e0ed33a6795d02a20796db83444b037e139",
        "20f13051e0eecdcfce4dacea0f50d1f247caa669f193c1b4075b51ae296d2d56",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 123 should fail");
    // 120] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #128: small r and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000100",
        "8f1e3c7862c58b16bb76eddbb76eddbb516af4f63f2d74d76e0d28c9bb75ea88",
    );
    let pk = build_pk(
        "d0f73792203716afd4be4329faa48d269f15313ebbba379d7783c97bf3e890d9",
        "971f4a3206605bec21782bf5e275c714417e8f566549e6bc68690d2363c89cc1",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 124 failed");
    // 121] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #129: smallish r and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "000000000000000000000000000000000000000000000000002d9b4d347952d6",
        "ef3043e7329581dbb3974497710ab11505ee1c87ff907beebadd195a0ffe6d7a",
    );
    let pk = build_pk(
        "4838b2be35a6276a80ef9e228140f9d9b96ce83b7a254f71ccdebbb8054ce05f",
        "fa9cbc123c919b19e00238198d04069043bd660a828814051fcb8aac738a6c6b",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 125 failed");
    // 122] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #130: 100-bit r and small s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "000000000000000000000000000000000000001033e67e37b32b445580bf4eff",
        "8b748b74000000008b748b748b748b7466e769ad4a16d3dcd87129b8e91d1b4d",
    );
    let pk = build_pk(
        "7393983ca30a520bbc4783dc9960746aab444ef520c0a8e771119aa4e74b0f64",
        "e9d7be1ab01a0bf626e709863e6a486dbaf32793afccf774e2c6cd27b1857526",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 126 failed");
    // 123] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #131: small r and 100 bit s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000100",
        "ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
    );
    let pk = build_pk(
        "5ac331a1103fe966697379f356a937f350588a05477e308851b8a502d5dfcdc5",
        "fe9993df4b57939b2b8da095bf6d794265204cfe03be995a02e65d408c871c0b",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 127 failed");
    // 124] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #132: 100-bit r and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "00000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c25",
        "ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
    );
    let pk = build_pk(
        "1d209be8de2de877095a399d3904c74cc458d926e27bb8e58e5eae5767c41509",
        "dd59e04c214f7b18dce351fc2a549893a6860e80163f38cc60a4f2c9d040d8c9",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 128 failed");
    // 125] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #133: r and s^-1 are close to n
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6324d5",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "083539fbee44625e3acaafa2fcb41349392cef0633a1b8fabecee0c133b10e99",
        "915c1ebe7bf00df8535196770a58047ae2a402f26326bb7d41d4d7616337911e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 129 failed");
    // 126] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #134: s == 1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "8aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e19373874",
        "05bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf576d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 130 failed");
    // 127] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #135: s == 0
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "8aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e19373874",
        "05bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf576d",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 131 should fail");
    // 128] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #136: point at infinity during verify
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "b533d4695dd5b8c5e07757e55e6e516f7e2c88fa0239e23f60e8ec07dd70f287",
        "1b134ee58cc583278456863f33c3a85d881f7d4a39850143e29d4eaf009afe47",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 132 should fail");
    // 129] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #137: edge case for signature malleability
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
    );
    let pk = build_pk(
        "f50d371b91bfb1d7d14e1323523bc3aa8cbf2c57f9e284de628c8b4536787b86",
        "f94ad887ac94d527247cd2e7d0c8b1291c553c9730405380b14cbb209f5fa2dd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 133 failed");
    // 130] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #138: edge case for signature malleability
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
    );
    let pk = build_pk(
        "68ec6e298eafe16539156ce57a14b04a7047c221bafc3a582eaeb0d857c4d946",
        "97bed1af17850117fdb39b2324f220a5698ed16c426a27335bb385ac8ca6fb30",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 134 failed");
    // 131] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #139: u1 == 1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
    );
    let pk = build_pk(
        "69da0364734d2e530fece94019265fefb781a0f1b08f6c8897bdf6557927c8b8",
        "66d2d3c7dcd518b23d726960f069ad71a933d86ef8abbcce8b20f71e2a847002",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 135 failed");
    // 132] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #140: u1 == n - 1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e",
    );
    let pk = build_pk(
        "d8adc00023a8edc02576e2b63e3e30621a471e2b2320620187bf067a1ac1ff32",
        "33e2b50ec09807accb36131fff95ed12a09a86b4ea9690aa32861576ba2362e1",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 136 failed");
    // 133] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #141: u2 == 1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "3623ac973ced0a56fa6d882f03a7d5c7edca02cfc7b2401fab3690dbe75ab785",
        "8db06908e64b28613da7257e737f39793da8e713ba0643b92e9bb3252be7f8fe",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 137 failed");
    // 134] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #142: u2 == n - 1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
    );
    let pk = build_pk(
        "cf04ea77e9622523d894b93ff52dc3027b31959503b6fa3890e5e04263f922f1",
        "e8528fb7c006b3983c8b8400e57b4ed71740c2f3975438821199bedeaecab2e9",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 138 failed");
    // 135] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #143: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "e91e1ba60fdedb76a46bcb51dc0b8b4b7e019f0a28721885fa5d3a8196623397",
    );
    let pk = build_pk(
        "db7a2c8a1ab573e5929dc24077b508d7e683d49227996bda3e9f78dbeff77350",
        "4f417f3bc9a88075c2e0aadd5a13311730cf7cc76a82f11a36eaf08a6c99a206",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 139 failed");
    // 136] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #144: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "fdea5843ffeb73af94313ba4831b53fe24f799e525b1e8e8c87b59b95b430ad9",
    );
    let pk = build_pk(
        "dead11c7a5b396862f21974dc4752fadeff994efe9bbd05ab413765ea80b6e1f",
        "1de3f0640e8ac6edcf89cff53c40e265bb94078a343736df07aa0318fc7fe1ff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 140 failed");
    // 137] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #145: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "03ffcabf2f1b4d2a65190db1680d62bb994e41c5251cd73b3c3dfc5e5bafc035",
    );
    let pk = build_pk(
        "d0bc472e0d7c81ebaed3a6ef96c18613bb1fea6f994326fbe80e00dfde67c7e9",
        "986c723ea4843d48389b946f64ad56c83ad70ff17ba85335667d1bb9fa619efd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 141 failed");
    // 138] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #146: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "4dfbc401f971cd304b33dfdb17d0fed0fe4c1a88ae648e0d2847f74977534989",
    );
    let pk = build_pk(
        "a0a44ca947d66a2acb736008b9c08d1ab2ad03776e02640f78495d458dd51c32",
        "6337fe5cf8c4604b1f1c409dc2d872d4294a4762420df43a30a2392e40426add",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 142 failed");
    // 139] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #147: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bc4024761cd2ffd43dfdb17d0fed112b988977055cd3a8e54971eba9cda5ca71",
    );
    let pk = build_pk(
        "c9c2115290d008b45fb65fad0f602389298c25420b775019d42b62c3ce8a96b7",
        "3877d25a8080dc02d987ca730f0405c2c9dbefac46f9e601cc3f06e9713973fd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 143 failed");
    // 140] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #148: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "788048ed39a5ffa77bfb62fa1fda2257742bf35d128fb3459f2a0c909ee86f91",
    );
    let pk = build_pk(
        "5eca1ef4c287dddc66b8bccf1b88e8a24c0018962f3c5e7efa83bc1a5ff6033e",
        "5e79c4cb2c245b8c45abdce8a8e4da758d92a607c32cd407ecaef22f1c934a71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 144 failed");
    // 141] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #149: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "476d9131fd381bd917d0fed112bc9e0a5924b5ed5b11167edd8b23582b3cb15e",
    );
    let pk = build_pk(
        "5caaa030e7fdf0e4936bc7ab5a96353e0a01e4130c3f8bf22d473e317029a47a",
        "deb6adc462f7058f2a20d371e9702254e9b201642005b3ceda926b42b178bef9",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 145 failed");
    // 142] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #150: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "8374253e3e21bd154448d0a8f640fe46fafa8b19ce78d538f6cc0a19662d3601",
    );
    let pk = build_pk(
        "c2fd20bac06e555bb8ac0ce69eb1ea20f83a1fc3501c8a66469b1a31f619b098",
        "6237050779f52b615bd7b8d76a25fc95ca2ed32525c75f27ffc87ac397e6cbaf",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 146 failed");
    // 143] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #151: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "357cfd3be4d01d413c5b9ede36cba5452c11ee7fe14879e749ae6a2d897a52d6",
    );
    let pk = build_pk(
        "3fd6a1ca7f77fb3b0bbe726c372010068426e11ea6ae78ce17bedae4bba86ced",
        "03ce5516406bf8cfaab8745eac1cd69018ad6f50b5461872ddfc56e0db3c8ff4",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 147 failed");
    // 144] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #152: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "29798c5c0ee287d4a5e8e6b799fd86b8df5225298e6ffc807cd2f2bc27a0a6d8",
    );
    let pk = build_pk(
        "9cb8e51e27a5ae3b624a60d6dc32734e4989db20e9bca3ede1edf7b086911114",
        "b4c104ab3c677e4b36d6556e8ad5f523410a19f2e277aa895fc57322b4427544",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 148 failed");
    // 145] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #153: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "0b70f22c781092452dca1a5711fa3a5a1f72add1bf52c2ff7cae4820b30078dd",
    );
    let pk = build_pk(
        "a3e52c156dcaf10502620b7955bc2b40bc78ef3d569e1223c262512d8f49602a",
        "4a2039f31c1097024ad3cc86e57321de032355463486164cf192944977df147f",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 149 failed");
    // 146] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #154: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "16e1e458f021248a5b9434ae23f474b43ee55ba37ea585fef95c90416600f1ba",
    );
    let pk = build_pk(
        "f19b78928720d5bee8e670fb90010fb15c37bf91b58a5157c3f3c059b2655e88",
        "cf701ec962fb4a11dcf273f5dc357e58468560c7cfeb942d074abd4329260509",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 150 failed");
    // 147] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #155: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "2252d6856831b6cf895e4f0535eeaf0e5e5809753df848fe760ad86219016a97",
    );
    let pk = build_pk(
        "83a744459ecdfb01a5cf52b27a05bb7337482d242f235d7b4cb89345545c90a8",
        "c05d49337b9649813287de9ffe90355fd905df5f3c32945828121f37cc50de6e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 151 failed");
    // 148] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #156: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "81ffe55f178da695b28c86d8b406b15dab1a9e39661a3ae017fbe390ac0972c3",
    );
    let pk = build_pk(
        "dd13c6b34c56982ddae124f039dfd23f4b19bbe88cee8e528ae51e5d6f3a21d7",
        "bfad4c2e6f263fe5eb59ca974d039fc0e4c3345692fb5320bdae4bd3b42a45ff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 152 failed");
    // 149] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #157: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "7fffffffaaaaaaaaffffffffffffffffe9a2538f37b28a2c513dee40fecbb71a",
    );
    let pk = build_pk(
        "67e6f659cdde869a2f65f094e94e5b4dfad636bbf95192feeed01b0f3deb7460",
        "a37e0a51f258b7aeb51dfe592f5cfd5685bbe58712c8d9233c62886437c38ba0",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 153 failed");
    // 150] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #158: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "b62f26b5f2a2b26f6de86d42ad8a13da3ab3cccd0459b201de009e526adf21f2",
    );
    let pk = build_pk(
        "2eb6412505aec05c6545f029932087e490d05511e8ec1f599617bb367f9ecaaf",
        "805f51efcc4803403f9b1ae0124890f06a43fedcddb31830f6669af292895cb0",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 154 failed");
    // 151] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #159: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bb1d9ac949dd748cd02bbbe749bd351cd57b38bb61403d700686aa7b4c90851e",
    );
    let pk = build_pk(
        "84db645868eab35e3a9fd80e056e2e855435e3a6b68d75a50a854625fe0d7f35",
        "6d2589ac655edc9a11ef3e075eddda9abf92e72171570ef7bf43a2ee39338cfe",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 155 failed");
    // 152] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #160: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "66755a00638cdaec1c732513ca0234ece52545dac11f816e818f725b4f60aaf2",
    );
    let pk = build_pk(
        "91b9e47c56278662d75c0983b22ca8ea6aa5059b7a2ff7637eb2975e386ad663",
        "49aa8ff283d0f77c18d6d11dc062165fd13c3c0310679c1408302a16854ecfbd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 156 failed");
    // 153] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #161: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "55a00c9fcdaebb6032513ca0234ecfffe98ebe492fdf02e48ca48e982beb3669",
    );
    let pk = build_pk(
        "f3ec2f13caf04d0192b47fb4c5311fb6d4dc6b0a9e802e5327f7ec5ee8e4834d",
        "f97e3e468b7d0db867d6ecfe81e2b0f9531df87efdb47c1338ac321fefe5a432",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 157 failed");
    // 154] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #162: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "ab40193f9b5d76c064a27940469d9fffd31d7c925fbe05c919491d3057d66cd2",
    );
    let pk = build_pk(
        "d92b200aefcab6ac7dafd9acaf2fa10b3180235b8f46b4503e4693c670fccc88",
        "5ef2f3aebf5b317475336256768f7c19efb7352d27e4cccadc85b6b8ab922c72",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 158 failed");
    // 155] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #163: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "ca0234ebb5fdcb13ca0234ecffffffffcb0dadbbc7f549f8a26b4408d0dc8600",
    );
    let pk = build_pk(
        "0a88361eb92ecca2625b38e5f98bbabb96bf179b3d76fc48140a3bcd881523cd",
        "e6bdf56033f84a5054035597375d90866aa2c96b86a41ccf6edebf47298ad489",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 159 failed");
    // 156] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #164: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff3ea3677e082b9310572620ae19933a9e65b285598711c77298815ad3",
    );
    let pk = build_pk(
        "d0fb17ccd8fafe827e0c1afc5d8d80366e2b20e7f14a563a2ba50469d84375e8",
        "68612569d39e2bb9f554355564646de99ac602cc6349cf8c1e236a7de7637d93",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 160 failed");
    // 157] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #165: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "266666663bbbbbbbe6666666666666665b37902e023fab7c8f055d86e5cc41f4",
    );
    let pk = build_pk(
        "836f33bbc1dc0d3d3abbcef0d91f11e2ac4181076c9af0a22b1e4309d3edb276",
        "9ab443ff6f901e30c773867582997c2bec2b0cb8120d760236f3a95bbe881f75",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 161 failed");
    // 158] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #166: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff36db6db7a492492492492492146c573f4c6dfc8d08a443e258970b09",
    );
    let pk = build_pk(
        "92f99fbe973ed4a299719baee4b432741237034dec8d72ba5103cb33e55feeb8",
        "033dd0e91134c734174889f3ebcf1b7a1ac05767289280ee7a794cebd6e69697",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 162 failed");
    // 159] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #167: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff2aaaaaab7fffffffffffffffc815d0e60b3e596ecb1ad3a27cfd49c4",
    );
    let pk = build_pk(
        "d35ba58da30197d378e618ec0fa7e2e2d12cffd73ebbb2049d130bba434af09e",
        "ff83986e6875e41ea432b7585a49b3a6c77cbb3c47919f8e82874c794635c1d2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 163 failed");
    // 160] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #168: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "7fffffff55555555ffffffffffffffffd344a71e6f651458a27bdc81fd976e37",
    );
    let pk = build_pk(
        "8651ce490f1b46d73f3ff475149be29136697334a519d7ddab0725c8d0793224",
        "e11c65bd8ca92dc8bc9ae82911f0b52751ce21dd9003ae60900bd825f590cc28",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 164 failed");
    // 161] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #169: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "3fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192aa",
    );
    let pk = build_pk(
        "6d8e1b12c831a0da8795650ff95f101ed921d9e2f72b15b1cdaca9826b9cfc6d",
        "ef6d63e2bc5c089570394a4bc9f892d5e6c7a6a637b20469a58c106ad486bf37",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 165 failed");
    // 162] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #170: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "5d8ecd64a4eeba466815ddf3a4de9a8e6abd9c5db0a01eb80343553da648428f",
    );
    let pk = build_pk(
        "0ae580bae933b4ef2997cbdbb0922328ca9a410f627a0f7dff24cb4d920e1542",
        "8911e7f8cc365a8a88eb81421a361ccc2b99e309d8dcd9a98ba83c3949d893e3",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 166 failed");
    // 163] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #171: point duplication during verification
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569",
        "bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
    );
    let pk = build_pk(
        "5b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc46963",
        "838a40f2a36092e9004e92d8d940cf5638550ce672ce8b8d4e15eba5499249e9",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 167 failed");
    // 164] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #172: duplication bug
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569",
        "bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
    );
    let pk = build_pk(
        "5b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc46963",
        "7c75bf0c5c9f6d17ffb16d2726bf30a9c7aaf31a8d317472b1ea145ab66db616",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 168 should fail");
    // 165] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #173: point with x-coordinate 0
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "6adda82b90261b0f319faa0d878665a6b6da497f09c903176222c34acfef72a6",
        "47e6f50dcc40ad5d9b59f7602bb222fad71a41bf5e1f9df4959a364c62e488d9",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 169 should fail");
    // 166] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #175: comparison with point at infinity
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aa9",
    );
    let pk = build_pk(
        "dd86d3b5f4a13e8511083b78002081c53ff467f11ebd98a51a633db76665d250",
        "45d5c8200c89f2fa10d849349226d21d8dfaed6ff8d5cb3e1b7e17474ebc18f7",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 170 should fail");
    // 167] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #176: extreme value for k and edgecase s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "4fea55b32cb32aca0c12c4cd0abfb4e64b0f5a516e578c016591a93f5a0fbcc5",
        "d7d3fd10b2be668c547b212f6bb14c88f0fecd38a8a4b2c785ed3be62ce4b280",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 171 failed");
    // 168] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #177: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
    );
    let pk = build_pk(
        "c6a771527024227792170a6f8eee735bf32b7f98af669ead299802e32d7c3107",
        "bc3b4b5e65ab887bbd343572b3e5619261fe3a073e2ffd78412f726867db589e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 172 failed");
    // 169] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #178: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
    );
    let pk = build_pk(
        "851c2bbad08e54ec7a9af99f49f03644d6ec6d59b207fec98de85a7d15b956ef",
        "cee9960283045075684b410be8d0f7494b91aa2379f60727319f10ddeb0fe9d6",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 173 failed");
    // 170] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #179: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
    );
    let pk = build_pk(
        "f6417c8a670584e388676949e53da7fc55911ff68318d1bf3061205acb19c48f",
        "8f2b743df34ad0f72674acb7505929784779cd9ac916c3669ead43026ab6d43f",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 174 failed");
    // 171] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #180: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "49249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
    );
    let pk = build_pk(
        "501421277be45a5eefec6c639930d636032565af420cf3373f557faa7f8a0643",
        "8673d6cb6076e1cfcdc7dfe7384c8e5cac08d74501f2ae6e89cad195d0aa1371",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 175 failed");
    // 172] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #181: extreme value for k
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "16a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
    );
    let pk = build_pk(
        "0d935bf9ffc115a527735f729ca8a4ca23ee01a4894adf0e3415ac84e808bb34",
        "3195a3762fea29ed38912bd9ea6c4fde70c3050893a4375850ce61d82eba33c5",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 176 failed");
    // 173] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #182: extreme value for k and edgecase s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "5e59f50708646be8a589355014308e60b668fb670196206c41e748e64e4dca21",
        "5de37fee5c97bcaf7144d5b459982f52eeeafbdf03aacbafef38e213624a01de",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 177 failed");
    // 174] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #183: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
    );
    let pk = build_pk(
        "169fb797325843faff2f7a5b5445da9e2fd6226f7ef90ef0bfe924104b02db8e",
        "7bbb8de662c7b9b1cf9b22f7a2e582bd46d581d68878efb2b861b131d8a1d667",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 178 failed");
    // 175] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #184: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
    );
    let pk = build_pk(
        "271cd89c000143096b62d4e9e4ca885aef2f7023d18affdaf8b7b54898148754",
        "0a1c6e954e32108435b55fa385b0f76481a609b9149ccb4b02b2ca47fe8e4da5",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 179 failed");
    // 176] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #185: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
    );
    let pk = build_pk(
        "3d0bc7ed8f09d2cb7ddb46ebc1ed799ab1563a9ab84bf524587a220afe499c12",
        "e22dc3b3c103824a4f378d96adb0a408abf19ce7d68aa6244f78cb216fa3f8df",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 180 failed");
    // 177] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #186: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "49249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
    );
    let pk = build_pk(
        "a6c885ade1a4c566f9bb010d066974abb281797fa701288c721bcbd23663a9b7",
        "2e424b690957168d193a6096fc77a2b004a9c7d467e007e1f2058458f98af316",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 181 failed");
    // 178] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #187: extreme value for k
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "16a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
    );
    let pk = build_pk(
        "8d3c2c2c3b765ba8289e6ac3812572a25bf75df62d87ab7330c3bdbad9ebfa5c",
        "4c6845442d66935b238578d43aec54f7caa1621d1af241d4632e0b780c423f5d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 182 failed");
    // 179] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #188: testing point duplication
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 183 should fail");
    // 180] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #189: testing point duplication
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 184 should fail");
    // 181] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #190: testing point duplication
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 185 should fail");
    // 182] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #191: testing point duplication
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 186 should fail");
    // 183] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #192: pseudorandom signature
    let msg = hex_to_32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    let sig = build_sig(
        "b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a",
        "0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 187 failed");
    // 184] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #193: pseudorandom signature
    let msg = hex_to_32("dc1921946f4af96a2856e7be399007c9e807bdf4c5332f19f59ec9dd1bb8c7b3");
    let sig = build_sig(
        "530bd6b0c9af2d69ba897f6b5fb59695cfbf33afe66dbadcf5b8d2a2a6538e23",
        "d85e489cb7a161fd55ededcedbf4cc0c0987e3e3f0f242cae934c72caa3f43e9",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 188 failed");
    // 185] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #194: pseudorandom signature
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "a8ea150cb80125d7381c4c1f1da8e9de2711f9917060406a73d7904519e51388",
        "f3ab9fa68bd47973a73b2d40480c2ba50c22c9d76ec217257288293285449b86",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 189 failed");
    // 186] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #195: pseudorandom signature
    let msg = hex_to_32("de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90");
    let sig = build_sig(
        "986e65933ef2ed4ee5aada139f52b70539aaf63f00a91f29c69178490d57fb71",
        "3dafedfb8da6189d372308cbf1489bbbdabf0c0217d1c0ff0f701aaa7a694b9c",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 190 failed");
    // 187] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #196: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d434e262a49eab7781e353a3565e482550dd0fd5defa013c7f29745eff3569f1",
        "9b0c0a93f267fb6052fd8077be769c2b98953195d7bc10de844218305c6ba17a",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 191 failed");
    // 188] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #197: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "0fe774355c04d060f76d79fd7a772e421463489221bf0a33add0be9b1979110b",
        "500dcba1c69a8fbd43fa4f57f743ce124ca8b91a1f325f3fac6181175df55737",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 192 failed");
    // 189] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #198: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "bb40bf217bed3fb3950c7d39f03d36dc8e3b2cd79693f125bfd06595ee1135e3",
        "541bf3532351ebb032710bdb6a1bf1bfc89a1e291ac692b3fa4780745bb55677",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 193 failed");
    // 190] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #199: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "664eb7ee6db84a34df3c86ea31389a5405badd5ca99231ff556d3e75a233e73a",
        "59f3c752e52eca46137642490a51560ce0badc678754b8f72e51a2901426a1bd",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 194 failed");
    // 191] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #200: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "4cd0429bbabd2827009d6fcd843d4ce39c3e42e2d1631fd001985a79d1fd8b43",
        "9638bf12dd682f60be7ef1d0e0d98f08b7bca77a1a2b869ae466189d2acdabe3",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 195 failed");
    // 192] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #201: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "e56c6ea2d1b017091c44d8b6cb62b9f460e3ce9aed5e5fd41e8added97c56c04",
        "a308ec31f281e955be20b457e463440b4fcf2b80258078207fc1378180f89b55",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 196 failed");
    // 193] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #202: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "1158a08d291500b4cabed3346d891eee57c176356a2624fb011f8fbbf3466830",
        "228a8c486a736006e082325b85290c5bc91f378b75d487dda46798c18f285519",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 197 failed");
    // 194] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #203: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b1db9289649f59410ea36b0c0fc8d6aa2687b29176939dd23e0dde56d309fa9d",
        "3e1535e4280559015b0dbd987366dcf43a6d1af5c23c7d584e1c3f48a1251336",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 198 failed");
    // 195] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #204: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b7b16e762286cb96446aa8d4e6e7578b0a341a79f2dd1a220ac6f0ca4e24ed86",
        "ddc60a700a139b04661c547d07bbb0721780146df799ccf55e55234ecb8f12bc",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 199 failed");
    // 196] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #205: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d82a7c2717261187c8e00d8df963ff35d796edad36bc6e6bd1c91c670d9105b4",
        "3dcabddaf8fcaa61f4603e7cbac0f3c0351ecd5988efb23f680d07debd139929",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 200 failed");
    // 197] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #206: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "5eb9c8845de68eb13d5befe719f462d77787802baff30ce96a5cba063254af78",
        "2c026ae9be2e2a5e7ca0ff9bbd92fb6e44972186228ee9a62b87ddbe2ef66fb5",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 201 failed");
    // 198] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #207: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "96843dd03c22abd2f3b782b170239f90f277921becc117d0404a8e4e36230c28",
        "f2be378f526f74a543f67165976de9ed9a31214eb4d7e6db19e1ede123dd991d",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 202 failed");
    // 199] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #208: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "766456dce1857c906f9996af729339464d27e9d98edc2d0e3b760297067421f6",
        "402385ecadae0d8081dccaf5d19037ec4e55376eced699e93646bfbbf19d0b41",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 203 failed");
    // 200] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #209: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "c605c4b2edeab20419e6518a11b2dbc2b97ed8b07cced0b19c34f777de7b9fd9",
        "edf0f612c5f46e03c719647bc8af1b29b2cde2eda700fb1cff5e159d47326dba",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 204 failed");
    // 201] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #210: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d48b68e6cabfe03cf6141c9ac54141f210e64485d9929ad7b732bfe3b7eb8a84",
        "feedae50c61bd00e19dc26f9b7e2265e4508c389109ad2f208f0772315b6c941",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 205 failed");
    // 202] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #211: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b7c81457d4aeb6aa65957098569f0479710ad7f6595d5874c35a93d12a5dd4c7",
        "b7961a0b652878c2d568069a432ca18a1a9199f2ca574dad4b9e3a05c0a1cdb3",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 206 failed");
    // 203] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #212: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "6b01332ddb6edfa9a30a1321d5858e1ee3cf97e263e669f8de5e9652e76ff3f7",
        "5939545fced457309a6a04ace2bd0f70139c8f7d86b02cb1cc58f9e69e96cd5a",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 207 failed");
    // 204] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #213: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "efdb884720eaeadc349f9fc356b6c0344101cd2fd8436b7d0e6a4fb93f106361",
        "f24bee6ad5dc05f7613975473aadf3aacba9e77de7d69b6ce48cb60d8113385d",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 208 failed");
    // 205] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #214: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "31230428405560dcb88fb5a646836aea9b23a23dd973dcbe8014c87b8b20eb07",
        "0f9344d6e812ce166646747694a41b0aaf97374e19f3c5fb8bd7ae3d9bd0beff",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 209 failed");
    // 206] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #215: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "caa797da65b320ab0d5c470cda0b36b294359c7db9841d679174db34c4855743",
        "cf543a62f23e212745391aaf7505f345123d2685ee3b941d3de6d9b36242e5a0",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 210 failed");
    // 207] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #216: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "7e5f0ab5d900d3d3d7867657e5d6d36519bc54084536e7d21c336ed800185945",
        "9450c07f201faec94b82dfb322e5ac676688294aad35aa72e727ff0b19b646aa",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 211 failed");
    // 208] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #217: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d7d70c581ae9e3f66dc6a480bf037ae23f8a1e4a2136fe4b03aa69f0ca25b356",
        "89c460f8a5a5c2bbba962c8a3ee833a413e85658e62a59e2af41d9127cc47224",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 212 failed");
    // 209] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #218: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "341c1b9ff3c83dd5e0dfa0bf68bcdf4bb7aa20c625975e5eeee34bb396266b34",
        "72b69f061b750fd5121b22b11366fad549c634e77765a017902a67099e0a4469",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 213 failed");
    // 210] wycheproof/ecdsa_secp256r1_sha256_p1363_test.json EcdsaP1363Verify SHA-256 #219: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67",
        "aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 214 failed");
    // 211] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #1: signature malleability
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "4cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 215 failed");
    // 212] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #2: Legacy:ASN encoding of s misses leading 0
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 216 failed");
    // 213] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #3: valid
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 217 failed");
    // 214] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #118: modify first byte of integer
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "29a3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 218 should fail");
    // 215] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #120: modify last byte of integer
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e98",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 219 should fail");
    // 216] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #121: modify last byte of integer
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b491568475b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 220 should fail");
    // 217] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #124: truncated integer
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "00b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 221 should fail");
    // 218] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #133: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "d45c5741946b2a137f59262ee6f5bc91001af27a5e1117a64733950642a3d1e8",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 222 should fail");
    // 219] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #134: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 223 should fail");
    // 220] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #137: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "d45c5741946b2a137f59262ee6f5bc91001af27a5e1117a64733950642a3d1e8",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 224 should fail");
    // 221] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #139: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "b329f47aa2bbd0a4c384ee1493b1f518ada018ef05465583885980861905228a",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 225 should fail");
    // 222] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #143: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "4cd60b865d442f5a3c7b11eb6c4e0ae79578ec6353a20bf783ecb4b6ea97b825",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 226 should fail");
    // 223] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #177: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 227 should fail");
    // 224] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #178: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 228 should fail");
    // 225] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #179: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 229 should fail");
    // 226] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #180: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 230 should fail");
    // 227] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #181: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 231 should fail");
    // 228] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #187: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 232 should fail");
    // 229] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #188: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 233 should fail");
    // 230] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #189: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 234 should fail");
    // 231] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #190: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 235 should fail");
    // 232] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #191: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 236 should fail");
    // 233] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #197: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 237 should fail");
    // 234] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #198: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 238 should fail");
    // 235] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #199: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 239 should fail");
    // 236] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #200: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 240 should fail");
    // 237] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #201: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 241 should fail");
    // 238] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #207: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 242 should fail");
    // 239] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #208: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 243 should fail");
    // 240] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #209: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 244 should fail");
    // 241] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #210: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 245 should fail");
    // 242] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #211: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 246 should fail");
    // 243] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #217: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 247 should fail");
    // 244] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #218: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 248 should fail");
    // 245] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #219: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 249 should fail");
    // 246] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #220: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 250 should fail");
    // 247] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #221: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 251 should fail");
    // 248] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #230: Edge case for Shamir multiplication
    let msg = hex_to_32("70239dd877f7c944c422f44dea4ed1a52f2627416faf2f072fa50c772ed6f807");
    let sig = build_sig(
        "64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e",
        "6af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 252 failed");
    // 249] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #231: special case hash
    let msg = hex_to_32("00000000690ed426ccf17803ebe2bd0884bcd58a1bb5e7477ead3645f356e7a9");
    let sig = build_sig(
        "16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf266",
        "252cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 253 failed");
    // 250] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #232: special case hash
    let msg = hex_to_32("7300000000213f2a525c6035725235c2f696ad3ebb5ee47f140697ad25770d91");
    let sig = build_sig(
        "9cc98be2347d469bf476dfc26b9b733df2d26d6ef524af917c665baccb23c882",
        "093496459effe2d8d70727b82462f61d0ec1b7847929d10ea631dacb16b56c32",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 254 failed");
    // 251] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #233: special case hash
    let msg = hex_to_32("ddf2000000005e0be0635b245f0b97978afd25daadeb3edb4a0161c27fe06045");
    let sig = build_sig(
        "73b3c90ecd390028058164524dde892703dce3dea0d53fa8093999f07ab8aa43",
        "2f67b0b8e20636695bb7d8bf0a651c802ed25a395387b5f4188c0c4075c88634",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 255 failed");
    // 252] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #234: special case hash
    let msg = hex_to_32("67ab1900000000784769c4ecb9e164d6642b8499588b89855be1ec355d0841a0");
    let sig = build_sig(
        "bfab3098252847b328fadf2f89b95c851a7f0eb390763378f37e90119d5ba3dd",
        "bdd64e234e832b1067c2d058ccb44d978195ccebb65c2aaf1e2da9b8b4987e3b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 256 failed");
    // 253] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #235: special case hash
    let msg = hex_to_32("a2bf09460000000076d7dbeffe125eaf02095dff252ee905e296b6350fc311cf");
    let sig = build_sig(
        "204a9784074b246d8bf8bf04a4ceb1c1f1c9aaab168b1596d17093c5cd21d2cd",
        "51cce41670636783dc06a759c8847868a406c2506fe17975582fe648d1d88b52",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 257 failed");
    // 254] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #236: special case hash
    let msg = hex_to_32("3554e827c700000000e1e75e624a06b3a0a353171160858129e15c544e4f0e65");
    let sig = build_sig(
        "ed66dc34f551ac82f63d4aa4f81fe2cb0031a91d1314f835027bca0f1ceeaa03",
        "99ca123aa09b13cd194a422e18d5fda167623c3f6e5d4d6abb8953d67c0c48c7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 258 failed");
    // 255] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #237: special case hash
    let msg = hex_to_32("9b6cd3b812610000000026941a0f0bb53255ea4c9fd0cb3426e3a54b9fc6965c");
    let sig = build_sig(
        "060b700bef665c68899d44f2356a578d126b062023ccc3c056bf0f60a237012b",
        "8d186c027832965f4fcc78a3366ca95dedbb410cbef3f26d6be5d581c11d3610",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 259 failed");
    // 256] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #238: special case hash
    let msg = hex_to_32("883ae39f50bf0100000000e7561c26fc82a52baa51c71ca877162f93c4ae0186");
    let sig = build_sig(
        "9f6adfe8d5eb5b2c24d7aa7934b6cf29c93ea76cd313c9132bb0c8e38c96831d",
        "b26a9c9e40e55ee0890c944cf271756c906a33e66b5bd15e051593883b5e9902",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 260 failed");
    // 257] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #239: special case hash
    let msg = hex_to_32("a1ce5d6e5ecaf28b0000000000fa7cd010540f420fb4ff7401fe9fce011d0ba6");
    let sig = build_sig(
        "a1af03ca91677b673ad2f33615e56174a1abf6da168cebfa8868f4ba273f16b7",
        "20aa73ffe48afa6435cd258b173d0c2377d69022e7d098d75caf24c8c5e06b1c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 261 failed");
    // 258] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #240: special case hash
    let msg = hex_to_32("8ea5f645f373f580930000000038345397330012a8ee836c5494cdffd5ee8054");
    let sig = build_sig(
        "fdc70602766f8eed11a6c99a71c973d5659355507b843da6e327a28c11893db9",
        "3df5349688a085b137b1eacf456a9e9e0f6d15ec0078ca60a7f83f2b10d21350",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 262 failed");
    // 259] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #241: special case hash
    let msg = hex_to_32("660570d323e9f75fa734000000008792d65ce93eabb7d60d8d9c1bbdcb5ef305");
    let sig = build_sig(
        "b516a314f2fce530d6537f6a6c49966c23456f63c643cf8e0dc738f7b876e675",
        "d39ffd033c92b6d717dd536fbc5efdf1967c4bd80954479ba66b0120cd16fff2",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 263 failed");
    // 260] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #242: special case hash
    let msg = hex_to_32("d0462673154cce587dde8800000000e98d35f1f45cf9c3bf46ada2de4c568c34");
    let sig = build_sig(
        "3b2cbf046eac45842ecb7984d475831582717bebb6492fd0a485c101e29ff0a8",
        "4c9b7b47a98b0f82de512bc9313aaf51701099cac5f76e68c8595fc1c1d99258",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 264 failed");
    // 261] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #243: special case hash
    let msg = hex_to_32("bd90640269a7822680cedfef000000000caef15a6171059ab83e7b4418d7278f");
    let sig = build_sig(
        "30c87d35e636f540841f14af54e2f9edd79d0312cfa1ab656c3fb15bfde48dcf",
        "47c15a5a82d24b75c85a692bd6ecafeb71409ede23efd08e0db9abf6340677ed",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 265 failed");
    // 262] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #244: special case hash
    let msg = hex_to_32("33239a52d72f1311512e41222a00000000d2dcceb301c54b4beae8e284788a73");
    let sig = build_sig(
        "38686ff0fda2cef6bc43b58cfe6647b9e2e8176d168dec3c68ff262113760f52",
        "067ec3b651f422669601662167fa8717e976e2db5e6a4cf7c2ddabb3fde9d67d",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 266 failed");
    // 263] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #245: special case hash
    let msg = hex_to_32("b8d64fbcd4a1c10f1365d4e6d95c000000007ee4a21a1cbe1dc84c2d941ffaf1");
    let sig = build_sig(
        "44a3e23bf314f2b344fc25c7f2de8b6af3e17d27f5ee844b225985ab6e2775cf",
        "2d48e223205e98041ddc87be532abed584f0411f5729500493c9cc3f4dd15e86",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 267 failed");
    // 264] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #246: special case hash
    let msg = hex_to_32("01603d3982bf77d7a3fef3183ed092000000003a227420db4088b20fe0e9d84a");
    let sig = build_sig(
        "2ded5b7ec8e90e7bf11f967a3d95110c41b99db3b5aa8d330eb9d638781688e9",
        "7d5792c53628155e1bfc46fb1a67e3088de049c328ae1f44ec69238a009808f9",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 268 failed");
    // 265] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #247: special case hash
    let msg = hex_to_32("9ea6994f1e0384c8599aa02e6cf66d9c000000004d89ef50b7e9eb0cfbff7363");
    let sig = build_sig(
        "bdae7bcb580bf335efd3bc3d31870f923eaccafcd40ec2f605976f15137d8b8f",
        "f6dfa12f19e525270b0106eecfe257499f373a4fb318994f24838122ce7ec3c7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 269 failed");
    // 266] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #248: special case hash
    let msg = hex_to_32("d03215a8401bcf16693979371a01068a4700000000e2fa5bf692bc670905b18c");
    let sig = build_sig(
        "50f9c4f0cd6940e162720957ffff513799209b78596956d21ece251c2401f1c6",
        "d7033a0a787d338e889defaaabb106b95a4355e411a59c32aa5167dfab244726",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 270 failed");
    // 267] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #249: special case hash
    let msg = hex_to_32("307bfaaffb650c889c84bf83f0300e5dc87e000000008408fd5f64b582e3bb14");
    let sig = build_sig(
        "f612820687604fa01906066a378d67540982e29575d019aabe90924ead5c860d",
        "3f9367702dd7dd4f75ea98afd20e328a1a99f4857b316525328230ce294b0fef",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 271 failed");
    // 268] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #250: special case hash
    let msg = hex_to_32("bab5c4f4df540d7b33324d36bb0c157551527c00000000e4af574bb4d54ea6b8");
    let sig = build_sig(
        "9505e407657d6e8bc93db5da7aa6f5081f61980c1949f56b0f2f507da5782a7a",
        "c60d31904e3669738ffbeccab6c3656c08e0ed5cb92b3cfa5e7f71784f9c5021",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 272 failed");
    // 269] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #251: special case hash
    let msg = hex_to_32("d4ba47f6ae28f274e4f58d8036f9c36ec2456f5b00000000c3b869197ef5e15e");
    let sig = build_sig(
        "bbd16fbbb656b6d0d83e6a7787cd691b08735aed371732723e1c68a40404517d",
        "9d8e35dba96028b7787d91315be675877d2d097be5e8ee34560e3e7fd25c0f00",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 273 failed");
    // 270] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #252: special case hash
    let msg = hex_to_32("79fd19c7235ea212f29f1fa00984342afe0f10aafd00000000801e47f8c184e1");
    let sig = build_sig(
        "2ec9760122db98fd06ea76848d35a6da442d2ceef7559a30cf57c61e92df327e",
        "7ab271da90859479701fccf86e462ee3393fb6814c27b760c4963625c0a19878",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 274 failed");
    // 271] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #253: special case hash
    let msg = hex_to_32("8c291e8eeaa45adbaf9aba5c0583462d79cbeb7ac97300000000a37ea6700cda");
    let sig = build_sig(
        "54e76b7683b6650baa6a7fc49b1c51eed9ba9dd463221f7a4f1005a89fe00c59",
        "2ea076886c773eb937ec1cc8374b7915cfd11b1c1ae1166152f2f7806a31c8fd",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 275 failed");
    // 272] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #254: special case hash
    let msg = hex_to_32("0eaae8641084fa979803efbfb8140732f4cdcf66c3f78a000000003c278a6b21");
    let sig = build_sig(
        "5291deaf24659ffbbce6e3c26f6021097a74abdbb69be4fb10419c0c496c9466",
        "65d6fcf336d27cc7cdb982bb4e4ecef5827f84742f29f10abf83469270a03dc3",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 276 failed");
    // 273] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #255: special case hash
    let msg = hex_to_32("e02716d01fb23a5a0068399bf01bab42ef17c6d96e13846c00000000afc0f89d");
    let sig = build_sig(
        "207a3241812d75d947419dc58efb05e8003b33fc17eb50f9d15166a88479f107",
        "cdee749f2e492b213ce80b32d0574f62f1c5d70793cf55e382d5caadf7592767",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 277 failed");
    // 274] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #256: special case hash
    let msg = hex_to_32("9eb0bf583a1a6b9a194e9a16bc7dab2a9061768af89d00659a00000000fc7de1");
    let sig = build_sig(
        "6554e49f82a855204328ac94913bf01bbe84437a355a0a37c0dee3cf81aa7728",
        "aea00de2507ddaf5c94e1e126980d3df16250a2eaebc8be486effe7f22b4f929",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 278 failed");
    // 275] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #257: special case hash
    let msg = hex_to_32("62aac98818b3b84a2c214f0d5e72ef286e1030cb53d9a82b690e00000000cd15");
    let sig = build_sig(
        "a54c5062648339d2bff06f71c88216c26c6e19b4d80a8c602990ac82707efdfc",
        "e99bbe7fcfafae3e69fd016777517aa01056317f467ad09aff09be73c9731b0d",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 279 failed");
    // 276] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #258: special case hash
    let msg = hex_to_32("3760a7f37cf96218f29ae43732e513efd2b6f552ea4b6895464b9300000000c8");
    let sig = build_sig(
        "975bd7157a8d363b309f1f444012b1a1d23096593133e71b4ca8b059cff37eaf",
        "7faa7a28b1c822baa241793f2abc930bd4c69840fe090f2aacc46786bf919622",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 280 failed");
    // 277] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #259: special case hash
    let msg = hex_to_32("0da0a1d2851d33023834f2098c0880096b4320bea836cd9cbb6ff6c800000000");
    let sig = build_sig(
        "5694a6f84b8f875c276afd2ebcfe4d61de9ec90305afb1357b95b3e0da43885e",
        "0dffad9ffd0b757d8051dec02ebdf70d8ee2dc5c7870c0823b6ccc7c679cbaa4",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 281 failed");
    // 278] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #260: special case hash
    let msg = hex_to_32("ffffffff293886d3086fd567aafd598f0fe975f735887194a764a231e82d289a");
    let sig = build_sig(
        "a0c30e8026fdb2b4b4968a27d16a6d08f7098f1a98d21620d7454ba9790f1ba6",
        "5e470453a8a399f15baf463f9deceb53acc5ca64459149688bd2760c65424339",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 282 failed");
    // 279] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #261: special case hash
    let msg = hex_to_32("7bffffffff2376d1e3c03445a072e24326acdc4ce127ec2e0e8d9ca99527e7b7");
    let sig = build_sig(
        "614ea84acf736527dd73602cd4bb4eea1dfebebd5ad8aca52aa0228cf7b99a88",
        "737cc85f5f2d2f60d1b8183f3ed490e4de14368e96a9482c2a4dd193195c902f",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 283 failed");
    // 280] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #262: special case hash
    let msg = hex_to_32("a2b5ffffffffebb251b085377605a224bc80872602a6e467fd016807e97fa395");
    let sig = build_sig(
        "bead6734ebe44b810d3fb2ea00b1732945377338febfd439a8d74dfbd0f942fa",
        "6bb18eae36616a7d3cad35919fd21a8af4bbe7a10f73b3e036a46b103ef56e2a",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 284 failed");
    // 281] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #263: special case hash
    let msg = hex_to_32("641227ffffffff6f1b96fa5f097fcf3cc1a3c256870d45a67b83d0967d4b20c0");
    let sig = build_sig(
        "499625479e161dacd4db9d9ce64854c98d922cbf212703e9654fae182df9bad2",
        "42c177cf37b8193a0131108d97819edd9439936028864ac195b64fca76d9d693",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 285 failed");
    // 282] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #264: special case hash
    let msg = hex_to_32("958415d8ffffffffabad03e2fc662dc3ba203521177502298df56f36600e0f8b");
    let sig = build_sig(
        "08f16b8093a8fb4d66a2c8065b541b3d31e3bfe694f6b89c50fb1aaa6ff6c9b2",
        "9d6455e2d5d1779748573b611cb95d4a21f967410399b39b535ba3e5af81ca2e",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 286 failed");
    // 283] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #265: special case hash
    let msg = hex_to_32("f1d8de4858ffffffff1281093536f47fe13deb04e1fbe8fb954521b6975420f8");
    let sig = build_sig(
        "be26231b6191658a19dd72ddb99ed8f8c579b6938d19bce8eed8dc2b338cb5f8",
        "e1d9a32ee56cffed37f0f22b2dcb57d5c943c14f79694a03b9c5e96952575c89",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 287 failed");
    // 284] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #266: special case hash
    let msg = hex_to_32("0927895f2802ffffffff10782dd14a3b32dc5d47c05ef6f1876b95c81fc31def");
    let sig = build_sig(
        "15e76880898316b16204ac920a02d58045f36a229d4aa4f812638c455abe0443",
        "e74d357d3fcb5c8c5337bd6aba4178b455ca10e226e13f9638196506a1939123",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 288 failed");
    // 285] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #267: special case hash
    let msg = hex_to_32("60907984aa7e8effffffff4f332862a10a57c3063fb5a30624cf6a0c3ac80589");
    let sig = build_sig(
        "352ecb53f8df2c503a45f9846fc28d1d31e6307d3ddbffc1132315cc07f16dad",
        "1348dfa9c482c558e1d05c5242ca1c39436726ecd28258b1899792887dd0a3c6",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 289 failed");
    // 286] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #268: special case hash
    let msg = hex_to_32("c6ff198484939170ffffffff0af42cda50f9a5f50636ea6942d6b9b8cd6ae1e2");
    let sig = build_sig(
        "4a40801a7e606ba78a0da9882ab23c7677b8642349ed3d652c5bfa5f2a9558fb",
        "3a49b64848d682ef7f605f2832f7384bdc24ed2925825bf8ea77dc5981725782",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 290 failed");
    // 287] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #269: special case hash
    let msg = hex_to_32("de030419345ca15c75ffffffff8074799b9e0956cc43135d16dfbe4d27d7e68d");
    let sig = build_sig(
        "eacc5e1a8304a74d2be412b078924b3bb3511bac855c05c9e5e9e44df3d61e96",
        "7451cd8e18d6ed1885dd827714847f96ec4bb0ed4c36ce9808db8f714204f6d1",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 291 failed");
    // 288] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #270: special case hash
    let msg = hex_to_32("6f0e3eeaf42b28132b88fffffffff6c8665604d34acb19037e1ab78caaaac6ff");
    let sig = build_sig(
        "2f7a5e9e5771d424f30f67fdab61e8ce4f8cd1214882adb65f7de94c31577052",
        "ac4e69808345809b44acb0b2bd889175fb75dd050c5a449ab9528f8f78daa10c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 292 failed");
    // 289] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #271: special case hash
    let msg = hex_to_32("cdb549f773b3e62b3708d1ffffffffbe48f7c0591ddcae7d2cb222d1f8017ab9");
    let sig = build_sig(
        "ffcda40f792ce4d93e7e0f0e95e1a2147dddd7f6487621c30a03d710b3300219",
        "79938b55f8a17f7ed7ba9ade8f2065a1fa77618f0b67add8d58c422c2453a49a",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 293 failed");
    // 290] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #272: special case hash
    let msg = hex_to_32("2c3f26f96a3ac0051df4989bffffffff9fd64886c1dc4f9924d8fd6f0edb0484");
    let sig = build_sig(
        "81f2359c4faba6b53d3e8c8c3fcc16a948350f7ab3a588b28c17603a431e39a8",
        "cd6f6a5cc3b55ead0ff695d06c6860b509e46d99fccefb9f7f9e101857f74300",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 294 failed");
    // 291] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #273: special case hash
    let msg = hex_to_32("ac18f8418c55a2502cb7d53f9affffffff5c31d89fda6a6b8476397c04edf411");
    let sig = build_sig(
        "dfc8bf520445cbb8ee1596fb073ea283ea130251a6fdffa5c3f5f2aaf75ca808",
        "048e33efce147c9dd92823640e338e68bfd7d0dc7a4905b3a7ac711e577e90e7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 295 failed");
    // 292] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #274: special case hash
    let msg = hex_to_32("4f9618f98e2d3a15b24094f72bb5ffffffffa2fd3e2893683e5a6ab8cf0ee610");
    let sig = build_sig(
        "ad019f74c6941d20efda70b46c53db166503a0e393e932f688227688ba6a5762",
        "93320eb7ca0710255346bdbb3102cdcf7964ef2e0988e712bc05efe16c199345",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 296 failed");
    // 293] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #275: special case hash
    let msg = hex_to_32("422e82a3d56ed10a9cc21d31d37a25ffffffff67edf7c40204caae73ab0bc75a");
    let sig = build_sig(
        "ac8096842e8add68c34e78ce11dd71e4b54316bd3ebf7fffdeb7bd5a3ebc1883",
        "f5ca2f4f23d674502d4caf85d187215d36e3ce9f0ce219709f21a3aac003b7a8",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 297 failed");
    // 294] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #276: special case hash
    let msg = hex_to_32("7075d245ccc3281b6e7b329ff738fbb417a5ffffffffa0842d9890b5cf95d018");
    let sig = build_sig(
        "677b2d3a59b18a5ff939b70ea002250889ddcd7b7b9d776854b4943693fb92f7",
        "6b4ba856ade7677bf30307b21f3ccda35d2f63aee81efd0bab6972cc0795db55",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 298 failed");
    // 295] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #277: special case hash
    let msg = hex_to_32("3c80de54cd9226989443d593fa4fd6597e280ebeffffffffc1847eb76c217a95");
    let sig = build_sig(
        "479e1ded14bcaed0379ba8e1b73d3115d84d31d4b7c30e1f05e1fc0d5957cfb0",
        "918f79e35b3d89487cf634a4f05b2e0c30857ca879f97c771e877027355b2443",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 299 failed");
    // 296] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #278: special case hash
    let msg = hex_to_32("de21754e29b85601980bef3d697ea2770ce891a8cdffffffffc7906aa794b39b");
    let sig = build_sig(
        "43dfccd0edb9e280d9a58f01164d55c3d711e14b12ac5cf3b64840ead512a0a3",
        "1dbe33fa8ba84533cd5c4934365b3442ca1174899b78ef9a3199f49584389772",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 300 failed");
    // 297] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #279: special case hash
    let msg = hex_to_32("8f65d92927cfb86a84dd59623fb531bb599e4d5f7289ffffffff2f1f2f57881c");
    let sig = build_sig(
        "5b09ab637bd4caf0f4c7c7e4bca592fea20e9087c259d26a38bb4085f0bbff11",
        "45b7eb467b6748af618e9d80d6fdcd6aa24964e5a13f885bca8101de08eb0d75",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 301 failed");
    // 298] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #280: special case hash
    let msg = hex_to_32("6b63e9a74e092120160bea3877dace8a2cc7cd0e8426cbfffffffffafc8c3ca8");
    let sig = build_sig(
        "5e9b1c5a028070df5728c5c8af9b74e0667afa570a6cfa0114a5039ed15ee06f",
        "b1360907e2d9785ead362bb8d7bd661b6c29eeffd3c5037744edaeb9ad990c20",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 302 failed");
    // 299] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #281: special case hash
    let msg = hex_to_32("fc28259702a03845b6d75219444e8b43d094586e249c8699ffffffffe852512e");
    let sig = build_sig(
        "0671a0a85c2b72d54a2fb0990e34538b4890050f5a5712f6d1a7a5fb8578f32e",
        "db1846bab6b7361479ab9c3285ca41291808f27fd5bd4fdac720e5854713694c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 303 failed");
    // 300] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #282: special case hash
    let msg = hex_to_32("1273b4502ea4e3bccee044ee8e8db7f774ecbcd52e8ceb571757ffffffffe20a");
    let sig = build_sig(
        "7673f8526748446477dbbb0590a45492c5d7d69859d301abbaedb35b2095103a",
        "3dc70ddf9c6b524d886bed9e6af02e0e4dec0d417a414fed3807ef4422913d7c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 304 failed");
    // 301] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #283: special case hash
    let msg = hex_to_32("08fb565610a79baa0c566c66228d81814f8c53a15b96e602fb49ffffffffff6e");
    let sig = build_sig(
        "7f085441070ecd2bb21285089ebb1aa6450d1a06c36d3ff39dfd657a796d12b5",
        "249712012029870a2459d18d47da9aa492a5e6cb4b2d8dafa9e4c5c54a2b9a8b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 305 failed");
    // 302] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #284: special case hash
    let msg = hex_to_32("d59291cc2cf89f3087715fcb1aa4e79aa2403f748e97d7cd28ecaefeffffffff");
    let sig = build_sig(
        "914c67fb61dd1e27c867398ea7322d5ab76df04bc5aa6683a8e0f30a5d287348",
        "fa07474031481dda4953e3ac1959ee8cea7e66ec412b38d6c96d28f6d37304ea",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 306 failed");
    // 303] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #286: r too large
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
    );
    let pk = build_pk(
        "0ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103",
        "c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 307 should fail");
    // 304] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #287: r,s are large
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
    );
    let pk = build_pk(
        "ab05fd9d0de26b9ce6f4819652d9fc69193d0aa398f0fba8013e09c582204554",
        "19235271228c786759095d12b75af0692dd4103f19f6a8c32f49435a1e9b8d45",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 308 failed");
    // 305] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #288: r and s^-1 have a large Hamming weight
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "909135bdb6799286170f5ead2de4f6511453fe50914f3df2de54a36383df8dd4",
    );
    let pk = build_pk(
        "80984f39a1ff38a86a68aa4201b6be5dfbfecf876219710b07badf6fdd4c6c56",
        "11feb97390d9826e7a06dfb41871c940d74415ed3cac2089f1445019bb55ed95",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 309 failed");
    // 306] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #289: r and s^-1 have a large Hamming weight
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "27b4577ca009376f71303fd5dd227dcef5deb773ad5f5a84360644669ca249a5",
    );
    let pk = build_pk(
        "4201b4272944201c3294f5baa9a3232b6dd687495fcc19a70a95bc602b4f7c05",
        "95c37eba9ee8171c1bb5ac6feaf753bc36f463e3aef16629572c0c0a8fb0800e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 310 failed");
    // 307] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #301: r and s^-1 are close to n
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6324d5",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "083539fbee44625e3acaafa2fcb41349392cef0633a1b8fabecee0c133b10e99",
        "915c1ebe7bf00df8535196770a58047ae2a402f26326bb7d41d4d7616337911e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 311 failed");
    // 308] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #304: point at infinity during verify
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "b533d4695dd5b8c5e07757e55e6e516f7e2c88fa0239e23f60e8ec07dd70f287",
        "1b134ee58cc583278456863f33c3a85d881f7d4a39850143e29d4eaf009afe47",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 312 should fail");
    // 309] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #305: edge case for signature malleability
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
    );
    let pk = build_pk(
        "f50d371b91bfb1d7d14e1323523bc3aa8cbf2c57f9e284de628c8b4536787b86",
        "f94ad887ac94d527247cd2e7d0c8b1291c553c9730405380b14cbb209f5fa2dd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 313 failed");
    // 310] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #306: edge case for signature malleability
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
    );
    let pk = build_pk(
        "68ec6e298eafe16539156ce57a14b04a7047c221bafc3a582eaeb0d857c4d946",
        "97bed1af17850117fdb39b2324f220a5698ed16c426a27335bb385ac8ca6fb30",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 314 failed");
    // 311] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #307: u1 == 1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
    );
    let pk = build_pk(
        "69da0364734d2e530fece94019265fefb781a0f1b08f6c8897bdf6557927c8b8",
        "66d2d3c7dcd518b23d726960f069ad71a933d86ef8abbcce8b20f71e2a847002",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 315 failed");
    // 312] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #308: u1 == n - 1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e",
    );
    let pk = build_pk(
        "d8adc00023a8edc02576e2b63e3e30621a471e2b2320620187bf067a1ac1ff32",
        "33e2b50ec09807accb36131fff95ed12a09a86b4ea9690aa32861576ba2362e1",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 316 failed");
    // 313] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #309: u2 == 1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "3623ac973ced0a56fa6d882f03a7d5c7edca02cfc7b2401fab3690dbe75ab785",
        "8db06908e64b28613da7257e737f39793da8e713ba0643b92e9bb3252be7f8fe",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 317 failed");
    // 314] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #310: u2 == n - 1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
    );
    let pk = build_pk(
        "cf04ea77e9622523d894b93ff52dc3027b31959503b6fa3890e5e04263f922f1",
        "e8528fb7c006b3983c8b8400e57b4ed71740c2f3975438821199bedeaecab2e9",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 318 failed");
    // 315] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #311: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "e91e1ba60fdedb76a46bcb51dc0b8b4b7e019f0a28721885fa5d3a8196623397",
    );
    let pk = build_pk(
        "db7a2c8a1ab573e5929dc24077b508d7e683d49227996bda3e9f78dbeff77350",
        "4f417f3bc9a88075c2e0aadd5a13311730cf7cc76a82f11a36eaf08a6c99a206",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 319 failed");
    // 316] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #312: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "fdea5843ffeb73af94313ba4831b53fe24f799e525b1e8e8c87b59b95b430ad9",
    );
    let pk = build_pk(
        "dead11c7a5b396862f21974dc4752fadeff994efe9bbd05ab413765ea80b6e1f",
        "1de3f0640e8ac6edcf89cff53c40e265bb94078a343736df07aa0318fc7fe1ff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 320 failed");
    // 317] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #313: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "03ffcabf2f1b4d2a65190db1680d62bb994e41c5251cd73b3c3dfc5e5bafc035",
    );
    let pk = build_pk(
        "d0bc472e0d7c81ebaed3a6ef96c18613bb1fea6f994326fbe80e00dfde67c7e9",
        "986c723ea4843d48389b946f64ad56c83ad70ff17ba85335667d1bb9fa619efd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 321 failed");
    // 318] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #314: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "4dfbc401f971cd304b33dfdb17d0fed0fe4c1a88ae648e0d2847f74977534989",
    );
    let pk = build_pk(
        "a0a44ca947d66a2acb736008b9c08d1ab2ad03776e02640f78495d458dd51c32",
        "6337fe5cf8c4604b1f1c409dc2d872d4294a4762420df43a30a2392e40426add",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 322 failed");
    // 319] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #315: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bc4024761cd2ffd43dfdb17d0fed112b988977055cd3a8e54971eba9cda5ca71",
    );
    let pk = build_pk(
        "c9c2115290d008b45fb65fad0f602389298c25420b775019d42b62c3ce8a96b7",
        "3877d25a8080dc02d987ca730f0405c2c9dbefac46f9e601cc3f06e9713973fd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 323 failed");
    // 320] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #316: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "788048ed39a5ffa77bfb62fa1fda2257742bf35d128fb3459f2a0c909ee86f91",
    );
    let pk = build_pk(
        "5eca1ef4c287dddc66b8bccf1b88e8a24c0018962f3c5e7efa83bc1a5ff6033e",
        "5e79c4cb2c245b8c45abdce8a8e4da758d92a607c32cd407ecaef22f1c934a71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 324 failed");
    // 321] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #317: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "476d9131fd381bd917d0fed112bc9e0a5924b5ed5b11167edd8b23582b3cb15e",
    );
    let pk = build_pk(
        "5caaa030e7fdf0e4936bc7ab5a96353e0a01e4130c3f8bf22d473e317029a47a",
        "deb6adc462f7058f2a20d371e9702254e9b201642005b3ceda926b42b178bef9",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 325 failed");
    // 322] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #318: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "8374253e3e21bd154448d0a8f640fe46fafa8b19ce78d538f6cc0a19662d3601",
    );
    let pk = build_pk(
        "c2fd20bac06e555bb8ac0ce69eb1ea20f83a1fc3501c8a66469b1a31f619b098",
        "6237050779f52b615bd7b8d76a25fc95ca2ed32525c75f27ffc87ac397e6cbaf",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 326 failed");
    // 323] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #319: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "357cfd3be4d01d413c5b9ede36cba5452c11ee7fe14879e749ae6a2d897a52d6",
    );
    let pk = build_pk(
        "3fd6a1ca7f77fb3b0bbe726c372010068426e11ea6ae78ce17bedae4bba86ced",
        "03ce5516406bf8cfaab8745eac1cd69018ad6f50b5461872ddfc56e0db3c8ff4",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 327 failed");
    // 324] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #320: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "29798c5c0ee287d4a5e8e6b799fd86b8df5225298e6ffc807cd2f2bc27a0a6d8",
    );
    let pk = build_pk(
        "9cb8e51e27a5ae3b624a60d6dc32734e4989db20e9bca3ede1edf7b086911114",
        "b4c104ab3c677e4b36d6556e8ad5f523410a19f2e277aa895fc57322b4427544",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 328 failed");
    // 325] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #321: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "0b70f22c781092452dca1a5711fa3a5a1f72add1bf52c2ff7cae4820b30078dd",
    );
    let pk = build_pk(
        "a3e52c156dcaf10502620b7955bc2b40bc78ef3d569e1223c262512d8f49602a",
        "4a2039f31c1097024ad3cc86e57321de032355463486164cf192944977df147f",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 329 failed");
    // 326] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #322: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "16e1e458f021248a5b9434ae23f474b43ee55ba37ea585fef95c90416600f1ba",
    );
    let pk = build_pk(
        "f19b78928720d5bee8e670fb90010fb15c37bf91b58a5157c3f3c059b2655e88",
        "cf701ec962fb4a11dcf273f5dc357e58468560c7cfeb942d074abd4329260509",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 330 failed");
    // 327] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #323: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "2252d6856831b6cf895e4f0535eeaf0e5e5809753df848fe760ad86219016a97",
    );
    let pk = build_pk(
        "83a744459ecdfb01a5cf52b27a05bb7337482d242f235d7b4cb89345545c90a8",
        "c05d49337b9649813287de9ffe90355fd905df5f3c32945828121f37cc50de6e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 331 failed");
    // 328] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #324: edge case for u1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "81ffe55f178da695b28c86d8b406b15dab1a9e39661a3ae017fbe390ac0972c3",
    );
    let pk = build_pk(
        "dd13c6b34c56982ddae124f039dfd23f4b19bbe88cee8e528ae51e5d6f3a21d7",
        "bfad4c2e6f263fe5eb59ca974d039fc0e4c3345692fb5320bdae4bd3b42a45ff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 332 failed");
    // 329] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #325: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "7fffffffaaaaaaaaffffffffffffffffe9a2538f37b28a2c513dee40fecbb71a",
    );
    let pk = build_pk(
        "67e6f659cdde869a2f65f094e94e5b4dfad636bbf95192feeed01b0f3deb7460",
        "a37e0a51f258b7aeb51dfe592f5cfd5685bbe58712c8d9233c62886437c38ba0",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 333 failed");
    // 330] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #326: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "b62f26b5f2a2b26f6de86d42ad8a13da3ab3cccd0459b201de009e526adf21f2",
    );
    let pk = build_pk(
        "2eb6412505aec05c6545f029932087e490d05511e8ec1f599617bb367f9ecaaf",
        "805f51efcc4803403f9b1ae0124890f06a43fedcddb31830f6669af292895cb0",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 334 failed");
    // 331] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #327: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bb1d9ac949dd748cd02bbbe749bd351cd57b38bb61403d700686aa7b4c90851e",
    );
    let pk = build_pk(
        "84db645868eab35e3a9fd80e056e2e855435e3a6b68d75a50a854625fe0d7f35",
        "6d2589ac655edc9a11ef3e075eddda9abf92e72171570ef7bf43a2ee39338cfe",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 335 failed");
    // 332] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #328: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "66755a00638cdaec1c732513ca0234ece52545dac11f816e818f725b4f60aaf2",
    );
    let pk = build_pk(
        "91b9e47c56278662d75c0983b22ca8ea6aa5059b7a2ff7637eb2975e386ad663",
        "49aa8ff283d0f77c18d6d11dc062165fd13c3c0310679c1408302a16854ecfbd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 336 failed");
    // 333] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #329: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "55a00c9fcdaebb6032513ca0234ecfffe98ebe492fdf02e48ca48e982beb3669",
    );
    let pk = build_pk(
        "f3ec2f13caf04d0192b47fb4c5311fb6d4dc6b0a9e802e5327f7ec5ee8e4834d",
        "f97e3e468b7d0db867d6ecfe81e2b0f9531df87efdb47c1338ac321fefe5a432",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 337 failed");
    // 334] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #330: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "ab40193f9b5d76c064a27940469d9fffd31d7c925fbe05c919491d3057d66cd2",
    );
    let pk = build_pk(
        "d92b200aefcab6ac7dafd9acaf2fa10b3180235b8f46b4503e4693c670fccc88",
        "5ef2f3aebf5b317475336256768f7c19efb7352d27e4cccadc85b6b8ab922c72",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 338 failed");
    // 335] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #331: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "ca0234ebb5fdcb13ca0234ecffffffffcb0dadbbc7f549f8a26b4408d0dc8600",
    );
    let pk = build_pk(
        "0a88361eb92ecca2625b38e5f98bbabb96bf179b3d76fc48140a3bcd881523cd",
        "e6bdf56033f84a5054035597375d90866aa2c96b86a41ccf6edebf47298ad489",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 339 failed");
    // 336] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #332: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff3ea3677e082b9310572620ae19933a9e65b285598711c77298815ad3",
    );
    let pk = build_pk(
        "d0fb17ccd8fafe827e0c1afc5d8d80366e2b20e7f14a563a2ba50469d84375e8",
        "68612569d39e2bb9f554355564646de99ac602cc6349cf8c1e236a7de7637d93",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 340 failed");
    // 337] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #333: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "266666663bbbbbbbe6666666666666665b37902e023fab7c8f055d86e5cc41f4",
    );
    let pk = build_pk(
        "836f33bbc1dc0d3d3abbcef0d91f11e2ac4181076c9af0a22b1e4309d3edb276",
        "9ab443ff6f901e30c773867582997c2bec2b0cb8120d760236f3a95bbe881f75",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 341 failed");
    // 338] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #334: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff36db6db7a492492492492492146c573f4c6dfc8d08a443e258970b09",
    );
    let pk = build_pk(
        "92f99fbe973ed4a299719baee4b432741237034dec8d72ba5103cb33e55feeb8",
        "033dd0e91134c734174889f3ebcf1b7a1ac05767289280ee7a794cebd6e69697",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 342 failed");
    // 339] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #335: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff2aaaaaab7fffffffffffffffc815d0e60b3e596ecb1ad3a27cfd49c4",
    );
    let pk = build_pk(
        "d35ba58da30197d378e618ec0fa7e2e2d12cffd73ebbb2049d130bba434af09e",
        "ff83986e6875e41ea432b7585a49b3a6c77cbb3c47919f8e82874c794635c1d2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 343 failed");
    // 340] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #336: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "7fffffff55555555ffffffffffffffffd344a71e6f651458a27bdc81fd976e37",
    );
    let pk = build_pk(
        "8651ce490f1b46d73f3ff475149be29136697334a519d7ddab0725c8d0793224",
        "e11c65bd8ca92dc8bc9ae82911f0b52751ce21dd9003ae60900bd825f590cc28",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 344 failed");
    // 341] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #337: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "3fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192aa",
    );
    let pk = build_pk(
        "6d8e1b12c831a0da8795650ff95f101ed921d9e2f72b15b1cdaca9826b9cfc6d",
        "ef6d63e2bc5c089570394a4bc9f892d5e6c7a6a637b20469a58c106ad486bf37",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 345 failed");
    // 342] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #338: edge case for u2
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "5d8ecd64a4eeba466815ddf3a4de9a8e6abd9c5db0a01eb80343553da648428f",
    );
    let pk = build_pk(
        "0ae580bae933b4ef2997cbdbb0922328ca9a410f627a0f7dff24cb4d920e1542",
        "8911e7f8cc365a8a88eb81421a361ccc2b99e309d8dcd9a98ba83c3949d893e3",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 346 failed");
    // 343] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #339: point duplication during verification
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569",
        "bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
    );
    let pk = build_pk(
        "5b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc46963",
        "838a40f2a36092e9004e92d8d940cf5638550ce672ce8b8d4e15eba5499249e9",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 347 failed");
    // 344] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #340: duplication bug
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569",
        "bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
    );
    let pk = build_pk(
        "5b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc46963",
        "7c75bf0c5c9f6d17ffb16d2726bf30a9c7aaf31a8d317472b1ea145ab66db616",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 348 should fail");
    // 345] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #343: comparison with point at infinity
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aa9",
    );
    let pk = build_pk(
        "dd86d3b5f4a13e8511083b78002081c53ff467f11ebd98a51a633db76665d250",
        "45d5c8200c89f2fa10d849349226d21d8dfaed6ff8d5cb3e1b7e17474ebc18f7",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 349 should fail");
    // 346] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #344: extreme value for k and edgecase s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "4fea55b32cb32aca0c12c4cd0abfb4e64b0f5a516e578c016591a93f5a0fbcc5",
        "d7d3fd10b2be668c547b212f6bb14c88f0fecd38a8a4b2c785ed3be62ce4b280",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 350 failed");
    // 347] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #345: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
    );
    let pk = build_pk(
        "c6a771527024227792170a6f8eee735bf32b7f98af669ead299802e32d7c3107",
        "bc3b4b5e65ab887bbd343572b3e5619261fe3a073e2ffd78412f726867db589e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 351 failed");
    // 348] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #346: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
    );
    let pk = build_pk(
        "851c2bbad08e54ec7a9af99f49f03644d6ec6d59b207fec98de85a7d15b956ef",
        "cee9960283045075684b410be8d0f7494b91aa2379f60727319f10ddeb0fe9d6",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 352 failed");
    // 349] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #347: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
    );
    let pk = build_pk(
        "f6417c8a670584e388676949e53da7fc55911ff68318d1bf3061205acb19c48f",
        "8f2b743df34ad0f72674acb7505929784779cd9ac916c3669ead43026ab6d43f",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 353 failed");
    // 350] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #348: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "49249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
    );
    let pk = build_pk(
        "501421277be45a5eefec6c639930d636032565af420cf3373f557faa7f8a0643",
        "8673d6cb6076e1cfcdc7dfe7384c8e5cac08d74501f2ae6e89cad195d0aa1371",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 354 failed");
    // 351] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #349: extreme value for k
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "16a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
    );
    let pk = build_pk(
        "0d935bf9ffc115a527735f729ca8a4ca23ee01a4894adf0e3415ac84e808bb34",
        "3195a3762fea29ed38912bd9ea6c4fde70c3050893a4375850ce61d82eba33c5",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 355 failed");
    // 352] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #350: extreme value for k and edgecase s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "5e59f50708646be8a589355014308e60b668fb670196206c41e748e64e4dca21",
        "5de37fee5c97bcaf7144d5b459982f52eeeafbdf03aacbafef38e213624a01de",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 356 failed");
    // 353] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #351: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
    );
    let pk = build_pk(
        "169fb797325843faff2f7a5b5445da9e2fd6226f7ef90ef0bfe924104b02db8e",
        "7bbb8de662c7b9b1cf9b22f7a2e582bd46d581d68878efb2b861b131d8a1d667",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 357 failed");
    // 354] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #352: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
    );
    let pk = build_pk(
        "271cd89c000143096b62d4e9e4ca885aef2f7023d18affdaf8b7b54898148754",
        "0a1c6e954e32108435b55fa385b0f76481a609b9149ccb4b02b2ca47fe8e4da5",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 358 failed");
    // 355] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #353: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
    );
    let pk = build_pk(
        "3d0bc7ed8f09d2cb7ddb46ebc1ed799ab1563a9ab84bf524587a220afe499c12",
        "e22dc3b3c103824a4f378d96adb0a408abf19ce7d68aa6244f78cb216fa3f8df",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 359 failed");
    // 356] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #354: extreme value for k and s^-1
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "49249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
    );
    let pk = build_pk(
        "a6c885ade1a4c566f9bb010d066974abb281797fa701288c721bcbd23663a9b7",
        "2e424b690957168d193a6096fc77a2b004a9c7d467e007e1f2058458f98af316",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 360 failed");
    // 357] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #355: extreme value for k
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "16a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
    );
    let pk = build_pk(
        "8d3c2c2c3b765ba8289e6ac3812572a25bf75df62d87ab7330c3bdbad9ebfa5c",
        "4c6845442d66935b238578d43aec54f7caa1621d1af241d4632e0b780c423f5d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 361 failed");
    // 358] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #356: testing point duplication
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 362 should fail");
    // 359] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #357: testing point duplication
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 363 should fail");
    // 360] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #358: testing point duplication
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 364 should fail");
    // 361] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #359: testing point duplication
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 365 should fail");
    // 362] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #360: pseudorandom signature
    let msg = hex_to_32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    let sig = build_sig(
        "b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a",
        "0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 366 failed");
    // 363] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #361: pseudorandom signature
    let msg = hex_to_32("dc1921946f4af96a2856e7be399007c9e807bdf4c5332f19f59ec9dd1bb8c7b3");
    let sig = build_sig(
        "530bd6b0c9af2d69ba897f6b5fb59695cfbf33afe66dbadcf5b8d2a2a6538e23",
        "d85e489cb7a161fd55ededcedbf4cc0c0987e3e3f0f242cae934c72caa3f43e9",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 367 failed");
    // 364] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #362: pseudorandom signature
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "a8ea150cb80125d7381c4c1f1da8e9de2711f9917060406a73d7904519e51388",
        "f3ab9fa68bd47973a73b2d40480c2ba50c22c9d76ec217257288293285449b86",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 368 failed");
    // 365] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #363: pseudorandom signature
    let msg = hex_to_32("de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90");
    let sig = build_sig(
        "986e65933ef2ed4ee5aada139f52b70539aaf63f00a91f29c69178490d57fb71",
        "3dafedfb8da6189d372308cbf1489bbbdabf0c0217d1c0ff0f701aaa7a694b9c",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 369 failed");
    // 366] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #364: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d434e262a49eab7781e353a3565e482550dd0fd5defa013c7f29745eff3569f1",
        "9b0c0a93f267fb6052fd8077be769c2b98953195d7bc10de844218305c6ba17a",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 370 failed");
    // 367] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #365: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "0fe774355c04d060f76d79fd7a772e421463489221bf0a33add0be9b1979110b",
        "500dcba1c69a8fbd43fa4f57f743ce124ca8b91a1f325f3fac6181175df55737",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 371 failed");
    // 368] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #366: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "bb40bf217bed3fb3950c7d39f03d36dc8e3b2cd79693f125bfd06595ee1135e3",
        "541bf3532351ebb032710bdb6a1bf1bfc89a1e291ac692b3fa4780745bb55677",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 372 failed");
    // 369] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #367: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "664eb7ee6db84a34df3c86ea31389a5405badd5ca99231ff556d3e75a233e73a",
        "59f3c752e52eca46137642490a51560ce0badc678754b8f72e51a2901426a1bd",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 373 failed");
    // 370] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #368: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "4cd0429bbabd2827009d6fcd843d4ce39c3e42e2d1631fd001985a79d1fd8b43",
        "9638bf12dd682f60be7ef1d0e0d98f08b7bca77a1a2b869ae466189d2acdabe3",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 374 failed");
    // 371] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #369: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "e56c6ea2d1b017091c44d8b6cb62b9f460e3ce9aed5e5fd41e8added97c56c04",
        "a308ec31f281e955be20b457e463440b4fcf2b80258078207fc1378180f89b55",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 375 failed");
    // 372] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #370: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "1158a08d291500b4cabed3346d891eee57c176356a2624fb011f8fbbf3466830",
        "228a8c486a736006e082325b85290c5bc91f378b75d487dda46798c18f285519",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 376 failed");
    // 373] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #371: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b1db9289649f59410ea36b0c0fc8d6aa2687b29176939dd23e0dde56d309fa9d",
        "3e1535e4280559015b0dbd987366dcf43a6d1af5c23c7d584e1c3f48a1251336",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 377 failed");
    // 374] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #372: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b7b16e762286cb96446aa8d4e6e7578b0a341a79f2dd1a220ac6f0ca4e24ed86",
        "ddc60a700a139b04661c547d07bbb0721780146df799ccf55e55234ecb8f12bc",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 378 failed");
    // 375] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #373: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d82a7c2717261187c8e00d8df963ff35d796edad36bc6e6bd1c91c670d9105b4",
        "3dcabddaf8fcaa61f4603e7cbac0f3c0351ecd5988efb23f680d07debd139929",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 379 failed");
    // 376] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #374: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "5eb9c8845de68eb13d5befe719f462d77787802baff30ce96a5cba063254af78",
        "2c026ae9be2e2a5e7ca0ff9bbd92fb6e44972186228ee9a62b87ddbe2ef66fb5",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 380 failed");
    // 377] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #375: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "96843dd03c22abd2f3b782b170239f90f277921becc117d0404a8e4e36230c28",
        "f2be378f526f74a543f67165976de9ed9a31214eb4d7e6db19e1ede123dd991d",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 381 failed");
    // 378] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #376: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "766456dce1857c906f9996af729339464d27e9d98edc2d0e3b760297067421f6",
        "402385ecadae0d8081dccaf5d19037ec4e55376eced699e93646bfbbf19d0b41",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 382 failed");
    // 379] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #377: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "c605c4b2edeab20419e6518a11b2dbc2b97ed8b07cced0b19c34f777de7b9fd9",
        "edf0f612c5f46e03c719647bc8af1b29b2cde2eda700fb1cff5e159d47326dba",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 383 failed");
    // 380] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #378: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d48b68e6cabfe03cf6141c9ac54141f210e64485d9929ad7b732bfe3b7eb8a84",
        "feedae50c61bd00e19dc26f9b7e2265e4508c389109ad2f208f0772315b6c941",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 384 failed");
    // 381] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #379: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b7c81457d4aeb6aa65957098569f0479710ad7f6595d5874c35a93d12a5dd4c7",
        "b7961a0b652878c2d568069a432ca18a1a9199f2ca574dad4b9e3a05c0a1cdb3",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 385 failed");
    // 382] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #380: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "6b01332ddb6edfa9a30a1321d5858e1ee3cf97e263e669f8de5e9652e76ff3f7",
        "5939545fced457309a6a04ace2bd0f70139c8f7d86b02cb1cc58f9e69e96cd5a",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 386 failed");
    // 383] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #381: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "efdb884720eaeadc349f9fc356b6c0344101cd2fd8436b7d0e6a4fb93f106361",
        "f24bee6ad5dc05f7613975473aadf3aacba9e77de7d69b6ce48cb60d8113385d",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 387 failed");
    // 384] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #382: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "31230428405560dcb88fb5a646836aea9b23a23dd973dcbe8014c87b8b20eb07",
        "0f9344d6e812ce166646747694a41b0aaf97374e19f3c5fb8bd7ae3d9bd0beff",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 388 failed");
    // 385] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #383: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "caa797da65b320ab0d5c470cda0b36b294359c7db9841d679174db34c4855743",
        "cf543a62f23e212745391aaf7505f345123d2685ee3b941d3de6d9b36242e5a0",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 389 failed");
    // 386] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #384: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "7e5f0ab5d900d3d3d7867657e5d6d36519bc54084536e7d21c336ed800185945",
        "9450c07f201faec94b82dfb322e5ac676688294aad35aa72e727ff0b19b646aa",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 390 failed");
    // 387] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #385: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d7d70c581ae9e3f66dc6a480bf037ae23f8a1e4a2136fe4b03aa69f0ca25b356",
        "89c460f8a5a5c2bbba962c8a3ee833a413e85658e62a59e2af41d9127cc47224",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 391 failed");
    // 388] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #386: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "341c1b9ff3c83dd5e0dfa0bf68bcdf4bb7aa20c625975e5eeee34bb396266b34",
        "72b69f061b750fd5121b22b11366fad549c634e77765a017902a67099e0a4469",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 392 failed");
    // 389] wycheproof/ecdsa_secp256r1_sha256_test.json EcdsaVerify SHA-256 #387: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67",
        "aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 393 failed");
    // 390] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1: signature malleability
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "4cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 394 failed");
    // 391] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #2: Legacy:ASN encoding of s misses leading 0
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 395 failed");
    // 392] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #3: valid
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 396 failed");
    // 393] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #118: modify first byte of integer
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "29a3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 397 should fail");
    // 394] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #120: modify last byte of integer
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e98",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 398 should fail");
    // 395] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #121: modify last byte of integer
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b491568475b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 399 should fail");
    // 396] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #124: truncated integer
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "00b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 400 should fail");
    // 397] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #133: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "d45c5741946b2a137f59262ee6f5bc91001af27a5e1117a64733950642a3d1e8",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 401 should fail");
    // 398] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #134: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 402 should fail");
    // 399] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #137: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "d45c5741946b2a137f59262ee6f5bc91001af27a5e1117a64733950642a3d1e8",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 403 should fail");
    // 400] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #139: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "b329f47aa2bbd0a4c384ee1493b1f518ada018ef05465583885980861905228a",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 404 should fail");
    // 401] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #143: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "4cd60b865d442f5a3c7b11eb6c4e0ae79578ec6353a20bf783ecb4b6ea97b825",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 405 should fail");
    // 402] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #177: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 406 should fail");
    // 403] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #178: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 407 should fail");
    // 404] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #179: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 408 should fail");
    // 405] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #180: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 409 should fail");
    // 406] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #181: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 410 should fail");
    // 407] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #187: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 411 should fail");
    // 408] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #188: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 412 should fail");
    // 409] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #189: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 413 should fail");
    // 410] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #190: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 414 should fail");
    // 411] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #191: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 415 should fail");
    // 412] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #197: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 416 should fail");
    // 413] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #198: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 417 should fail");
    // 414] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #199: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 418 should fail");
    // 415] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #200: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 419 should fail");
    // 416] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #201: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 420 should fail");
    // 417] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #207: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 421 should fail");
    // 418] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #208: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 422 should fail");
    // 419] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #209: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 423 should fail");
    // 420] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #210: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 424 should fail");
    // 421] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #211: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 425 should fail");
    // 422] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #217: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 426 should fail");
    // 423] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #218: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 427 should fail");
    // 424] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #219: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 428 should fail");
    // 425] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #220: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 429 should fail");
    // 426] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #221: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 430 should fail");
    // 427] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #230: Edge case for Shamir multiplication
    let msg = hex_to_32("70239dd877f7c944c422f44dea4ed1a52f2627416faf2f072fa50c772ed6f807");
    let sig = build_sig(
        "64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e",
        "6af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 431 failed");
    // 428] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #231: special case hash
    let msg = hex_to_32("00000000690ed426ccf17803ebe2bd0884bcd58a1bb5e7477ead3645f356e7a9");
    let sig = build_sig(
        "16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf266",
        "252cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 432 failed");
    // 429] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #232: special case hash
    let msg = hex_to_32("7300000000213f2a525c6035725235c2f696ad3ebb5ee47f140697ad25770d91");
    let sig = build_sig(
        "9cc98be2347d469bf476dfc26b9b733df2d26d6ef524af917c665baccb23c882",
        "093496459effe2d8d70727b82462f61d0ec1b7847929d10ea631dacb16b56c32",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 433 failed");
    // 430] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #233: special case hash
    let msg = hex_to_32("ddf2000000005e0be0635b245f0b97978afd25daadeb3edb4a0161c27fe06045");
    let sig = build_sig(
        "73b3c90ecd390028058164524dde892703dce3dea0d53fa8093999f07ab8aa43",
        "2f67b0b8e20636695bb7d8bf0a651c802ed25a395387b5f4188c0c4075c88634",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 434 failed");
    // 431] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #234: special case hash
    let msg = hex_to_32("67ab1900000000784769c4ecb9e164d6642b8499588b89855be1ec355d0841a0");
    let sig = build_sig(
        "bfab3098252847b328fadf2f89b95c851a7f0eb390763378f37e90119d5ba3dd",
        "bdd64e234e832b1067c2d058ccb44d978195ccebb65c2aaf1e2da9b8b4987e3b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 435 failed");
    // 432] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #235: special case hash
    let msg = hex_to_32("a2bf09460000000076d7dbeffe125eaf02095dff252ee905e296b6350fc311cf");
    let sig = build_sig(
        "204a9784074b246d8bf8bf04a4ceb1c1f1c9aaab168b1596d17093c5cd21d2cd",
        "51cce41670636783dc06a759c8847868a406c2506fe17975582fe648d1d88b52",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 436 failed");
    // 433] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #236: special case hash
    let msg = hex_to_32("3554e827c700000000e1e75e624a06b3a0a353171160858129e15c544e4f0e65");
    let sig = build_sig(
        "ed66dc34f551ac82f63d4aa4f81fe2cb0031a91d1314f835027bca0f1ceeaa03",
        "99ca123aa09b13cd194a422e18d5fda167623c3f6e5d4d6abb8953d67c0c48c7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 437 failed");
    // 434] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #237: special case hash
    let msg = hex_to_32("9b6cd3b812610000000026941a0f0bb53255ea4c9fd0cb3426e3a54b9fc6965c");
    let sig = build_sig(
        "060b700bef665c68899d44f2356a578d126b062023ccc3c056bf0f60a237012b",
        "8d186c027832965f4fcc78a3366ca95dedbb410cbef3f26d6be5d581c11d3610",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 438 failed");
    // 435] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #238: special case hash
    let msg = hex_to_32("883ae39f50bf0100000000e7561c26fc82a52baa51c71ca877162f93c4ae0186");
    let sig = build_sig(
        "9f6adfe8d5eb5b2c24d7aa7934b6cf29c93ea76cd313c9132bb0c8e38c96831d",
        "b26a9c9e40e55ee0890c944cf271756c906a33e66b5bd15e051593883b5e9902",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 439 failed");
    // 436] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #239: special case hash
    let msg = hex_to_32("a1ce5d6e5ecaf28b0000000000fa7cd010540f420fb4ff7401fe9fce011d0ba6");
    let sig = build_sig(
        "a1af03ca91677b673ad2f33615e56174a1abf6da168cebfa8868f4ba273f16b7",
        "20aa73ffe48afa6435cd258b173d0c2377d69022e7d098d75caf24c8c5e06b1c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 440 failed");
    // 437] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #240: special case hash
    let msg = hex_to_32("8ea5f645f373f580930000000038345397330012a8ee836c5494cdffd5ee8054");
    let sig = build_sig(
        "fdc70602766f8eed11a6c99a71c973d5659355507b843da6e327a28c11893db9",
        "3df5349688a085b137b1eacf456a9e9e0f6d15ec0078ca60a7f83f2b10d21350",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 441 failed");
    // 438] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #241: special case hash
    let msg = hex_to_32("660570d323e9f75fa734000000008792d65ce93eabb7d60d8d9c1bbdcb5ef305");
    let sig = build_sig(
        "b516a314f2fce530d6537f6a6c49966c23456f63c643cf8e0dc738f7b876e675",
        "d39ffd033c92b6d717dd536fbc5efdf1967c4bd80954479ba66b0120cd16fff2",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 442 failed");
    // 439] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #242: special case hash
    let msg = hex_to_32("d0462673154cce587dde8800000000e98d35f1f45cf9c3bf46ada2de4c568c34");
    let sig = build_sig(
        "3b2cbf046eac45842ecb7984d475831582717bebb6492fd0a485c101e29ff0a8",
        "4c9b7b47a98b0f82de512bc9313aaf51701099cac5f76e68c8595fc1c1d99258",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 443 failed");
    // 440] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #243: special case hash
    let msg = hex_to_32("bd90640269a7822680cedfef000000000caef15a6171059ab83e7b4418d7278f");
    let sig = build_sig(
        "30c87d35e636f540841f14af54e2f9edd79d0312cfa1ab656c3fb15bfde48dcf",
        "47c15a5a82d24b75c85a692bd6ecafeb71409ede23efd08e0db9abf6340677ed",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 444 failed");
    // 441] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #244: special case hash
    let msg = hex_to_32("33239a52d72f1311512e41222a00000000d2dcceb301c54b4beae8e284788a73");
    let sig = build_sig(
        "38686ff0fda2cef6bc43b58cfe6647b9e2e8176d168dec3c68ff262113760f52",
        "067ec3b651f422669601662167fa8717e976e2db5e6a4cf7c2ddabb3fde9d67d",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 445 failed");
    // 442] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #245: special case hash
    let msg = hex_to_32("b8d64fbcd4a1c10f1365d4e6d95c000000007ee4a21a1cbe1dc84c2d941ffaf1");
    let sig = build_sig(
        "44a3e23bf314f2b344fc25c7f2de8b6af3e17d27f5ee844b225985ab6e2775cf",
        "2d48e223205e98041ddc87be532abed584f0411f5729500493c9cc3f4dd15e86",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 446 failed");
    // 443] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #246: special case hash
    let msg = hex_to_32("01603d3982bf77d7a3fef3183ed092000000003a227420db4088b20fe0e9d84a");
    let sig = build_sig(
        "2ded5b7ec8e90e7bf11f967a3d95110c41b99db3b5aa8d330eb9d638781688e9",
        "7d5792c53628155e1bfc46fb1a67e3088de049c328ae1f44ec69238a009808f9",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 447 failed");
    // 444] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #247: special case hash
    let msg = hex_to_32("9ea6994f1e0384c8599aa02e6cf66d9c000000004d89ef50b7e9eb0cfbff7363");
    let sig = build_sig(
        "bdae7bcb580bf335efd3bc3d31870f923eaccafcd40ec2f605976f15137d8b8f",
        "f6dfa12f19e525270b0106eecfe257499f373a4fb318994f24838122ce7ec3c7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 448 failed");
    // 445] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #248: special case hash
    let msg = hex_to_32("d03215a8401bcf16693979371a01068a4700000000e2fa5bf692bc670905b18c");
    let sig = build_sig(
        "50f9c4f0cd6940e162720957ffff513799209b78596956d21ece251c2401f1c6",
        "d7033a0a787d338e889defaaabb106b95a4355e411a59c32aa5167dfab244726",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 449 failed");
    // 446] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #249: special case hash
    let msg = hex_to_32("307bfaaffb650c889c84bf83f0300e5dc87e000000008408fd5f64b582e3bb14");
    let sig = build_sig(
        "f612820687604fa01906066a378d67540982e29575d019aabe90924ead5c860d",
        "3f9367702dd7dd4f75ea98afd20e328a1a99f4857b316525328230ce294b0fef",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 450 failed");
    // 447] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #250: special case hash
    let msg = hex_to_32("bab5c4f4df540d7b33324d36bb0c157551527c00000000e4af574bb4d54ea6b8");
    let sig = build_sig(
        "9505e407657d6e8bc93db5da7aa6f5081f61980c1949f56b0f2f507da5782a7a",
        "c60d31904e3669738ffbeccab6c3656c08e0ed5cb92b3cfa5e7f71784f9c5021",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 451 failed");
    // 448] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #251: special case hash
    let msg = hex_to_32("d4ba47f6ae28f274e4f58d8036f9c36ec2456f5b00000000c3b869197ef5e15e");
    let sig = build_sig(
        "bbd16fbbb656b6d0d83e6a7787cd691b08735aed371732723e1c68a40404517d",
        "9d8e35dba96028b7787d91315be675877d2d097be5e8ee34560e3e7fd25c0f00",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 452 failed");
    // 449] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #252: special case hash
    let msg = hex_to_32("79fd19c7235ea212f29f1fa00984342afe0f10aafd00000000801e47f8c184e1");
    let sig = build_sig(
        "2ec9760122db98fd06ea76848d35a6da442d2ceef7559a30cf57c61e92df327e",
        "7ab271da90859479701fccf86e462ee3393fb6814c27b760c4963625c0a19878",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 453 failed");
    // 450] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #253: special case hash
    let msg = hex_to_32("8c291e8eeaa45adbaf9aba5c0583462d79cbeb7ac97300000000a37ea6700cda");
    let sig = build_sig(
        "54e76b7683b6650baa6a7fc49b1c51eed9ba9dd463221f7a4f1005a89fe00c59",
        "2ea076886c773eb937ec1cc8374b7915cfd11b1c1ae1166152f2f7806a31c8fd",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 454 failed");
    // 451] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #254: special case hash
    let msg = hex_to_32("0eaae8641084fa979803efbfb8140732f4cdcf66c3f78a000000003c278a6b21");
    let sig = build_sig(
        "5291deaf24659ffbbce6e3c26f6021097a74abdbb69be4fb10419c0c496c9466",
        "65d6fcf336d27cc7cdb982bb4e4ecef5827f84742f29f10abf83469270a03dc3",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 455 failed");
    // 452] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #255: special case hash
    let msg = hex_to_32("e02716d01fb23a5a0068399bf01bab42ef17c6d96e13846c00000000afc0f89d");
    let sig = build_sig(
        "207a3241812d75d947419dc58efb05e8003b33fc17eb50f9d15166a88479f107",
        "cdee749f2e492b213ce80b32d0574f62f1c5d70793cf55e382d5caadf7592767",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 456 failed");
    // 453] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #256: special case hash
    let msg = hex_to_32("9eb0bf583a1a6b9a194e9a16bc7dab2a9061768af89d00659a00000000fc7de1");
    let sig = build_sig(
        "6554e49f82a855204328ac94913bf01bbe84437a355a0a37c0dee3cf81aa7728",
        "aea00de2507ddaf5c94e1e126980d3df16250a2eaebc8be486effe7f22b4f929",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 457 failed");
    // 454] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #257: special case hash
    let msg = hex_to_32("62aac98818b3b84a2c214f0d5e72ef286e1030cb53d9a82b690e00000000cd15");
    let sig = build_sig(
        "a54c5062648339d2bff06f71c88216c26c6e19b4d80a8c602990ac82707efdfc",
        "e99bbe7fcfafae3e69fd016777517aa01056317f467ad09aff09be73c9731b0d",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 458 failed");
    // 455] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #258: special case hash
    let msg = hex_to_32("3760a7f37cf96218f29ae43732e513efd2b6f552ea4b6895464b9300000000c8");
    let sig = build_sig(
        "975bd7157a8d363b309f1f444012b1a1d23096593133e71b4ca8b059cff37eaf",
        "7faa7a28b1c822baa241793f2abc930bd4c69840fe090f2aacc46786bf919622",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 459 failed");
    // 456] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #259: special case hash
    let msg = hex_to_32("0da0a1d2851d33023834f2098c0880096b4320bea836cd9cbb6ff6c800000000");
    let sig = build_sig(
        "5694a6f84b8f875c276afd2ebcfe4d61de9ec90305afb1357b95b3e0da43885e",
        "0dffad9ffd0b757d8051dec02ebdf70d8ee2dc5c7870c0823b6ccc7c679cbaa4",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 460 failed");
    // 457] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #260: special case hash
    let msg = hex_to_32("ffffffff293886d3086fd567aafd598f0fe975f735887194a764a231e82d289a");
    let sig = build_sig(
        "a0c30e8026fdb2b4b4968a27d16a6d08f7098f1a98d21620d7454ba9790f1ba6",
        "5e470453a8a399f15baf463f9deceb53acc5ca64459149688bd2760c65424339",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 461 failed");
    // 458] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #261: special case hash
    let msg = hex_to_32("7bffffffff2376d1e3c03445a072e24326acdc4ce127ec2e0e8d9ca99527e7b7");
    let sig = build_sig(
        "614ea84acf736527dd73602cd4bb4eea1dfebebd5ad8aca52aa0228cf7b99a88",
        "737cc85f5f2d2f60d1b8183f3ed490e4de14368e96a9482c2a4dd193195c902f",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 462 failed");
    // 459] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #262: special case hash
    let msg = hex_to_32("a2b5ffffffffebb251b085377605a224bc80872602a6e467fd016807e97fa395");
    let sig = build_sig(
        "bead6734ebe44b810d3fb2ea00b1732945377338febfd439a8d74dfbd0f942fa",
        "6bb18eae36616a7d3cad35919fd21a8af4bbe7a10f73b3e036a46b103ef56e2a",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 463 failed");
    // 460] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #263: special case hash
    let msg = hex_to_32("641227ffffffff6f1b96fa5f097fcf3cc1a3c256870d45a67b83d0967d4b20c0");
    let sig = build_sig(
        "499625479e161dacd4db9d9ce64854c98d922cbf212703e9654fae182df9bad2",
        "42c177cf37b8193a0131108d97819edd9439936028864ac195b64fca76d9d693",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 464 failed");
    // 461] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #264: special case hash
    let msg = hex_to_32("958415d8ffffffffabad03e2fc662dc3ba203521177502298df56f36600e0f8b");
    let sig = build_sig(
        "08f16b8093a8fb4d66a2c8065b541b3d31e3bfe694f6b89c50fb1aaa6ff6c9b2",
        "9d6455e2d5d1779748573b611cb95d4a21f967410399b39b535ba3e5af81ca2e",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 465 failed");
    // 462] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #265: special case hash
    let msg = hex_to_32("f1d8de4858ffffffff1281093536f47fe13deb04e1fbe8fb954521b6975420f8");
    let sig = build_sig(
        "be26231b6191658a19dd72ddb99ed8f8c579b6938d19bce8eed8dc2b338cb5f8",
        "e1d9a32ee56cffed37f0f22b2dcb57d5c943c14f79694a03b9c5e96952575c89",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 466 failed");
    // 463] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #266: special case hash
    let msg = hex_to_32("0927895f2802ffffffff10782dd14a3b32dc5d47c05ef6f1876b95c81fc31def");
    let sig = build_sig(
        "15e76880898316b16204ac920a02d58045f36a229d4aa4f812638c455abe0443",
        "e74d357d3fcb5c8c5337bd6aba4178b455ca10e226e13f9638196506a1939123",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 467 failed");
    // 464] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #267: special case hash
    let msg = hex_to_32("60907984aa7e8effffffff4f332862a10a57c3063fb5a30624cf6a0c3ac80589");
    let sig = build_sig(
        "352ecb53f8df2c503a45f9846fc28d1d31e6307d3ddbffc1132315cc07f16dad",
        "1348dfa9c482c558e1d05c5242ca1c39436726ecd28258b1899792887dd0a3c6",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 468 failed");
    // 465] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #268: special case hash
    let msg = hex_to_32("c6ff198484939170ffffffff0af42cda50f9a5f50636ea6942d6b9b8cd6ae1e2");
    let sig = build_sig(
        "4a40801a7e606ba78a0da9882ab23c7677b8642349ed3d652c5bfa5f2a9558fb",
        "3a49b64848d682ef7f605f2832f7384bdc24ed2925825bf8ea77dc5981725782",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 469 failed");
    // 466] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #269: special case hash
    let msg = hex_to_32("de030419345ca15c75ffffffff8074799b9e0956cc43135d16dfbe4d27d7e68d");
    let sig = build_sig(
        "eacc5e1a8304a74d2be412b078924b3bb3511bac855c05c9e5e9e44df3d61e96",
        "7451cd8e18d6ed1885dd827714847f96ec4bb0ed4c36ce9808db8f714204f6d1",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 470 failed");
    // 467] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #270: special case hash
    let msg = hex_to_32("6f0e3eeaf42b28132b88fffffffff6c8665604d34acb19037e1ab78caaaac6ff");
    let sig = build_sig(
        "2f7a5e9e5771d424f30f67fdab61e8ce4f8cd1214882adb65f7de94c31577052",
        "ac4e69808345809b44acb0b2bd889175fb75dd050c5a449ab9528f8f78daa10c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 471 failed");
    // 468] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #271: special case hash
    let msg = hex_to_32("cdb549f773b3e62b3708d1ffffffffbe48f7c0591ddcae7d2cb222d1f8017ab9");
    let sig = build_sig(
        "ffcda40f792ce4d93e7e0f0e95e1a2147dddd7f6487621c30a03d710b3300219",
        "79938b55f8a17f7ed7ba9ade8f2065a1fa77618f0b67add8d58c422c2453a49a",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 472 failed");
    // 469] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #272: special case hash
    let msg = hex_to_32("2c3f26f96a3ac0051df4989bffffffff9fd64886c1dc4f9924d8fd6f0edb0484");
    let sig = build_sig(
        "81f2359c4faba6b53d3e8c8c3fcc16a948350f7ab3a588b28c17603a431e39a8",
        "cd6f6a5cc3b55ead0ff695d06c6860b509e46d99fccefb9f7f9e101857f74300",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 473 failed");
    // 470] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #273: special case hash
    let msg = hex_to_32("ac18f8418c55a2502cb7d53f9affffffff5c31d89fda6a6b8476397c04edf411");
    let sig = build_sig(
        "dfc8bf520445cbb8ee1596fb073ea283ea130251a6fdffa5c3f5f2aaf75ca808",
        "048e33efce147c9dd92823640e338e68bfd7d0dc7a4905b3a7ac711e577e90e7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 474 failed");
    // 471] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #274: special case hash
    let msg = hex_to_32("4f9618f98e2d3a15b24094f72bb5ffffffffa2fd3e2893683e5a6ab8cf0ee610");
    let sig = build_sig(
        "ad019f74c6941d20efda70b46c53db166503a0e393e932f688227688ba6a5762",
        "93320eb7ca0710255346bdbb3102cdcf7964ef2e0988e712bc05efe16c199345",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 475 failed");
    // 472] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #275: special case hash
    let msg = hex_to_32("422e82a3d56ed10a9cc21d31d37a25ffffffff67edf7c40204caae73ab0bc75a");
    let sig = build_sig(
        "ac8096842e8add68c34e78ce11dd71e4b54316bd3ebf7fffdeb7bd5a3ebc1883",
        "f5ca2f4f23d674502d4caf85d187215d36e3ce9f0ce219709f21a3aac003b7a8",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 476 failed");
    // 473] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #276: special case hash
    let msg = hex_to_32("7075d245ccc3281b6e7b329ff738fbb417a5ffffffffa0842d9890b5cf95d018");
    let sig = build_sig(
        "677b2d3a59b18a5ff939b70ea002250889ddcd7b7b9d776854b4943693fb92f7",
        "6b4ba856ade7677bf30307b21f3ccda35d2f63aee81efd0bab6972cc0795db55",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 477 failed");
    // 474] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #277: special case hash
    let msg = hex_to_32("3c80de54cd9226989443d593fa4fd6597e280ebeffffffffc1847eb76c217a95");
    let sig = build_sig(
        "479e1ded14bcaed0379ba8e1b73d3115d84d31d4b7c30e1f05e1fc0d5957cfb0",
        "918f79e35b3d89487cf634a4f05b2e0c30857ca879f97c771e877027355b2443",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 478 failed");
    // 475] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #278: special case hash
    let msg = hex_to_32("de21754e29b85601980bef3d697ea2770ce891a8cdffffffffc7906aa794b39b");
    let sig = build_sig(
        "43dfccd0edb9e280d9a58f01164d55c3d711e14b12ac5cf3b64840ead512a0a3",
        "1dbe33fa8ba84533cd5c4934365b3442ca1174899b78ef9a3199f49584389772",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 479 failed");
    // 476] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #279: special case hash
    let msg = hex_to_32("8f65d92927cfb86a84dd59623fb531bb599e4d5f7289ffffffff2f1f2f57881c");
    let sig = build_sig(
        "5b09ab637bd4caf0f4c7c7e4bca592fea20e9087c259d26a38bb4085f0bbff11",
        "45b7eb467b6748af618e9d80d6fdcd6aa24964e5a13f885bca8101de08eb0d75",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 480 failed");
    // 477] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #280: special case hash
    let msg = hex_to_32("6b63e9a74e092120160bea3877dace8a2cc7cd0e8426cbfffffffffafc8c3ca8");
    let sig = build_sig(
        "5e9b1c5a028070df5728c5c8af9b74e0667afa570a6cfa0114a5039ed15ee06f",
        "b1360907e2d9785ead362bb8d7bd661b6c29eeffd3c5037744edaeb9ad990c20",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 481 failed");
    // 478] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #281: special case hash
    let msg = hex_to_32("fc28259702a03845b6d75219444e8b43d094586e249c8699ffffffffe852512e");
    let sig = build_sig(
        "0671a0a85c2b72d54a2fb0990e34538b4890050f5a5712f6d1a7a5fb8578f32e",
        "db1846bab6b7361479ab9c3285ca41291808f27fd5bd4fdac720e5854713694c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 482 failed");
    // 479] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #282: special case hash
    let msg = hex_to_32("1273b4502ea4e3bccee044ee8e8db7f774ecbcd52e8ceb571757ffffffffe20a");
    let sig = build_sig(
        "7673f8526748446477dbbb0590a45492c5d7d69859d301abbaedb35b2095103a",
        "3dc70ddf9c6b524d886bed9e6af02e0e4dec0d417a414fed3807ef4422913d7c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 483 failed");
    // 480] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #283: special case hash
    let msg = hex_to_32("08fb565610a79baa0c566c66228d81814f8c53a15b96e602fb49ffffffffff6e");
    let sig = build_sig(
        "7f085441070ecd2bb21285089ebb1aa6450d1a06c36d3ff39dfd657a796d12b5",
        "249712012029870a2459d18d47da9aa492a5e6cb4b2d8dafa9e4c5c54a2b9a8b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 484 failed");
    // 481] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #284: special case hash
    let msg = hex_to_32("d59291cc2cf89f3087715fcb1aa4e79aa2403f748e97d7cd28ecaefeffffffff");
    let sig = build_sig(
        "914c67fb61dd1e27c867398ea7322d5ab76df04bc5aa6683a8e0f30a5d287348",
        "fa07474031481dda4953e3ac1959ee8cea7e66ec412b38d6c96d28f6d37304ea",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 485 failed");
    // 482] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #636: r too large
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
    );
    let pk = build_pk(
        "d705d16f80987e2d9b1a6957d29ce22febf7d10fa515153182415c8361baaca4",
        "b1fc105ee5ce80d514ec1238beae2037a6f83625593620d460819e8682160926",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 486 should fail");
    // 483] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #637: r,s are large
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
    );
    let pk = build_pk(
        "3cd8d2f81d6953b0844c09d7b560d527cd2ef67056893eadafa52c8501387d59",
        "ee41fdb4d10402ce7a0c5e3b747adfa3a490b62a6b7719068903485c0bb6dc2d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 487 failed");
    // 484] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #638: r and s^-1 have a large Hamming weight
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "909135bdb6799286170f5ead2de4f6511453fe50914f3df2de54a36383df8dd4",
    );
    let pk = build_pk(
        "8240cd81edd91cb6936133508c3915100e81f332c4545d41189b481196851378",
        "e05b06e72d4a1bff80ea5db514aa2f93ea6dd6d9c0ae27b7837dc432f9ce89d9",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 488 failed");
    // 485] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #639: r and s^-1 have a large Hamming weight
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "27b4577ca009376f71303fd5dd227dcef5deb773ad5f5a84360644669ca249a5",
    );
    let pk = build_pk(
        "b062947356748b0fc17f1704c65aa1dca6e1bfe6779756fa616d91eaad13df2c",
        "0b38c17f3d0672e7409cfc5992a99fff12b84a4f8432293b431113f1b2fb579d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 489 failed");
    // 486] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #651: r and s^-1 are close to n
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6324d5",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "7a736d8e326a9ca62bbe25a34ea4e3633b499a96afa7aaa3fcf3fd88f8e07ede",
        "b3e45879d8622b93e818443a686e869eeda7bf9ae46aa3eafcc48a5934864627",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 490 failed");
    // 487] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #654: point at infinity during verify
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "0203736fcb198b15d8d7a0c80f66dddd15259240aa78d08aae67c467de045034",
        "34383438d5041ea9a387ee8e4d4e84b4471b160c6bcf2568b072f8f20e87a996",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 491 should fail");
    // 488] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #655: edge case for signature malleability
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
    );
    let pk = build_pk(
        "78d844dc7f16b73b1f2a39730da5d8cd99fe2e70a18482384e37dcd2bfea02e1",
        "ed6572e01eb7a8d113d02c666c45ef22d3b9a6a6dea99aa43a8183c26e75d336",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 492 failed");
    // 489] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #656: edge case for signature malleability
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
    );
    let pk = build_pk(
        "dec6c8257dde94110eacc8c09d2e5789cc5beb81a958b02b4d62da9599a74014",
        "66fae1614174be63970b83f6524421067b06dd6f4e9c56baca4e344fdd690f1d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 493 failed");
    // 490] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #657: u1 == 1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
    );
    let pk = build_pk(
        "a17f5b75a35ed64623ca5cbf1f91951292db0c23f0c2ea24c3d0cad0988cabc0",
        "83a7a618625c228940730b4fa3ee64faecbb2fc20fdde7c58b3a3f6300424dc6",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 494 failed");
    // 491] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #658: u1 == n - 1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "acd155416a8b77f34089464733ff7cd39c400e9c69af7beb9eac5054ed2ec72c",
    );
    let pk = build_pk(
        "04ba0cba291a37db13f33bf90dab628c04ec8393a0200419e9eaa1ebcc9fb5c3",
        "1f3a0a0e6823a49b625ad57b12a32d4047970fc3428f0f0049ecf4265dc12f62",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 495 failed");
    // 492] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #659: u2 == 1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "692b6c828e0feed63d8aeaa2b7322f9ccbe8723a1ed39f229f204a434b8900ef",
        "a1f6f6abcb38ea3b8fde38b98c7c271f274af56a8c5628dc3329069ae4dd5716",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 496 failed");
    // 493] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #660: u2 == n - 1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
    );
    let pk = build_pk(
        "00cefd9162d13e64cb93687a9cd8f9755ebb5a3ef7632f800f84871874ccef09",
        "543ecbeaf7e8044ef721be2fb5f549e4b8480d2587404ebf7dbbef2c54bc0cb1",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 497 failed");
    // 494] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #661: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "710f8e3edc7c2d5a3fd23de844002bb949d9f794f6d5405f6d97c1bb03dd2bd2",
    );
    let pk = build_pk(
        "b975183b42551cf52f291d5c1921fd5e12f50c8c85a4beb9de03efa3f0f24486",
        "2243018e6866df922dc313612020311ff21e242ce3fb15bc78c406b25ab43091",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 498 failed");
    // 495] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #662: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "edffbc270f722c243069a7e5f40335a61a58525c7b4db2e7a8e269274ffe4e1b",
    );
    let pk = build_pk(
        "c25f1d166f3e211cdf042a26f8abf6094d48b8d17191d74ed717149274466999",
        "65d06dd6a88abfa49e8b4c5da6bb922851969adf9604b5accfb52a114e77ccdb",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 499 failed");
    // 496] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #663: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "a25adcae105ed7ff4f95d2344e24ee523314c3e178525d007904b68919ba4d53",
    );
    let pk = build_pk(
        "8fe5e88243a76e41a004236218a3c3a2d6eee398a23c3a0b008d7f0164cbc0ca",
        "98a20d1bdcf573513c7cfd9b83c63e3a82d40127c897697c86b8cb387af7f240",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 500 failed");
    // 497] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #664: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "2e4348c645707dce6760d773de3f3e87346924b2f64bd3dd0297e766b5805ebb",
    );
    let pk = build_pk(
        "02148256b530fbc470c7b341970b38243ecee6d5a840a37beca2efb37e8dff2c",
        "c0adbea0882482a7489ca703a399864ba987eeb6ddb738af53a83573473cb30d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 501 failed");
    // 498] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #665: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "348c673b07dce3920d773de3f3e87408869e916dbcf797d8f9684fb67753d1dc",
    );
    let pk = build_pk(
        "a34db012ce6eda1e9c7375c5fcf3e54ed698e19615124273b3a621d021c76f8e",
        "777458d6f55a364c221e39e1205d5510bb4fbb7ddf08d8d8fdde13d1d6df7f14",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 502 failed");
    // 499] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #666: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "6918ce760fb9c7241aee7bc7e7d0e8110d3d22db79ef2fb1f2d09f6ceea7a3b8",
    );
    let pk = build_pk(
        "b97af3fe78be15f2912b6271dd8a43badb6dd2a1b315b2ce7ae37b4e7778041d",
        "930d71ee1992d2466495c42102d08e81154c305307d1dcd52d0fa4c479b278e7",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 503 failed");
    // 500] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #667: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "73b3c694391d8eadde3f3e874089464715ac20e4c126bbf6d864d648969f5b5a",
    );
    let pk = build_pk(
        "81e7198a3c3f23901cedc7a1d6eff6e9bf81108e6c35cd8559139af3135dbcbb",
        "9ef1568530291a8061b90c9f4285eefcba990d4570a4e3b7b737525b5d580034",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 504 failed");
    // 501] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #668: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bb07ac7a86948c2c2989a16db1930ef1b89ce112595197656877e53c41457f28",
    );
    let pk = build_pk(
        "ab4d792ca121d1dba39cb9de645149c2ab573e8becc6ddff3cc9960f188ddf73",
        "7f90ba23664153e93262ff73355415195858d7be1315a69456386de68285a3c8",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 505 failed");
    // 502] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #669: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "27e4d82cb6c061dd9337c69bf9332ed3d198662d6f2299443f62c861187db648",
    );
    let pk = build_pk(
        "518412b69af43aae084476a68d59bbde51fbfa9e5be80563f587c9c2652f88ef",
        "2d3b90d25baa6bdb7b0c55e5240a3a98fbc24afed8523edec1c70503fc10f233",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 506 failed");
    // 503] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #670: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "e7c5cf3aac2e88923b77850515fff6a12d13b356dfe9ec275c3dd81ae94609a4",
    );
    let pk = build_pk(
        "a08f14a644b9a935dffea4761ebaf592d1f66fe6cd373aa7f5d370af34f8352d",
        "a54b5bc4025cf335900a914c2934ec2fec7a396d0a7affcad732a5741c7aaaf5",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 507 failed");
    // 504] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #671: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "c77838df91c1e953e016e10bddffea2317f9fee32bacfe553cede9e57a748f68",
    );
    let pk = build_pk(
        "ccf2296a6a89b62b90739d38af4ae3a20e9f45715b90044639241061e33f8f8c",
        "aace0046491eeaa1c6e9a472b96d88f4af83e7ff1bb84438c7e058034412ae08",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 508 failed");
    // 505] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #672: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "8ef071c02383d2a6c02dc217bbffd446730d0318b0425e2586220907f885f97f",
    );
    let pk = build_pk(
        "94b0fc1525bcabf82b1f34895e5819a06c02b23e04002276e165f962c86e3927",
        "be7c2ab4d0b25303204fb32a1f8292902792225e16a6d2dbfb29fbc89a9c3376",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 509 failed");
    // 506] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #673: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "5668aaa0b545bbf9a044a32399ffbe69ce20074e34d7bdf5cf56282a76976396",
    );
    let pk = build_pk(
        "5351f37e1de0c88c508527d89882d183ccdcf2efca407edb0627cadfd16de6ec",
        "44b4b57cdf960d32ebcc4c97847eed218425853b5b675eb781b766a1a1300349",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 510 failed");
    // 507] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #674: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "d12d6e56882f6c0027cae91a27127728f7fddf478fb4fdc2b65f40a60b0eb952",
    );
    let pk = build_pk(
        "748bbafc320e6735cb64019710a269c6c2b5d147bdc831325cb2fb276ac971a6",
        "9d655e9a755bc9d800ad21ee3fd4d980d93a7a49a8c5ccd37005177578f51163",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 511 failed");
    // 508] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #675: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "7fffffffaaaaaaaaffffffffffffffffe9a2538f37b28a2c513dee40fecbb71a",
    );
    let pk = build_pk(
        "14b3bbd75c5e1c0c36535a934d4ab85112410b3b90fa97a31c33038964fd85cc",
        "112f7d837f8f9c36b460d636c965a5f818f2b50c5d00fb3f9705561dd6631883",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 512 failed");
    // 509] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #676: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "b62f26b5f2a2b26f6de86d42ad8a13da3ab3cccd0459b201de009e526adf21f2",
    );
    let pk = build_pk(
        "d823533c04cd8edc6d6f950a8e08ade04a9bafa2f14a590356935671ae9305bf",
        "43178d1f88b6a57a96924c265f0ddb75b58312907b195acb59d7797303123775",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 513 failed");
    // 510] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #677: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bb1d9ac949dd748cd02bbbe749bd351cd57b38bb61403d700686aa7b4c90851e",
    );
    let pk = build_pk(
        "db2b3408b3167d91030624c6328e8ce3ec108c105575c2f3d209b92e654bab69",
        "c34318139c50b0802c6e612f0fd3189d800df7c996d5d7b7c3d6be82836fa258",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 514 failed");
    // 511] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #678: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "66755a00638cdaec1c732513ca0234ece52545dac11f816e818f725b4f60aaf2",
    );
    let pk = build_pk(
        "09179ce7c59225392216453b2ac1e9d178c24837dfae26bc1dd7ab6063852742",
        "5556b42e330289f3b826b2db7a86d19d45c2860a59f2be1ddcc3b691f95a9255",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 515 failed");
    // 512] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #679: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "55a00c9fcdaebb6032513ca0234ecfffe98ebe492fdf02e48ca48e982beb3669",
    );
    let pk = build_pk(
        "01959fb8deda56e5467b7e4b214ea4c2d0c2fb29d70ff19b6b1eccebd6568d7e",
        "d9dbd77a918297fd970bff01e1343f6925167db5a14d098a211c39cc3a413398",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 516 failed");
    // 513] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #680: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "ab40193f9b5d76c064a27940469d9fffd31d7c925fbe05c919491d3057d66cd2",
    );
    let pk = build_pk(
        "567f1fdc387e5350c852b4e8f8ba9d6d947e1c5dd7ccc61a5938245dd6bcab3a",
        "9960bebaf919514f9535c22eaaf0b5812857970e26662267b1f3eb1011130a11",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 517 failed");
    // 514] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #681: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "ca0234ebb5fdcb13ca0234ecffffffffcb0dadbbc7f549f8a26b4408d0dc8600",
    );
    let pk = build_pk(
        "3499f974ff4ca6bbb2f51682fd5f51762f9dd6dd2855262660b36d46d3e4bec2",
        "f498fae2487807e220119152f0122476c64d4fa46ddce85c4546630f0d5c5e81",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 518 failed");
    // 515] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #682: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff3ea3677e082b9310572620ae19933a9e65b285598711c77298815ad3",
    );
    let pk = build_pk(
        "2c5c01662cf00c1929596257db13b26ecf30d0f3ec4b9f0351b0f27094473426",
        "e986a086060d086eee822ddd2fc744247a0154b57f7a69c51d9fdafa484e4ac7",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 519 failed");
    // 516] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #683: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "266666663bbbbbbbe6666666666666665b37902e023fab7c8f055d86e5cc41f4",
    );
    let pk = build_pk(
        "91d4cba813a04d86dbae94c23be6f52c15774183be7ba5b2d9f3cf010b160501",
        "900b8adfea6491019a9ac080d516025a541bf4b952b0ad7be4b1874b02fd544a",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 520 failed");
    // 517] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #684: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff36db6db7a492492492492492146c573f4c6dfc8d08a443e258970b09",
    );
    let pk = build_pk(
        "ef7fd0a3a36386638330ecad41e1a3b302af36960831d0210c614b948e8aa124",
        "ef0d6d800e4047d6d3c1be0fdeaf11fcd8cab5ab59c730eb34116e35a8c7d098",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 521 failed");
    // 518] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #685: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff2aaaaaab7fffffffffffffffc815d0e60b3e596ecb1ad3a27cfd49c4",
    );
    let pk = build_pk(
        "a521dab13cc9152d8ca77035a607fea06c55cc3ca5dbeb868cea92eafe93df2a",
        "7bfb9b28531996635e6a5ccaa2826a406ce1111bdb9c2e0ca36500418a2f43de",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 522 failed");
    // 519] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #686: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "7fffffff55555555ffffffffffffffffd344a71e6f651458a27bdc81fd976e37",
    );
    let pk = build_pk(
        "474d58a4eec16e0d565f2187fe11d4e8e7a2683a12f38b4fc01d1237a81a1097",
        "6e55f73bb7cdda46bdb67ef77f6fd2969df2b67920fb5945fde3a517a6ded4cd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 523 failed");
    // 520] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #687: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "3fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192aa",
    );
    let pk = build_pk(
        "692da5cd4309d9a6e5cb525c37da8fa0879f7b57208cdabbf47d223a5b23a621",
        "40e0daa78cfdd207a7389aaed61738b17fc5fc3e6a5ed3397d2902e9125e6ab4",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 524 failed");
    // 521] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #688: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "5d8ecd64a4eeba466815ddf3a4de9a8e6abd9c5db0a01eb80343553da648428f",
    );
    let pk = build_pk(
        "85689b3e0775c7718a90279f14a8082cfcd4d1f1679274f4e9b8805c570a0670",
        "167fcc5ca734552e09afa3640f4a034e15b9b7ca661ec7ff70d3f240ebe705b1",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 525 failed");
    // 522] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #689: point duplication during verification
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569",
        "f21d907e3890916dc4fa1f4703c1e50d3f54ddf7383e44023a41de562aa18ed8",
    );
    let pk = build_pk(
        "0158137755b901f797a90d4ca8887e023cb2ef63b2ba2c0d455edaef42cf237e",
        "2a964fc00d377a8592b8b61aafa7a4aaa7c7b9fd2b41d6e0e17bd1ba5677edcd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 526 failed");
    // 523] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #690: duplication bug
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569",
        "f21d907e3890916dc4fa1f4703c1e50d3f54ddf7383e44023a41de562aa18ed8",
    );
    let pk = build_pk(
        "0158137755b901f797a90d4ca8887e023cb2ef63b2ba2c0d455edaef42cf237e",
        "d569b03ef2c8857b6d4749e550585b5558384603d4be291f1e842e45a9881232",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 527 should fail");
    // 524] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #693: comparison with point at infinity
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aa9",
    );
    let pk = build_pk(
        "664ce273320d918d8bdb2e61201b4549b36b7cdc54e33b84adb6f2c10aac831e",
        "49e68831f18bda2973ac3d76bfbc8c5ee1cceed2dd862e2dc7c915c736cef1f4",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 528 should fail");
    // 525] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #694: extreme value for k and edgecase s
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "961691a5e960d07a301dbbad4d86247ec27d7089faeb3ddd1add395efff1e0fe",
        "7254622cc371866cdf990d2c5377790e37d1f1519817f09a231bd260a9e78aeb",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 529 failed");
    // 526] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #695: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
    );
    let pk = build_pk(
        "5d283e13ce8ca60da868e3b0fb33e6b4f1074793274e2928250e71e2aca63e9c",
        "214dc74fa25371fb4d9e506d418ed9a1bfd6d0c8bb6591d3e0f44505a84886ce",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 530 failed");
    // 527] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #696: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
    );
    let pk = build_pk(
        "0fc351da038ae0803bd1d86514ae0462f9f8216551d9315aa9d297f792eef6a3",
        "41c74eed786f2d33da35360ca7aa925e753f00d6077a1e9e5fc339d634019c73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 531 failed");
    // 528] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #697: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
    );
    let pk = build_pk(
        "a1e34c8f16d138673fee55c080547c2bfd4de7550065f638322bba9430ce4b60",
        "662be9bb512663aa4d7df8ab3f3b4181c5d44a7bdf42436620b7d8a6b81ac936",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 532 failed");
    // 529] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #698: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "49249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
    );
    let pk = build_pk(
        "7e1a8a8338d7fd8cf41d322a302d2078a87a23c7186150ed7cda6e52817c1bdf",
        "d0a9135a89d21ce821e29014b2898349254d748272b2d4eb8d59ee34c615377f",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 533 failed");
    // 530] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #699: extreme value for k
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "16a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
    );
    let pk = build_pk(
        "5c19fe227a61abc65c61ee7a018cc9571b2c6f663ea33583f76a686f64be078b",
        "7b4a0d734940f613d52bc48673b457c2cf78492490a5cc5606c0541d17b24ddb",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 534 failed");
    // 531] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #700: extreme value for k and edgecase s
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "db02d1f3421d600e9d9ef9e47419dba3208eed08c2d4189a5db63abeb2739666",
        "e0ed26967b9ada9ed7ffe480827f90a0d210d5fd8ec628e31715e6b24125512a",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 535 failed");
    // 532] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #701: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
    );
    let pk = build_pk(
        "6222d1962655501893c29e441395b6c05711bd3ed5a0ef72cfab338b88229c4b",
        "aaae079cb44a1af070362aaa520ee24cac2626423b0bf81af1c54311d8e2fd23",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 536 failed");
    // 533] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #702: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
    );
    let pk = build_pk(
        "4ccfa24c67f3def7fa81bc99c70bb0419c0952ba599f4c03361da184b04cdca5",
        "db76b797f7f41d9c729a2219478a7e629728df870800be8cf6ca7a0a82153bfa",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 537 failed");
    // 534] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #703: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
    );
    let pk = build_pk(
        "ea1c72c91034036bac71402b6e9ecc4af3dbde7a99dc574061e99fefff9d84da",
        "b7dd057e75b78ac6f56e34eb048f0a9d29d5d055408c90d02bc2ea918c18cb63",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 538 failed");
    // 535] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #704: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "49249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
    );
    let pk = build_pk(
        "c2879a66d86cb20b820b7795da2da62b38924f7817d1cd350d936988e90e79bc",
        "5431a7268ff6931c7a759de024eff90bcb0177216db6fd1f3aaaa11fa3b6a083",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 539 failed");
    // 536] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #705: extreme value for k
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "16a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
    );
    let pk = build_pk(
        "ab1c0f273f74abc2b848c75006f2ef3c54c26df27711b06558f455079aee0ba3",
        "df510f2ecef6d9a05997c776f14ad6456c179f0a13af1771e4d6c37fa48b47f2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 540 failed");
    // 537] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #706: testing point duplication
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 541 should fail");
    // 538] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #707: testing point duplication
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "acd155416a8b77f34089464733ff7cd39c400e9c69af7beb9eac5054ed2ec72c",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 542 should fail");
    // 539] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #708: testing point duplication
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 543 should fail");
    // 540] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #709: testing point duplication
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "acd155416a8b77f34089464733ff7cd39c400e9c69af7beb9eac5054ed2ec72c",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 544 should fail");
    // 541] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1210: pseudorandom signature
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "a8ea150cb80125d7381c4c1f1da8e9de2711f9917060406a73d7904519e51388",
        "f3ab9fa68bd47973a73b2d40480c2ba50c22c9d76ec217257288293285449b86",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 545 failed");
    // 542] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1211: pseudorandom signature
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "30e782f964b2e2ff065a051bc7adc20615d8c43a1365713c88268822c253bcce",
        "5b16df652aa1ecb2dc8b46c515f9604e2e84cacfa7c6eec30428d2d3f4e08ed5",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 546 failed");
    // 543] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1212: pseudorandom signature
    let msg = hex_to_32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    let sig = build_sig(
        "b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a",
        "0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 547 failed");
    // 544] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1213: pseudorandom signature
    let msg = hex_to_32("de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90");
    let sig = build_sig(
        "986e65933ef2ed4ee5aada139f52b70539aaf63f00a91f29c69178490d57fb71",
        "3dafedfb8da6189d372308cbf1489bbbdabf0c0217d1c0ff0f701aaa7a694b9c",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 548 failed");
    // 545] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1303: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d434e262a49eab7781e353a3565e482550dd0fd5defa013c7f29745eff3569f1",
        "9b0c0a93f267fb6052fd8077be769c2b98953195d7bc10de844218305c6ba17a",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 549 failed");
    // 546] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1304: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "0fe774355c04d060f76d79fd7a772e421463489221bf0a33add0be9b1979110b",
        "500dcba1c69a8fbd43fa4f57f743ce124ca8b91a1f325f3fac6181175df55737",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 550 failed");
    // 547] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1305: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "bb40bf217bed3fb3950c7d39f03d36dc8e3b2cd79693f125bfd06595ee1135e3",
        "541bf3532351ebb032710bdb6a1bf1bfc89a1e291ac692b3fa4780745bb55677",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 551 failed");
    // 548] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1306: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "664eb7ee6db84a34df3c86ea31389a5405badd5ca99231ff556d3e75a233e73a",
        "59f3c752e52eca46137642490a51560ce0badc678754b8f72e51a2901426a1bd",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 552 failed");
    // 549] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1307: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "4cd0429bbabd2827009d6fcd843d4ce39c3e42e2d1631fd001985a79d1fd8b43",
        "9638bf12dd682f60be7ef1d0e0d98f08b7bca77a1a2b869ae466189d2acdabe3",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 553 failed");
    // 550] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1308: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "e56c6ea2d1b017091c44d8b6cb62b9f460e3ce9aed5e5fd41e8added97c56c04",
        "a308ec31f281e955be20b457e463440b4fcf2b80258078207fc1378180f89b55",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 554 failed");
    // 551] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1309: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "1158a08d291500b4cabed3346d891eee57c176356a2624fb011f8fbbf3466830",
        "228a8c486a736006e082325b85290c5bc91f378b75d487dda46798c18f285519",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 555 failed");
    // 552] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1310: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b1db9289649f59410ea36b0c0fc8d6aa2687b29176939dd23e0dde56d309fa9d",
        "3e1535e4280559015b0dbd987366dcf43a6d1af5c23c7d584e1c3f48a1251336",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 556 failed");
    // 553] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1311: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b7b16e762286cb96446aa8d4e6e7578b0a341a79f2dd1a220ac6f0ca4e24ed86",
        "ddc60a700a139b04661c547d07bbb0721780146df799ccf55e55234ecb8f12bc",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 557 failed");
    // 554] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1312: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d82a7c2717261187c8e00d8df963ff35d796edad36bc6e6bd1c91c670d9105b4",
        "3dcabddaf8fcaa61f4603e7cbac0f3c0351ecd5988efb23f680d07debd139929",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 558 failed");
    // 555] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1313: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "5eb9c8845de68eb13d5befe719f462d77787802baff30ce96a5cba063254af78",
        "2c026ae9be2e2a5e7ca0ff9bbd92fb6e44972186228ee9a62b87ddbe2ef66fb5",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 559 failed");
    // 556] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1314: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "96843dd03c22abd2f3b782b170239f90f277921becc117d0404a8e4e36230c28",
        "f2be378f526f74a543f67165976de9ed9a31214eb4d7e6db19e1ede123dd991d",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 560 failed");
    // 557] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1315: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "766456dce1857c906f9996af729339464d27e9d98edc2d0e3b760297067421f6",
        "402385ecadae0d8081dccaf5d19037ec4e55376eced699e93646bfbbf19d0b41",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 561 failed");
    // 558] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1316: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "c605c4b2edeab20419e6518a11b2dbc2b97ed8b07cced0b19c34f777de7b9fd9",
        "edf0f612c5f46e03c719647bc8af1b29b2cde2eda700fb1cff5e159d47326dba",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 562 failed");
    // 559] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1317: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d48b68e6cabfe03cf6141c9ac54141f210e64485d9929ad7b732bfe3b7eb8a84",
        "feedae50c61bd00e19dc26f9b7e2265e4508c389109ad2f208f0772315b6c941",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 563 failed");
    // 560] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1318: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b7c81457d4aeb6aa65957098569f0479710ad7f6595d5874c35a93d12a5dd4c7",
        "b7961a0b652878c2d568069a432ca18a1a9199f2ca574dad4b9e3a05c0a1cdb3",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 564 failed");
    // 561] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1319: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "6b01332ddb6edfa9a30a1321d5858e1ee3cf97e263e669f8de5e9652e76ff3f7",
        "5939545fced457309a6a04ace2bd0f70139c8f7d86b02cb1cc58f9e69e96cd5a",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 565 failed");
    // 562] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1320: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "efdb884720eaeadc349f9fc356b6c0344101cd2fd8436b7d0e6a4fb93f106361",
        "f24bee6ad5dc05f7613975473aadf3aacba9e77de7d69b6ce48cb60d8113385d",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 566 failed");
    // 563] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1321: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "31230428405560dcb88fb5a646836aea9b23a23dd973dcbe8014c87b8b20eb07",
        "0f9344d6e812ce166646747694a41b0aaf97374e19f3c5fb8bd7ae3d9bd0beff",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 567 failed");
    // 564] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1322: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "caa797da65b320ab0d5c470cda0b36b294359c7db9841d679174db34c4855743",
        "cf543a62f23e212745391aaf7505f345123d2685ee3b941d3de6d9b36242e5a0",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 568 failed");
    // 565] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1323: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "7e5f0ab5d900d3d3d7867657e5d6d36519bc54084536e7d21c336ed800185945",
        "9450c07f201faec94b82dfb322e5ac676688294aad35aa72e727ff0b19b646aa",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 569 failed");
    // 566] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1324: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d7d70c581ae9e3f66dc6a480bf037ae23f8a1e4a2136fe4b03aa69f0ca25b356",
        "89c460f8a5a5c2bbba962c8a3ee833a413e85658e62a59e2af41d9127cc47224",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 570 failed");
    // 567] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1325: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "341c1b9ff3c83dd5e0dfa0bf68bcdf4bb7aa20c625975e5eeee34bb396266b34",
        "72b69f061b750fd5121b22b11366fad549c634e77765a017902a67099e0a4469",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 571 failed");
    // 568] wycheproof/ecdsa_test.json EcdsaVerify SHA-256 #1326: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67",
        "aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 572 failed");
    // 569] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #1: signature malleability
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "4cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 573 failed");
    // 570] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #3: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 574 should fail");
    // 571] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #5: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "d45c5741946b2a137f59262ee6f5bc91001af27a5e1117a64733950642a3d1e8",
        "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 575 should fail");
    // 572] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #8: Modified r or s, e.g. by adding or subtracting the order of the group
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
        "4cd60b865d442f5a3c7b11eb6c4e0ae79578ec6353a20bf783ecb4b6ea97b825",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 576 should fail");
    // 573] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #9: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 577 should fail");
    // 574] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #10: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 578 should fail");
    // 575] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #11: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 579 should fail");
    // 576] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #12: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 580 should fail");
    // 577] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #13: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 581 should fail");
    // 578] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #14: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 582 should fail");
    // 579] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #15: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 583 should fail");
    // 580] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #16: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 584 should fail");
    // 581] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #17: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 585 should fail");
    // 582] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #18: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 586 should fail");
    // 583] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #19: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 587 should fail");
    // 584] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #20: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 588 should fail");
    // 585] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #21: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 589 should fail");
    // 586] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #22: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 590 should fail");
    // 587] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #23: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 591 should fail");
    // 588] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #24: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 592 should fail");
    // 589] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #25: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 593 should fail");
    // 590] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #26: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 594 should fail");
    // 591] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #27: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 595 should fail");
    // 592] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #28: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 596 should fail");
    // 593] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #29: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 597 should fail");
    // 594] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #30: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 598 should fail");
    // 595] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #31: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 599 should fail");
    // 596] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #32: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 600 should fail");
    // 597] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #33: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 601 should fail");
    // 598] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #34: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 602 should fail");
    // 599] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #35: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 603 should fail");
    // 600] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #36: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 604 should fail");
    // 601] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #37: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 605 should fail");
    // 602] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #38: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 606 should fail");
    // 603] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #39: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 607 should fail");
    // 604] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #40: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 608 should fail");
    // 605] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #41: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 609 should fail");
    // 606] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #42: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 610 should fail");
    // 607] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #43: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 611 should fail");
    // 608] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #44: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 612 should fail");
    // 609] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #45: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 613 should fail");
    // 610] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #46: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 614 should fail");
    // 611] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #47: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 615 should fail");
    // 612] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #48: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 616 should fail");
    // 613] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #49: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 617 should fail");
    // 614] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #50: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 618 should fail");
    // 615] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #51: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 619 should fail");
    // 616] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #52: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 620 should fail");
    // 617] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #53: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 621 should fail");
    // 618] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #54: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 622 should fail");
    // 619] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #55: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 623 should fail");
    // 620] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #56: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 624 should fail");
    // 621] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #57: Signature with special case values for r and s
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000001000000000000000000000000",
        "ffffffff00000001000000000000000000000001000000000000000000000000",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 625 should fail");
    // 622] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #58: Edge case for Shamir multiplication
    let msg = hex_to_32("70239dd877f7c944c422f44dea4ed1a52f2627416faf2f072fa50c772ed6f807");
    let sig = build_sig(
        "64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e",
        "6af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 626 failed");
    // 623] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #59: special case hash
    let msg = hex_to_32("00000000690ed426ccf17803ebe2bd0884bcd58a1bb5e7477ead3645f356e7a9");
    let sig = build_sig(
        "16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf266",
        "252cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 627 failed");
    // 624] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #60: special case hash
    let msg = hex_to_32("7300000000213f2a525c6035725235c2f696ad3ebb5ee47f140697ad25770d91");
    let sig = build_sig(
        "9cc98be2347d469bf476dfc26b9b733df2d26d6ef524af917c665baccb23c882",
        "093496459effe2d8d70727b82462f61d0ec1b7847929d10ea631dacb16b56c32",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 628 failed");
    // 625] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #61: special case hash
    let msg = hex_to_32("ddf2000000005e0be0635b245f0b97978afd25daadeb3edb4a0161c27fe06045");
    let sig = build_sig(
        "73b3c90ecd390028058164524dde892703dce3dea0d53fa8093999f07ab8aa43",
        "2f67b0b8e20636695bb7d8bf0a651c802ed25a395387b5f4188c0c4075c88634",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 629 failed");
    // 626] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #62: special case hash
    let msg = hex_to_32("67ab1900000000784769c4ecb9e164d6642b8499588b89855be1ec355d0841a0");
    let sig = build_sig(
        "bfab3098252847b328fadf2f89b95c851a7f0eb390763378f37e90119d5ba3dd",
        "bdd64e234e832b1067c2d058ccb44d978195ccebb65c2aaf1e2da9b8b4987e3b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 630 failed");
    // 627] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #63: special case hash
    let msg = hex_to_32("a2bf09460000000076d7dbeffe125eaf02095dff252ee905e296b6350fc311cf");
    let sig = build_sig(
        "204a9784074b246d8bf8bf04a4ceb1c1f1c9aaab168b1596d17093c5cd21d2cd",
        "51cce41670636783dc06a759c8847868a406c2506fe17975582fe648d1d88b52",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 631 failed");
    // 628] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #64: special case hash
    let msg = hex_to_32("3554e827c700000000e1e75e624a06b3a0a353171160858129e15c544e4f0e65");
    let sig = build_sig(
        "ed66dc34f551ac82f63d4aa4f81fe2cb0031a91d1314f835027bca0f1ceeaa03",
        "99ca123aa09b13cd194a422e18d5fda167623c3f6e5d4d6abb8953d67c0c48c7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 632 failed");
    // 629] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #65: special case hash
    let msg = hex_to_32("9b6cd3b812610000000026941a0f0bb53255ea4c9fd0cb3426e3a54b9fc6965c");
    let sig = build_sig(
        "060b700bef665c68899d44f2356a578d126b062023ccc3c056bf0f60a237012b",
        "8d186c027832965f4fcc78a3366ca95dedbb410cbef3f26d6be5d581c11d3610",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 633 failed");
    // 630] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #66: special case hash
    let msg = hex_to_32("883ae39f50bf0100000000e7561c26fc82a52baa51c71ca877162f93c4ae0186");
    let sig = build_sig(
        "9f6adfe8d5eb5b2c24d7aa7934b6cf29c93ea76cd313c9132bb0c8e38c96831d",
        "b26a9c9e40e55ee0890c944cf271756c906a33e66b5bd15e051593883b5e9902",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 634 failed");
    // 631] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #67: special case hash
    let msg = hex_to_32("a1ce5d6e5ecaf28b0000000000fa7cd010540f420fb4ff7401fe9fce011d0ba6");
    let sig = build_sig(
        "a1af03ca91677b673ad2f33615e56174a1abf6da168cebfa8868f4ba273f16b7",
        "20aa73ffe48afa6435cd258b173d0c2377d69022e7d098d75caf24c8c5e06b1c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 635 failed");
    // 632] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #68: special case hash
    let msg = hex_to_32("8ea5f645f373f580930000000038345397330012a8ee836c5494cdffd5ee8054");
    let sig = build_sig(
        "fdc70602766f8eed11a6c99a71c973d5659355507b843da6e327a28c11893db9",
        "3df5349688a085b137b1eacf456a9e9e0f6d15ec0078ca60a7f83f2b10d21350",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 636 failed");
    // 633] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #69: special case hash
    let msg = hex_to_32("660570d323e9f75fa734000000008792d65ce93eabb7d60d8d9c1bbdcb5ef305");
    let sig = build_sig(
        "b516a314f2fce530d6537f6a6c49966c23456f63c643cf8e0dc738f7b876e675",
        "d39ffd033c92b6d717dd536fbc5efdf1967c4bd80954479ba66b0120cd16fff2",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 637 failed");
    // 634] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #70: special case hash
    let msg = hex_to_32("d0462673154cce587dde8800000000e98d35f1f45cf9c3bf46ada2de4c568c34");
    let sig = build_sig(
        "3b2cbf046eac45842ecb7984d475831582717bebb6492fd0a485c101e29ff0a8",
        "4c9b7b47a98b0f82de512bc9313aaf51701099cac5f76e68c8595fc1c1d99258",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 638 failed");
    // 635] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #71: special case hash
    let msg = hex_to_32("bd90640269a7822680cedfef000000000caef15a6171059ab83e7b4418d7278f");
    let sig = build_sig(
        "30c87d35e636f540841f14af54e2f9edd79d0312cfa1ab656c3fb15bfde48dcf",
        "47c15a5a82d24b75c85a692bd6ecafeb71409ede23efd08e0db9abf6340677ed",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 639 failed");
    // 636] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #72: special case hash
    let msg = hex_to_32("33239a52d72f1311512e41222a00000000d2dcceb301c54b4beae8e284788a73");
    let sig = build_sig(
        "38686ff0fda2cef6bc43b58cfe6647b9e2e8176d168dec3c68ff262113760f52",
        "067ec3b651f422669601662167fa8717e976e2db5e6a4cf7c2ddabb3fde9d67d",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 640 failed");
    // 637] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #73: special case hash
    let msg = hex_to_32("b8d64fbcd4a1c10f1365d4e6d95c000000007ee4a21a1cbe1dc84c2d941ffaf1");
    let sig = build_sig(
        "44a3e23bf314f2b344fc25c7f2de8b6af3e17d27f5ee844b225985ab6e2775cf",
        "2d48e223205e98041ddc87be532abed584f0411f5729500493c9cc3f4dd15e86",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 641 failed");
    // 638] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #74: special case hash
    let msg = hex_to_32("01603d3982bf77d7a3fef3183ed092000000003a227420db4088b20fe0e9d84a");
    let sig = build_sig(
        "2ded5b7ec8e90e7bf11f967a3d95110c41b99db3b5aa8d330eb9d638781688e9",
        "7d5792c53628155e1bfc46fb1a67e3088de049c328ae1f44ec69238a009808f9",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 642 failed");
    // 639] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #75: special case hash
    let msg = hex_to_32("9ea6994f1e0384c8599aa02e6cf66d9c000000004d89ef50b7e9eb0cfbff7363");
    let sig = build_sig(
        "bdae7bcb580bf335efd3bc3d31870f923eaccafcd40ec2f605976f15137d8b8f",
        "f6dfa12f19e525270b0106eecfe257499f373a4fb318994f24838122ce7ec3c7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 643 failed");
    // 640] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #76: special case hash
    let msg = hex_to_32("d03215a8401bcf16693979371a01068a4700000000e2fa5bf692bc670905b18c");
    let sig = build_sig(
        "50f9c4f0cd6940e162720957ffff513799209b78596956d21ece251c2401f1c6",
        "d7033a0a787d338e889defaaabb106b95a4355e411a59c32aa5167dfab244726",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 644 failed");
    // 641] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #77: special case hash
    let msg = hex_to_32("307bfaaffb650c889c84bf83f0300e5dc87e000000008408fd5f64b582e3bb14");
    let sig = build_sig(
        "f612820687604fa01906066a378d67540982e29575d019aabe90924ead5c860d",
        "3f9367702dd7dd4f75ea98afd20e328a1a99f4857b316525328230ce294b0fef",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 645 failed");
    // 642] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #78: special case hash
    let msg = hex_to_32("bab5c4f4df540d7b33324d36bb0c157551527c00000000e4af574bb4d54ea6b8");
    let sig = build_sig(
        "9505e407657d6e8bc93db5da7aa6f5081f61980c1949f56b0f2f507da5782a7a",
        "c60d31904e3669738ffbeccab6c3656c08e0ed5cb92b3cfa5e7f71784f9c5021",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 646 failed");
    // 643] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #79: special case hash
    let msg = hex_to_32("d4ba47f6ae28f274e4f58d8036f9c36ec2456f5b00000000c3b869197ef5e15e");
    let sig = build_sig(
        "bbd16fbbb656b6d0d83e6a7787cd691b08735aed371732723e1c68a40404517d",
        "9d8e35dba96028b7787d91315be675877d2d097be5e8ee34560e3e7fd25c0f00",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 647 failed");
    // 644] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #80: special case hash
    let msg = hex_to_32("79fd19c7235ea212f29f1fa00984342afe0f10aafd00000000801e47f8c184e1");
    let sig = build_sig(
        "2ec9760122db98fd06ea76848d35a6da442d2ceef7559a30cf57c61e92df327e",
        "7ab271da90859479701fccf86e462ee3393fb6814c27b760c4963625c0a19878",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 648 failed");
    // 645] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #81: special case hash
    let msg = hex_to_32("8c291e8eeaa45adbaf9aba5c0583462d79cbeb7ac97300000000a37ea6700cda");
    let sig = build_sig(
        "54e76b7683b6650baa6a7fc49b1c51eed9ba9dd463221f7a4f1005a89fe00c59",
        "2ea076886c773eb937ec1cc8374b7915cfd11b1c1ae1166152f2f7806a31c8fd",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 649 failed");
    // 646] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #82: special case hash
    let msg = hex_to_32("0eaae8641084fa979803efbfb8140732f4cdcf66c3f78a000000003c278a6b21");
    let sig = build_sig(
        "5291deaf24659ffbbce6e3c26f6021097a74abdbb69be4fb10419c0c496c9466",
        "65d6fcf336d27cc7cdb982bb4e4ecef5827f84742f29f10abf83469270a03dc3",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 650 failed");
    // 647] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #83: special case hash
    let msg = hex_to_32("e02716d01fb23a5a0068399bf01bab42ef17c6d96e13846c00000000afc0f89d");
    let sig = build_sig(
        "207a3241812d75d947419dc58efb05e8003b33fc17eb50f9d15166a88479f107",
        "cdee749f2e492b213ce80b32d0574f62f1c5d70793cf55e382d5caadf7592767",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 651 failed");
    // 648] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #84: special case hash
    let msg = hex_to_32("9eb0bf583a1a6b9a194e9a16bc7dab2a9061768af89d00659a00000000fc7de1");
    let sig = build_sig(
        "6554e49f82a855204328ac94913bf01bbe84437a355a0a37c0dee3cf81aa7728",
        "aea00de2507ddaf5c94e1e126980d3df16250a2eaebc8be486effe7f22b4f929",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 652 failed");
    // 649] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #85: special case hash
    let msg = hex_to_32("62aac98818b3b84a2c214f0d5e72ef286e1030cb53d9a82b690e00000000cd15");
    let sig = build_sig(
        "a54c5062648339d2bff06f71c88216c26c6e19b4d80a8c602990ac82707efdfc",
        "e99bbe7fcfafae3e69fd016777517aa01056317f467ad09aff09be73c9731b0d",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 653 failed");
    // 650] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #86: special case hash
    let msg = hex_to_32("3760a7f37cf96218f29ae43732e513efd2b6f552ea4b6895464b9300000000c8");
    let sig = build_sig(
        "975bd7157a8d363b309f1f444012b1a1d23096593133e71b4ca8b059cff37eaf",
        "7faa7a28b1c822baa241793f2abc930bd4c69840fe090f2aacc46786bf919622",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 654 failed");
    // 651] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #87: special case hash
    let msg = hex_to_32("0da0a1d2851d33023834f2098c0880096b4320bea836cd9cbb6ff6c800000000");
    let sig = build_sig(
        "5694a6f84b8f875c276afd2ebcfe4d61de9ec90305afb1357b95b3e0da43885e",
        "0dffad9ffd0b757d8051dec02ebdf70d8ee2dc5c7870c0823b6ccc7c679cbaa4",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 655 failed");
    // 652] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #88: special case hash
    let msg = hex_to_32("ffffffff293886d3086fd567aafd598f0fe975f735887194a764a231e82d289a");
    let sig = build_sig(
        "a0c30e8026fdb2b4b4968a27d16a6d08f7098f1a98d21620d7454ba9790f1ba6",
        "5e470453a8a399f15baf463f9deceb53acc5ca64459149688bd2760c65424339",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 656 failed");
    // 653] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #89: special case hash
    let msg = hex_to_32("7bffffffff2376d1e3c03445a072e24326acdc4ce127ec2e0e8d9ca99527e7b7");
    let sig = build_sig(
        "614ea84acf736527dd73602cd4bb4eea1dfebebd5ad8aca52aa0228cf7b99a88",
        "737cc85f5f2d2f60d1b8183f3ed490e4de14368e96a9482c2a4dd193195c902f",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 657 failed");
    // 654] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #90: special case hash
    let msg = hex_to_32("a2b5ffffffffebb251b085377605a224bc80872602a6e467fd016807e97fa395");
    let sig = build_sig(
        "bead6734ebe44b810d3fb2ea00b1732945377338febfd439a8d74dfbd0f942fa",
        "6bb18eae36616a7d3cad35919fd21a8af4bbe7a10f73b3e036a46b103ef56e2a",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 658 failed");
    // 655] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #91: special case hash
    let msg = hex_to_32("641227ffffffff6f1b96fa5f097fcf3cc1a3c256870d45a67b83d0967d4b20c0");
    let sig = build_sig(
        "499625479e161dacd4db9d9ce64854c98d922cbf212703e9654fae182df9bad2",
        "42c177cf37b8193a0131108d97819edd9439936028864ac195b64fca76d9d693",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 659 failed");
    // 656] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #92: special case hash
    let msg = hex_to_32("958415d8ffffffffabad03e2fc662dc3ba203521177502298df56f36600e0f8b");
    let sig = build_sig(
        "08f16b8093a8fb4d66a2c8065b541b3d31e3bfe694f6b89c50fb1aaa6ff6c9b2",
        "9d6455e2d5d1779748573b611cb95d4a21f967410399b39b535ba3e5af81ca2e",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 660 failed");
    // 657] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #93: special case hash
    let msg = hex_to_32("f1d8de4858ffffffff1281093536f47fe13deb04e1fbe8fb954521b6975420f8");
    let sig = build_sig(
        "be26231b6191658a19dd72ddb99ed8f8c579b6938d19bce8eed8dc2b338cb5f8",
        "e1d9a32ee56cffed37f0f22b2dcb57d5c943c14f79694a03b9c5e96952575c89",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 661 failed");
    // 658] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #94: special case hash
    let msg = hex_to_32("0927895f2802ffffffff10782dd14a3b32dc5d47c05ef6f1876b95c81fc31def");
    let sig = build_sig(
        "15e76880898316b16204ac920a02d58045f36a229d4aa4f812638c455abe0443",
        "e74d357d3fcb5c8c5337bd6aba4178b455ca10e226e13f9638196506a1939123",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 662 failed");
    // 659] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #95: special case hash
    let msg = hex_to_32("60907984aa7e8effffffff4f332862a10a57c3063fb5a30624cf6a0c3ac80589");
    let sig = build_sig(
        "352ecb53f8df2c503a45f9846fc28d1d31e6307d3ddbffc1132315cc07f16dad",
        "1348dfa9c482c558e1d05c5242ca1c39436726ecd28258b1899792887dd0a3c6",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 663 failed");
    // 660] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #96: special case hash
    let msg = hex_to_32("c6ff198484939170ffffffff0af42cda50f9a5f50636ea6942d6b9b8cd6ae1e2");
    let sig = build_sig(
        "4a40801a7e606ba78a0da9882ab23c7677b8642349ed3d652c5bfa5f2a9558fb",
        "3a49b64848d682ef7f605f2832f7384bdc24ed2925825bf8ea77dc5981725782",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 664 failed");
    // 661] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #97: special case hash
    let msg = hex_to_32("de030419345ca15c75ffffffff8074799b9e0956cc43135d16dfbe4d27d7e68d");
    let sig = build_sig(
        "eacc5e1a8304a74d2be412b078924b3bb3511bac855c05c9e5e9e44df3d61e96",
        "7451cd8e18d6ed1885dd827714847f96ec4bb0ed4c36ce9808db8f714204f6d1",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 665 failed");
    // 662] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #98: special case hash
    let msg = hex_to_32("6f0e3eeaf42b28132b88fffffffff6c8665604d34acb19037e1ab78caaaac6ff");
    let sig = build_sig(
        "2f7a5e9e5771d424f30f67fdab61e8ce4f8cd1214882adb65f7de94c31577052",
        "ac4e69808345809b44acb0b2bd889175fb75dd050c5a449ab9528f8f78daa10c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 666 failed");
    // 663] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #99: special case hash
    let msg = hex_to_32("cdb549f773b3e62b3708d1ffffffffbe48f7c0591ddcae7d2cb222d1f8017ab9");
    let sig = build_sig(
        "ffcda40f792ce4d93e7e0f0e95e1a2147dddd7f6487621c30a03d710b3300219",
        "79938b55f8a17f7ed7ba9ade8f2065a1fa77618f0b67add8d58c422c2453a49a",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 667 failed");
    // 664] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #100: special case hash
    let msg = hex_to_32("2c3f26f96a3ac0051df4989bffffffff9fd64886c1dc4f9924d8fd6f0edb0484");
    let sig = build_sig(
        "81f2359c4faba6b53d3e8c8c3fcc16a948350f7ab3a588b28c17603a431e39a8",
        "cd6f6a5cc3b55ead0ff695d06c6860b509e46d99fccefb9f7f9e101857f74300",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 668 failed");
    // 665] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #101: special case hash
    let msg = hex_to_32("ac18f8418c55a2502cb7d53f9affffffff5c31d89fda6a6b8476397c04edf411");
    let sig = build_sig(
        "dfc8bf520445cbb8ee1596fb073ea283ea130251a6fdffa5c3f5f2aaf75ca808",
        "048e33efce147c9dd92823640e338e68bfd7d0dc7a4905b3a7ac711e577e90e7",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 669 failed");
    // 666] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #102: special case hash
    let msg = hex_to_32("4f9618f98e2d3a15b24094f72bb5ffffffffa2fd3e2893683e5a6ab8cf0ee610");
    let sig = build_sig(
        "ad019f74c6941d20efda70b46c53db166503a0e393e932f688227688ba6a5762",
        "93320eb7ca0710255346bdbb3102cdcf7964ef2e0988e712bc05efe16c199345",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 670 failed");
    // 667] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #103: special case hash
    let msg = hex_to_32("422e82a3d56ed10a9cc21d31d37a25ffffffff67edf7c40204caae73ab0bc75a");
    let sig = build_sig(
        "ac8096842e8add68c34e78ce11dd71e4b54316bd3ebf7fffdeb7bd5a3ebc1883",
        "f5ca2f4f23d674502d4caf85d187215d36e3ce9f0ce219709f21a3aac003b7a8",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 671 failed");
    // 668] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #104: special case hash
    let msg = hex_to_32("7075d245ccc3281b6e7b329ff738fbb417a5ffffffffa0842d9890b5cf95d018");
    let sig = build_sig(
        "677b2d3a59b18a5ff939b70ea002250889ddcd7b7b9d776854b4943693fb92f7",
        "6b4ba856ade7677bf30307b21f3ccda35d2f63aee81efd0bab6972cc0795db55",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 672 failed");
    // 669] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #105: special case hash
    let msg = hex_to_32("3c80de54cd9226989443d593fa4fd6597e280ebeffffffffc1847eb76c217a95");
    let sig = build_sig(
        "479e1ded14bcaed0379ba8e1b73d3115d84d31d4b7c30e1f05e1fc0d5957cfb0",
        "918f79e35b3d89487cf634a4f05b2e0c30857ca879f97c771e877027355b2443",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 673 failed");
    // 670] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #106: special case hash
    let msg = hex_to_32("de21754e29b85601980bef3d697ea2770ce891a8cdffffffffc7906aa794b39b");
    let sig = build_sig(
        "43dfccd0edb9e280d9a58f01164d55c3d711e14b12ac5cf3b64840ead512a0a3",
        "1dbe33fa8ba84533cd5c4934365b3442ca1174899b78ef9a3199f49584389772",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 674 failed");
    // 671] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #107: special case hash
    let msg = hex_to_32("8f65d92927cfb86a84dd59623fb531bb599e4d5f7289ffffffff2f1f2f57881c");
    let sig = build_sig(
        "5b09ab637bd4caf0f4c7c7e4bca592fea20e9087c259d26a38bb4085f0bbff11",
        "45b7eb467b6748af618e9d80d6fdcd6aa24964e5a13f885bca8101de08eb0d75",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 675 failed");
    // 672] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #108: special case hash
    let msg = hex_to_32("6b63e9a74e092120160bea3877dace8a2cc7cd0e8426cbfffffffffafc8c3ca8");
    let sig = build_sig(
        "5e9b1c5a028070df5728c5c8af9b74e0667afa570a6cfa0114a5039ed15ee06f",
        "b1360907e2d9785ead362bb8d7bd661b6c29eeffd3c5037744edaeb9ad990c20",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 676 failed");
    // 673] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #109: special case hash
    let msg = hex_to_32("fc28259702a03845b6d75219444e8b43d094586e249c8699ffffffffe852512e");
    let sig = build_sig(
        "0671a0a85c2b72d54a2fb0990e34538b4890050f5a5712f6d1a7a5fb8578f32e",
        "db1846bab6b7361479ab9c3285ca41291808f27fd5bd4fdac720e5854713694c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 677 failed");
    // 674] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #110: special case hash
    let msg = hex_to_32("1273b4502ea4e3bccee044ee8e8db7f774ecbcd52e8ceb571757ffffffffe20a");
    let sig = build_sig(
        "7673f8526748446477dbbb0590a45492c5d7d69859d301abbaedb35b2095103a",
        "3dc70ddf9c6b524d886bed9e6af02e0e4dec0d417a414fed3807ef4422913d7c",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 678 failed");
    // 675] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #111: special case hash
    let msg = hex_to_32("08fb565610a79baa0c566c66228d81814f8c53a15b96e602fb49ffffffffff6e");
    let sig = build_sig(
        "7f085441070ecd2bb21285089ebb1aa6450d1a06c36d3ff39dfd657a796d12b5",
        "249712012029870a2459d18d47da9aa492a5e6cb4b2d8dafa9e4c5c54a2b9a8b",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 679 failed");
    // 676] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #112: special case hash
    let msg = hex_to_32("d59291cc2cf89f3087715fcb1aa4e79aa2403f748e97d7cd28ecaefeffffffff");
    let sig = build_sig(
        "914c67fb61dd1e27c867398ea7322d5ab76df04bc5aa6683a8e0f30a5d287348",
        "fa07474031481dda4953e3ac1959ee8cea7e66ec412b38d6c96d28f6d37304ea",
    );
    let pk = build_pk(
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 680 failed");
    // 677] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #113: k*G has a large x-coordinate
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "000000000000000000000000000000004319055358e8617b0c46353d039cdaab",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
    );
    let pk = build_pk(
        "d705d16f80987e2d9b1a6957d29ce22febf7d10fa515153182415c8361baaca4",
        "b1fc105ee5ce80d514ec1238beae2037a6f83625593620d460819e8682160926",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 681 failed");
    // 678] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #114: r too large
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
    );
    let pk = build_pk(
        "d705d16f80987e2d9b1a6957d29ce22febf7d10fa515153182415c8361baaca4",
        "b1fc105ee5ce80d514ec1238beae2037a6f83625593620d460819e8682160926",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 682 should fail");
    // 679] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #115: r,s are large
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
    );
    let pk = build_pk(
        "3cd8d2f81d6953b0844c09d7b560d527cd2ef67056893eadafa52c8501387d59",
        "ee41fdb4d10402ce7a0c5e3b747adfa3a490b62a6b7719068903485c0bb6dc2d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 683 failed");
    // 680] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #116: r and s^-1 have a large Hamming weight
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "909135bdb6799286170f5ead2de4f6511453fe50914f3df2de54a36383df8dd4",
    );
    let pk = build_pk(
        "8240cd81edd91cb6936133508c3915100e81f332c4545d41189b481196851378",
        "e05b06e72d4a1bff80ea5db514aa2f93ea6dd6d9c0ae27b7837dc432f9ce89d9",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 684 failed");
    // 681] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #117: r and s^-1 have a large Hamming weight
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "27b4577ca009376f71303fd5dd227dcef5deb773ad5f5a84360644669ca249a5",
    );
    let pk = build_pk(
        "b062947356748b0fc17f1704c65aa1dca6e1bfe6779756fa616d91eaad13df2c",
        "0b38c17f3d0672e7409cfc5992a99fff12b84a4f8432293b431113f1b2fb579d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 685 failed");
    // 682] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #118: small r and s
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000005",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "4a03ef9f92eb268cafa601072489a56380fa0dc43171d7712813b3a19a1eb5e5",
        "3e213e28a608ce9a2f4a17fd830c6654018a79b3e0263d91a8ba90622df6f2f0",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 686 failed");
    // 683] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #120: small r and s
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000005",
        "0000000000000000000000000000000000000000000000000000000000000003",
    );
    let pk = build_pk(
        "091194c1cba17f34e286b4833701606a41cef26177ada8850b601ea1f859e701",
        "27242fcec708828758403ce2fe501983a7984e6209f4d6b95db9ad77767f55eb",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 687 failed");
    // 684] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #122: small r and s
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000005",
        "0000000000000000000000000000000000000000000000000000000000000005",
    );
    let pk = build_pk(
        "103c6ecceff59e71ea8f56fee3a4b2b148e81c2bdbdd39c195812c96dcfb41a7",
        "2303a193dc591be150b883d770ec51ebb4ebce8b09042c2ecb16c448d8e57bf5",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 688 failed");
    // 685] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #124: small r and s
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000005",
        "0000000000000000000000000000000000000000000000000000000000000006",
    );
    let pk = build_pk(
        "3b66b829fe604638bcb2bfe8c22228be67390c20111bd2b451468927e87fb6ea",
        "bc8e59c009361758b274ba2cad36b58fde485a3ed09dade76712fa9e9c4ac212",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 689 failed");
    // 686] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #126: r is larger than n
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632556",
        "0000000000000000000000000000000000000000000000000000000000000006",
    );
    let pk = build_pk(
        "3b66b829fe604638bcb2bfe8c22228be67390c20111bd2b451468927e87fb6ea",
        "bc8e59c009361758b274ba2cad36b58fde485a3ed09dade76712fa9e9c4ac212",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 690 should fail");
    // 687] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #127: s is larger than n
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000005",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc75fbd8",
    );
    let pk = build_pk(
        "4ff2f6c24e4a33cd71c09fdcbc74a6233961b874b8c8e0eb94582092cbc50c30",
        "84fa9547afda5c66335f3f937d4c79afa120486b534139d59ae82d61ead26420",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 691 should fail");
    // 688] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #128: small r and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000100",
        "8f1e3c7862c58b16bb76eddbb76eddbb516af4f63f2d74d76e0d28c9bb75ea88",
    );
    let pk = build_pk(
        "84b959080bb30859cd53c2fb973cf14d60cdaa8ee00587889b5bc657ac588175",
        "a02ce5c1e53cb196113c78b4cb8dc7d360e5ea7850b0f6650b0c45af2c3cd7ca",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 692 failed");
    // 689] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #129: smallish r and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "000000000000000000000000000000000000000000000000002d9b4d347952d6",
        "ef3043e7329581dbb3974497710ab11505ee1c87ff907beebadd195a0ffe6d7a",
    );
    let pk = build_pk(
        "df4083bd6ecbda5a77ae578e5d835fa7f74a07ebb91e0570e1ff32a563354e99",
        "25af80b09a167d9ef647df28e2d9acd0d4bc4f2deec5723818edaf9071e311f8",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 693 failed");
    // 690] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #130: 100-bit r and small s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "000000000000000000000000000000000000001033e67e37b32b445580bf4eff",
        "8b748b74000000008b748b748b748b7466e769ad4a16d3dcd87129b8e91d1b4d",
    );
    let pk = build_pk(
        "c2569a3c9bf8c1838ca821f7ba6f000cc8679d278f3736b414a34a7c956a0377",
        "0387ea85bc4f28804b4a91c9b7d65bc6434c975806795ab7d441a4e9683aeb09",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 694 failed");
    // 691] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #131: small r and 100 bit s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000100",
        "ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
    );
    let pk = build_pk(
        "4a9f7da2a6c359a16540c271774a6bf1c586357c978256f44a6496d80670968a",
        "c496e73a44563f8d56fbd7bb9e4e3ae304c86f2c508eb777b03924755beb40d4",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 695 failed");
    // 692] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #132: 100-bit r and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "00000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c25",
        "ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
    );
    let pk = build_pk(
        "874146432b3cd2c9e26204c0a34136996067d466dde4917a8ff23a8e95ca106b",
        "709b3d50976ef8b385a813bc35f3a20710bdc6edd465e6f43ac4866703a6608c",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 696 failed");
    // 693] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #133: r and s^-1 are close to n
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6324d5",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "7a736d8e326a9ca62bbe25a34ea4e3633b499a96afa7aaa3fcf3fd88f8e07ede",
        "b3e45879d8622b93e818443a686e869eeda7bf9ae46aa3eafcc48a5934864627",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 697 failed");
    // 694] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #134: s == 1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let pk = build_pk(
        "e84d9b232e971a43382630f99725e423ec1ecb41e55172e9c69748a03f0d5988",
        "618b15b427ad83363bd041ff75fac98ef2ee923714e7d1dfe31753793c7588d4",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 698 failed");
    // 695] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #135: s == 0
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = build_pk(
        "e84d9b232e971a43382630f99725e423ec1ecb41e55172e9c69748a03f0d5988",
        "618b15b427ad83363bd041ff75fac98ef2ee923714e7d1dfe31753793c7588d4",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 699 should fail");
    // 696] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #136: point at infinity during verify
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "0203736fcb198b15d8d7a0c80f66dddd15259240aa78d08aae67c467de045034",
        "34383438d5041ea9a387ee8e4d4e84b4471b160c6bcf2568b072f8f20e87a996",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 700 should fail");
    // 697] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #137: edge case for signature malleability
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
    );
    let pk = build_pk(
        "78d844dc7f16b73b1f2a39730da5d8cd99fe2e70a18482384e37dcd2bfea02e1",
        "ed6572e01eb7a8d113d02c666c45ef22d3b9a6a6dea99aa43a8183c26e75d336",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 701 failed");
    // 698] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #138: edge case for signature malleability
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
    );
    let pk = build_pk(
        "dec6c8257dde94110eacc8c09d2e5789cc5beb81a958b02b4d62da9599a74014",
        "66fae1614174be63970b83f6524421067b06dd6f4e9c56baca4e344fdd690f1d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 702 failed");
    // 699] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #139: u1 == 1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
    );
    let pk = build_pk(
        "a17f5b75a35ed64623ca5cbf1f91951292db0c23f0c2ea24c3d0cad0988cabc0",
        "83a7a618625c228940730b4fa3ee64faecbb2fc20fdde7c58b3a3f6300424dc6",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 703 failed");
    // 700] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #140: u1 == n - 1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "acd155416a8b77f34089464733ff7cd39c400e9c69af7beb9eac5054ed2ec72c",
    );
    let pk = build_pk(
        "04ba0cba291a37db13f33bf90dab628c04ec8393a0200419e9eaa1ebcc9fb5c3",
        "1f3a0a0e6823a49b625ad57b12a32d4047970fc3428f0f0049ecf4265dc12f62",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 704 failed");
    // 701] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #141: u2 == 1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "692b6c828e0feed63d8aeaa2b7322f9ccbe8723a1ed39f229f204a434b8900ef",
        "a1f6f6abcb38ea3b8fde38b98c7c271f274af56a8c5628dc3329069ae4dd5716",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 705 failed");
    // 702] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #142: u2 == n - 1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
    );
    let pk = build_pk(
        "00cefd9162d13e64cb93687a9cd8f9755ebb5a3ef7632f800f84871874ccef09",
        "543ecbeaf7e8044ef721be2fb5f549e4b8480d2587404ebf7dbbef2c54bc0cb1",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 706 failed");
    // 703] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #143: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "710f8e3edc7c2d5a3fd23de844002bb949d9f794f6d5405f6d97c1bb03dd2bd2",
    );
    let pk = build_pk(
        "b975183b42551cf52f291d5c1921fd5e12f50c8c85a4beb9de03efa3f0f24486",
        "2243018e6866df922dc313612020311ff21e242ce3fb15bc78c406b25ab43091",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 707 failed");
    // 704] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #144: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "edffbc270f722c243069a7e5f40335a61a58525c7b4db2e7a8e269274ffe4e1b",
    );
    let pk = build_pk(
        "c25f1d166f3e211cdf042a26f8abf6094d48b8d17191d74ed717149274466999",
        "65d06dd6a88abfa49e8b4c5da6bb922851969adf9604b5accfb52a114e77ccdb",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 708 failed");
    // 705] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #145: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "a25adcae105ed7ff4f95d2344e24ee523314c3e178525d007904b68919ba4d53",
    );
    let pk = build_pk(
        "8fe5e88243a76e41a004236218a3c3a2d6eee398a23c3a0b008d7f0164cbc0ca",
        "98a20d1bdcf573513c7cfd9b83c63e3a82d40127c897697c86b8cb387af7f240",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 709 failed");
    // 706] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #146: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "2e4348c645707dce6760d773de3f3e87346924b2f64bd3dd0297e766b5805ebb",
    );
    let pk = build_pk(
        "02148256b530fbc470c7b341970b38243ecee6d5a840a37beca2efb37e8dff2c",
        "c0adbea0882482a7489ca703a399864ba987eeb6ddb738af53a83573473cb30d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 710 failed");
    // 707] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #147: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "348c673b07dce3920d773de3f3e87408869e916dbcf797d8f9684fb67753d1dc",
    );
    let pk = build_pk(
        "a34db012ce6eda1e9c7375c5fcf3e54ed698e19615124273b3a621d021c76f8e",
        "777458d6f55a364c221e39e1205d5510bb4fbb7ddf08d8d8fdde13d1d6df7f14",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 711 failed");
    // 708] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #148: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "6918ce760fb9c7241aee7bc7e7d0e8110d3d22db79ef2fb1f2d09f6ceea7a3b8",
    );
    let pk = build_pk(
        "b97af3fe78be15f2912b6271dd8a43badb6dd2a1b315b2ce7ae37b4e7778041d",
        "930d71ee1992d2466495c42102d08e81154c305307d1dcd52d0fa4c479b278e7",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 712 failed");
    // 709] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #149: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "73b3c694391d8eadde3f3e874089464715ac20e4c126bbf6d864d648969f5b5a",
    );
    let pk = build_pk(
        "81e7198a3c3f23901cedc7a1d6eff6e9bf81108e6c35cd8559139af3135dbcbb",
        "9ef1568530291a8061b90c9f4285eefcba990d4570a4e3b7b737525b5d580034",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 713 failed");
    // 710] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #150: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bb07ac7a86948c2c2989a16db1930ef1b89ce112595197656877e53c41457f28",
    );
    let pk = build_pk(
        "ab4d792ca121d1dba39cb9de645149c2ab573e8becc6ddff3cc9960f188ddf73",
        "7f90ba23664153e93262ff73355415195858d7be1315a69456386de68285a3c8",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 714 failed");
    // 711] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #151: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "27e4d82cb6c061dd9337c69bf9332ed3d198662d6f2299443f62c861187db648",
    );
    let pk = build_pk(
        "518412b69af43aae084476a68d59bbde51fbfa9e5be80563f587c9c2652f88ef",
        "2d3b90d25baa6bdb7b0c55e5240a3a98fbc24afed8523edec1c70503fc10f233",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 715 failed");
    // 712] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #152: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "e7c5cf3aac2e88923b77850515fff6a12d13b356dfe9ec275c3dd81ae94609a4",
    );
    let pk = build_pk(
        "a08f14a644b9a935dffea4761ebaf592d1f66fe6cd373aa7f5d370af34f8352d",
        "a54b5bc4025cf335900a914c2934ec2fec7a396d0a7affcad732a5741c7aaaf5",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 716 failed");
    // 713] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #153: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "c77838df91c1e953e016e10bddffea2317f9fee32bacfe553cede9e57a748f68",
    );
    let pk = build_pk(
        "ccf2296a6a89b62b90739d38af4ae3a20e9f45715b90044639241061e33f8f8c",
        "aace0046491eeaa1c6e9a472b96d88f4af83e7ff1bb84438c7e058034412ae08",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 717 failed");
    // 714] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #154: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "8ef071c02383d2a6c02dc217bbffd446730d0318b0425e2586220907f885f97f",
    );
    let pk = build_pk(
        "94b0fc1525bcabf82b1f34895e5819a06c02b23e04002276e165f962c86e3927",
        "be7c2ab4d0b25303204fb32a1f8292902792225e16a6d2dbfb29fbc89a9c3376",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 718 failed");
    // 715] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #155: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "5668aaa0b545bbf9a044a32399ffbe69ce20074e34d7bdf5cf56282a76976396",
    );
    let pk = build_pk(
        "5351f37e1de0c88c508527d89882d183ccdcf2efca407edb0627cadfd16de6ec",
        "44b4b57cdf960d32ebcc4c97847eed218425853b5b675eb781b766a1a1300349",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 719 failed");
    // 716] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #156: edge case for u1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "d12d6e56882f6c0027cae91a27127728f7fddf478fb4fdc2b65f40a60b0eb952",
    );
    let pk = build_pk(
        "748bbafc320e6735cb64019710a269c6c2b5d147bdc831325cb2fb276ac971a6",
        "9d655e9a755bc9d800ad21ee3fd4d980d93a7a49a8c5ccd37005177578f51163",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 720 failed");
    // 717] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #157: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "7fffffffaaaaaaaaffffffffffffffffe9a2538f37b28a2c513dee40fecbb71a",
    );
    let pk = build_pk(
        "14b3bbd75c5e1c0c36535a934d4ab85112410b3b90fa97a31c33038964fd85cc",
        "112f7d837f8f9c36b460d636c965a5f818f2b50c5d00fb3f9705561dd6631883",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 721 failed");
    // 718] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #158: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "b62f26b5f2a2b26f6de86d42ad8a13da3ab3cccd0459b201de009e526adf21f2",
    );
    let pk = build_pk(
        "d823533c04cd8edc6d6f950a8e08ade04a9bafa2f14a590356935671ae9305bf",
        "43178d1f88b6a57a96924c265f0ddb75b58312907b195acb59d7797303123775",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 722 failed");
    // 719] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #159: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bb1d9ac949dd748cd02bbbe749bd351cd57b38bb61403d700686aa7b4c90851e",
    );
    let pk = build_pk(
        "db2b3408b3167d91030624c6328e8ce3ec108c105575c2f3d209b92e654bab69",
        "c34318139c50b0802c6e612f0fd3189d800df7c996d5d7b7c3d6be82836fa258",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 723 failed");
    // 720] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #160: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "66755a00638cdaec1c732513ca0234ece52545dac11f816e818f725b4f60aaf2",
    );
    let pk = build_pk(
        "09179ce7c59225392216453b2ac1e9d178c24837dfae26bc1dd7ab6063852742",
        "5556b42e330289f3b826b2db7a86d19d45c2860a59f2be1ddcc3b691f95a9255",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 724 failed");
    // 721] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #161: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "55a00c9fcdaebb6032513ca0234ecfffe98ebe492fdf02e48ca48e982beb3669",
    );
    let pk = build_pk(
        "01959fb8deda56e5467b7e4b214ea4c2d0c2fb29d70ff19b6b1eccebd6568d7e",
        "d9dbd77a918297fd970bff01e1343f6925167db5a14d098a211c39cc3a413398",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 725 failed");
    // 722] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #162: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "ab40193f9b5d76c064a27940469d9fffd31d7c925fbe05c919491d3057d66cd2",
    );
    let pk = build_pk(
        "567f1fdc387e5350c852b4e8f8ba9d6d947e1c5dd7ccc61a5938245dd6bcab3a",
        "9960bebaf919514f9535c22eaaf0b5812857970e26662267b1f3eb1011130a11",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 726 failed");
    // 723] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #163: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "ca0234ebb5fdcb13ca0234ecffffffffcb0dadbbc7f549f8a26b4408d0dc8600",
    );
    let pk = build_pk(
        "3499f974ff4ca6bbb2f51682fd5f51762f9dd6dd2855262660b36d46d3e4bec2",
        "f498fae2487807e220119152f0122476c64d4fa46ddce85c4546630f0d5c5e81",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 727 failed");
    // 724] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #164: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff3ea3677e082b9310572620ae19933a9e65b285598711c77298815ad3",
    );
    let pk = build_pk(
        "2c5c01662cf00c1929596257db13b26ecf30d0f3ec4b9f0351b0f27094473426",
        "e986a086060d086eee822ddd2fc744247a0154b57f7a69c51d9fdafa484e4ac7",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 728 failed");
    // 725] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #165: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "266666663bbbbbbbe6666666666666665b37902e023fab7c8f055d86e5cc41f4",
    );
    let pk = build_pk(
        "91d4cba813a04d86dbae94c23be6f52c15774183be7ba5b2d9f3cf010b160501",
        "900b8adfea6491019a9ac080d516025a541bf4b952b0ad7be4b1874b02fd544a",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 729 failed");
    // 726] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #166: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff36db6db7a492492492492492146c573f4c6dfc8d08a443e258970b09",
    );
    let pk = build_pk(
        "ef7fd0a3a36386638330ecad41e1a3b302af36960831d0210c614b948e8aa124",
        "ef0d6d800e4047d6d3c1be0fdeaf11fcd8cab5ab59c730eb34116e35a8c7d098",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 730 failed");
    // 727] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #167: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "bfffffff2aaaaaab7fffffffffffffffc815d0e60b3e596ecb1ad3a27cfd49c4",
    );
    let pk = build_pk(
        "a521dab13cc9152d8ca77035a607fea06c55cc3ca5dbeb868cea92eafe93df2a",
        "7bfb9b28531996635e6a5ccaa2826a406ce1111bdb9c2e0ca36500418a2f43de",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 731 failed");
    // 728] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #168: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "7fffffff55555555ffffffffffffffffd344a71e6f651458a27bdc81fd976e37",
    );
    let pk = build_pk(
        "474d58a4eec16e0d565f2187fe11d4e8e7a2683a12f38b4fc01d1237a81a1097",
        "6e55f73bb7cdda46bdb67ef77f6fd2969df2b67920fb5945fde3a517a6ded4cd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 732 failed");
    // 729] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #169: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "3fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192aa",
    );
    let pk = build_pk(
        "692da5cd4309d9a6e5cb525c37da8fa0879f7b57208cdabbf47d223a5b23a621",
        "40e0daa78cfdd207a7389aaed61738b17fc5fc3e6a5ed3397d2902e9125e6ab4",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 733 failed");
    // 730] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #170: edge case for u2
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        "5d8ecd64a4eeba466815ddf3a4de9a8e6abd9c5db0a01eb80343553da648428f",
    );
    let pk = build_pk(
        "85689b3e0775c7718a90279f14a8082cfcd4d1f1679274f4e9b8805c570a0670",
        "167fcc5ca734552e09afa3640f4a034e15b9b7ca661ec7ff70d3f240ebe705b1",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 734 failed");
    // 731] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #171: point duplication during verification
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569",
        "f21d907e3890916dc4fa1f4703c1e50d3f54ddf7383e44023a41de562aa18ed8",
    );
    let pk = build_pk(
        "0158137755b901f797a90d4ca8887e023cb2ef63b2ba2c0d455edaef42cf237e",
        "2a964fc00d377a8592b8b61aafa7a4aaa7c7b9fd2b41d6e0e17bd1ba5677edcd",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 735 failed");
    // 732] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #172: duplication bug
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569",
        "f21d907e3890916dc4fa1f4703c1e50d3f54ddf7383e44023a41de562aa18ed8",
    );
    let pk = build_pk(
        "0158137755b901f797a90d4ca8887e023cb2ef63b2ba2c0d455edaef42cf237e",
        "d569b03ef2c8857b6d4749e550585b5558384603d4be291f1e842e45a9881232",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 736 should fail");
    // 733] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #173: point with x-coordinate 0
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "38a084ffccc4ae2f8204be2abca9fb8ad4ab283b2aa50f13b6bb2347adabc69c",
        "a699799b77b1cc6dad271e88b899c12931986e958e1f5cf5653dddf7389365e2",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 737 should fail");
    // 734] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #175: comparison with point at infinity
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aa9",
    );
    let pk = build_pk(
        "664ce273320d918d8bdb2e61201b4549b36b7cdc54e33b84adb6f2c10aac831e",
        "49e68831f18bda2973ac3d76bfbc8c5ee1cceed2dd862e2dc7c915c736cef1f4",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 738 should fail");
    // 735] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #176: extreme value for k and edgecase s
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "961691a5e960d07a301dbbad4d86247ec27d7089faeb3ddd1add395efff1e0fe",
        "7254622cc371866cdf990d2c5377790e37d1f1519817f09a231bd260a9e78aeb",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 739 failed");
    // 736] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #177: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
    );
    let pk = build_pk(
        "5d283e13ce8ca60da868e3b0fb33e6b4f1074793274e2928250e71e2aca63e9c",
        "214dc74fa25371fb4d9e506d418ed9a1bfd6d0c8bb6591d3e0f44505a84886ce",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 740 failed");
    // 737] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #178: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
    );
    let pk = build_pk(
        "0fc351da038ae0803bd1d86514ae0462f9f8216551d9315aa9d297f792eef6a3",
        "41c74eed786f2d33da35360ca7aa925e753f00d6077a1e9e5fc339d634019c73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 741 failed");
    // 738] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #179: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
    );
    let pk = build_pk(
        "a1e34c8f16d138673fee55c080547c2bfd4de7550065f638322bba9430ce4b60",
        "662be9bb512663aa4d7df8ab3f3b4181c5d44a7bdf42436620b7d8a6b81ac936",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 742 failed");
    // 739] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #180: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "49249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
    );
    let pk = build_pk(
        "7e1a8a8338d7fd8cf41d322a302d2078a87a23c7186150ed7cda6e52817c1bdf",
        "d0a9135a89d21ce821e29014b2898349254d748272b2d4eb8d59ee34c615377f",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 743 failed");
    // 740] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #181: extreme value for k
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "16a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
    );
    let pk = build_pk(
        "5c19fe227a61abc65c61ee7a018cc9571b2c6f663ea33583f76a686f64be078b",
        "7b4a0d734940f613d52bc48673b457c2cf78492490a5cc5606c0541d17b24ddb",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 744 failed");
    // 741] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #182: extreme value for k and edgecase s
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
    );
    let pk = build_pk(
        "db02d1f3421d600e9d9ef9e47419dba3208eed08c2d4189a5db63abeb2739666",
        "e0ed26967b9ada9ed7ffe480827f90a0d210d5fd8ec628e31715e6b24125512a",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 745 failed");
    // 742] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #183: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
    );
    let pk = build_pk(
        "6222d1962655501893c29e441395b6c05711bd3ed5a0ef72cfab338b88229c4b",
        "aaae079cb44a1af070362aaa520ee24cac2626423b0bf81af1c54311d8e2fd23",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 746 failed");
    // 743] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #184: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
    );
    let pk = build_pk(
        "4ccfa24c67f3def7fa81bc99c70bb0419c0952ba599f4c03361da184b04cdca5",
        "db76b797f7f41d9c729a2219478a7e629728df870800be8cf6ca7a0a82153bfa",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 747 failed");
    // 744] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #185: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
    );
    let pk = build_pk(
        "ea1c72c91034036bac71402b6e9ecc4af3dbde7a99dc574061e99fefff9d84da",
        "b7dd057e75b78ac6f56e34eb048f0a9d29d5d055408c90d02bc2ea918c18cb63",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 748 failed");
    // 745] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #186: extreme value for k and s^-1
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "49249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
    );
    let pk = build_pk(
        "c2879a66d86cb20b820b7795da2da62b38924f7817d1cd350d936988e90e79bc",
        "5431a7268ff6931c7a759de024eff90bcb0177216db6fd1f3aaaa11fa3b6a083",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 749 failed");
    // 746] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #187: extreme value for k
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "16a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
    );
    let pk = build_pk(
        "ab1c0f273f74abc2b848c75006f2ef3c54c26df27711b06558f455079aee0ba3",
        "df510f2ecef6d9a05997c776f14ad6456c179f0a13af1771e4d6c37fa48b47f2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 750 failed");
    // 747] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #188: testing point duplication
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 751 should fail");
    // 748] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #189: testing point duplication
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "acd155416a8b77f34089464733ff7cd39c400e9c69af7beb9eac5054ed2ec72c",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 752 should fail");
    // 749] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #190: testing point duplication
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 753 should fail");
    // 750] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #191: testing point duplication
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "acd155416a8b77f34089464733ff7cd39c400e9c69af7beb9eac5054ed2ec72c",
        "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
    );
    let pk = build_pk(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 754 should fail");
    // 751] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #269: pseudorandom signature
    let msg = hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
    let sig = build_sig(
        "a8ea150cb80125d7381c4c1f1da8e9de2711f9917060406a73d7904519e51388",
        "f3ab9fa68bd47973a73b2d40480c2ba50c22c9d76ec217257288293285449b86",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 755 failed");
    // 752] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #270: pseudorandom signature
    let msg = hex_to_32("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
    let sig = build_sig(
        "30e782f964b2e2ff065a051bc7adc20615d8c43a1365713c88268822c253bcce",
        "5b16df652aa1ecb2dc8b46c515f9604e2e84cacfa7c6eec30428d2d3f4e08ed5",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 756 failed");
    // 753] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #271: pseudorandom signature
    let msg = hex_to_32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    let sig = build_sig(
        "b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a",
        "0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 757 failed");
    // 754] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #272: pseudorandom signature
    let msg = hex_to_32("de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90");
    let sig = build_sig(
        "986e65933ef2ed4ee5aada139f52b70539aaf63f00a91f29c69178490d57fb71",
        "3dafedfb8da6189d372308cbf1489bbbdabf0c0217d1c0ff0f701aaa7a694b9c",
    );
    let pk = build_pk(
        "04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5",
        "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 758 failed");
    // 755] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #288: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d434e262a49eab7781e353a3565e482550dd0fd5defa013c7f29745eff3569f1",
        "9b0c0a93f267fb6052fd8077be769c2b98953195d7bc10de844218305c6ba17a",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 759 failed");
    // 756] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #289: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "0fe774355c04d060f76d79fd7a772e421463489221bf0a33add0be9b1979110b",
        "500dcba1c69a8fbd43fa4f57f743ce124ca8b91a1f325f3fac6181175df55737",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 760 failed");
    // 757] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #290: x-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "bb40bf217bed3fb3950c7d39f03d36dc8e3b2cd79693f125bfd06595ee1135e3",
        "541bf3532351ebb032710bdb6a1bf1bfc89a1e291ac692b3fa4780745bb55677",
    );
    let pk = build_pk(
        "4f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000",
        "ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 761 failed");
    // 758] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #291: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "664eb7ee6db84a34df3c86ea31389a5405badd5ca99231ff556d3e75a233e73a",
        "59f3c752e52eca46137642490a51560ce0badc678754b8f72e51a2901426a1bd",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 762 failed");
    // 759] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #292: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "4cd0429bbabd2827009d6fcd843d4ce39c3e42e2d1631fd001985a79d1fd8b43",
        "9638bf12dd682f60be7ef1d0e0d98f08b7bca77a1a2b869ae466189d2acdabe3",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 763 failed");
    // 760] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #293: y-coordinate of the public key has many trailing 0's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "e56c6ea2d1b017091c44d8b6cb62b9f460e3ce9aed5e5fd41e8added97c56c04",
        "a308ec31f281e955be20b457e463440b4fcf2b80258078207fc1378180f89b55",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "84fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 764 failed");
    // 761] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #294: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "1158a08d291500b4cabed3346d891eee57c176356a2624fb011f8fbbf3466830",
        "228a8c486a736006e082325b85290c5bc91f378b75d487dda46798c18f285519",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 765 failed");
    // 762] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #295: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b1db9289649f59410ea36b0c0fc8d6aa2687b29176939dd23e0dde56d309fa9d",
        "3e1535e4280559015b0dbd987366dcf43a6d1af5c23c7d584e1c3f48a1251336",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 766 failed");
    // 763] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #296: y-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b7b16e762286cb96446aa8d4e6e7578b0a341a79f2dd1a220ac6f0ca4e24ed86",
        "ddc60a700a139b04661c547d07bbb0721780146df799ccf55e55234ecb8f12bc",
    );
    let pk = build_pk(
        "3cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f497265004935",
        "7b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 767 failed");
    // 764] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #297: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d82a7c2717261187c8e00d8df963ff35d796edad36bc6e6bd1c91c670d9105b4",
        "3dcabddaf8fcaa61f4603e7cbac0f3c0351ecd5988efb23f680d07debd139929",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 768 failed");
    // 765] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #298: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "5eb9c8845de68eb13d5befe719f462d77787802baff30ce96a5cba063254af78",
        "2c026ae9be2e2a5e7ca0ff9bbd92fb6e44972186228ee9a62b87ddbe2ef66fb5",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 769 failed");
    // 766] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #299: x-coordinate of the public key has many trailing 1's
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "96843dd03c22abd2f3b782b170239f90f277921becc117d0404a8e4e36230c28",
        "f2be378f526f74a543f67165976de9ed9a31214eb4d7e6db19e1ede123dd991d",
    );
    let pk = build_pk(
        "2829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffff",
        "a01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 770 failed");
    // 767] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #300: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "766456dce1857c906f9996af729339464d27e9d98edc2d0e3b760297067421f6",
        "402385ecadae0d8081dccaf5d19037ec4e55376eced699e93646bfbbf19d0b41",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 771 failed");
    // 768] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #301: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "c605c4b2edeab20419e6518a11b2dbc2b97ed8b07cced0b19c34f777de7b9fd9",
        "edf0f612c5f46e03c719647bc8af1b29b2cde2eda700fb1cff5e159d47326dba",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 772 failed");
    // 769] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #302: x-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d48b68e6cabfe03cf6141c9ac54141f210e64485d9929ad7b732bfe3b7eb8a84",
        "feedae50c61bd00e19dc26f9b7e2265e4508c389109ad2f208f0772315b6c941",
    );
    let pk = build_pk(
        "fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f5",
        "5a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 773 failed");
    // 770] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #303: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "b7c81457d4aeb6aa65957098569f0479710ad7f6595d5874c35a93d12a5dd4c7",
        "b7961a0b652878c2d568069a432ca18a1a9199f2ca574dad4b9e3a05c0a1cdb3",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 774 failed");
    // 771] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #304: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "6b01332ddb6edfa9a30a1321d5858e1ee3cf97e263e669f8de5e9652e76ff3f7",
        "5939545fced457309a6a04ace2bd0f70139c8f7d86b02cb1cc58f9e69e96cd5a",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 775 failed");
    // 772] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #305: x-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "efdb884720eaeadc349f9fc356b6c0344101cd2fd8436b7d0e6a4fb93f106361",
        "f24bee6ad5dc05f7613975473aadf3aacba9e77de7d69b6ce48cb60d8113385d",
    );
    let pk = build_pk(
        "00000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e",
        "1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 776 failed");
    // 773] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #306: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "31230428405560dcb88fb5a646836aea9b23a23dd973dcbe8014c87b8b20eb07",
        "0f9344d6e812ce166646747694a41b0aaf97374e19f3c5fb8bd7ae3d9bd0beff",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 777 failed");
    // 774] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #307: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "caa797da65b320ab0d5c470cda0b36b294359c7db9841d679174db34c4855743",
        "cf543a62f23e212745391aaf7505f345123d2685ee3b941d3de6d9b36242e5a0",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 778 failed");
    // 775] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #308: y-coordinate of the public key is small
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "7e5f0ab5d900d3d3d7867657e5d6d36519bc54084536e7d21c336ed800185945",
        "9450c07f201faec94b82dfb322e5ac676688294aad35aa72e727ff0b19b646aa",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 779 failed");
    // 776] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #309: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "d7d70c581ae9e3f66dc6a480bf037ae23f8a1e4a2136fe4b03aa69f0ca25b356",
        "89c460f8a5a5c2bbba962c8a3ee833a413e85658e62a59e2af41d9127cc47224",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 780 failed");
    // 777] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #310: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "341c1b9ff3c83dd5e0dfa0bf68bcdf4bb7aa20c625975e5eeee34bb396266b34",
        "72b69f061b750fd5121b22b11366fad549c634e77765a017902a67099e0a4469",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 781 failed");
    // 778] wycheproof/ecdsa_webcrypto_test.json EcdsaP1363Verify SHA-256 #311: y-coordinate of the public key is large
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67",
        "aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 782 failed");
    // 779] invalid public key x param errors
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67",
        "aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
    );
    let pk = build_pk(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 783 should fail");
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67",
        "aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
    );
    let pk = build_pk(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 784 should fail");
    // 780] invalid public key y param errors
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67",
        "aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 785 should fail");
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67",
        "aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
    );
    let pk = build_pk(
        "bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 786 should fail");
    // 781] reference point errors
    let msg = hex_to_32("2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91");
    let sig = build_sig(
        "70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67",
        "aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
    );
    let pk = build_pk(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), "Test 787 should fail");
    // Test 788: incomplete data
}
