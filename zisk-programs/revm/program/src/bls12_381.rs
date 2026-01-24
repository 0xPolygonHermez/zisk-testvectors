use crypto::CustomEvmCrypto;
use revm::precompile::Crypto;

pub fn bls12_381_tests(crypto: &CustomEvmCrypto) {
    kzg_verify_tests(crypto);
    g1_add_tests(crypto);
    g1_mul_tests(crypto); // Use MSM
    g1_msm_tests(crypto);
    g2_add_tests(crypto);
    g2_mul_tests(crypto); // Use MSM
    g2_msm_tests(crypto);
    pairing_check_tests(crypto);
    // TODO!
    // fp_to_g1_tests(crypto);
    // fp2_to_g2_tests(crypto);
}

fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex).expect("valid hex");
    let mut arr = [0u8; N];
    // Handle case where hex string may have leading zeros stripped
    let start = N.saturating_sub(bytes.len());
    arr[start..].copy_from_slice(&bytes);
    arr
}

/// Build KZG commitment (48 bytes) from low (32 bytes) and high (16 bytes) parts
/// The commitment is: high (16 bytes) || low (32 bytes) = 48 bytes total
fn build_commitment(low: &str, high: &str) -> [u8; 48] {
    let low_bytes: [u8; 32] = hex_to_bytes(low);
    let high_bytes: [u8; 16] = hex_to_bytes(high);

    let mut commitment = [0u8; 48];
    commitment[..16].copy_from_slice(&high_bytes);
    commitment[16..].copy_from_slice(&low_bytes);
    commitment
}

/// Build KZG proof (48 bytes) from low (32 bytes) and high (16 bytes) parts
fn build_proof(low: &str, high: &str) -> [u8; 48] {
    build_commitment(low, high) // Same format as commitment
}

fn kzg_verify_tests(crypto: &CustomEvmCrypto) {
    kzg_verify_tests_basic(crypto);

    // Test cases from https://github.com/crate-crypto/go-kzg-4844/tree/master/tests/verify_kzg_proof/kzg-mainnet
    kzg_verify_tests_correct(crypto);
    kzg_verify_tests_incorrect(crypto);
    kzg_verify_tests_invalid(crypto);
    println!("All KZG Verify tests passed!");
}

fn kzg_verify_tests_basic(crypto: &CustomEvmCrypto) {
    // Test 1: Proof is not correct - should fail verification
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );

    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "Test 1: Incorrect proof should fail verification");

    // Test 2: Commitment has invalid serialization - should fail
    let commitment = build_commitment(
        "0x0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6",
        "0x97f1d3a73197d7942695638c4fa9ac", // Note: shorter high part
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    let proof = build_proof(
        "0xf7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f",
        "0xb0c829a8d2d3405304fecbea193e6c67",
    );

    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "Test 2: Invalid commitment serialization should fail");

    // Test 3: Edge case - [y] = 0 and proof = 𝒪 (point at infinity)
    // This is trivially satisfied as long as [z]₂ is a curve element
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );

    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "Test 3: Edge case with point at infinity should pass");

    // Test 4: Standard test case 1
    let commitment = build_commitment(
        "0x27d54c976157cb64d0a7087329a115f6ccf8d94a5f3a1af6b6c744ffc2b1eca9",
        "0xa1aa6c0a85beb947df00587918144c82",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x4124347a6f69eed4bf5eae100bf955d5f54d1ea6a0d12c4993cdf46d71e3f6e1");
    let y: [u8; 32] =
        hex_to_bytes("0x1c6627da2f0d65e53ee1abd701ca7651be8fa5c89f6130af9bdf06fee6f0133b");
    let proof = build_proof(
        "0xe0905b77094efe5a5ee7bbbe6a306a0fab2796adedbeed5a80e94be7edc85391",
        "0xb07fece886f5ed974445971028e184c7",
    );

    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "Test 4: Standard test case 1 should pass");

    // Test 5: Standard test case 2
    let commitment = build_commitment(
        "0x787bfcb37bf03d23741eaa351c8dd79d30fd2084ba5b50f31c8d9d7ea5b132cf",
        "0xa621f969ffcf63b944d27acc57aaee96",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x13594569a0b1bd6467f11a346d8c7c5a175d3bc7d2bf2dc7789653f170c71f8f");
    let y: [u8; 32] =
        hex_to_bytes("0x61588b03541afc34b0eb0d370b69251dd4b92b3d46160ea7bf849f7fd76aab75");
    let proof = build_proof(
        "0x086b73e626eff578ee686c30d58cf5c990b014869a57053fb3cd77354b411e55",
        "0x930d5e1b4f053e7a633d8346a46d624b",
    );

    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "Test 5: Standard test case 2 should pass");

    // Test 6: Standard test case 3
    let commitment = build_commitment(
        "0x9681f5651de744fb1821f8549c78985dfe8e857456e8077fb212e7dbf4659919",
        "0x91929026d7362c49c0728370697906f5",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x2bc11ee1fd56fb16c9613ea547eddf16c98c2ebc585d20e9c41b41a7af88cf85");
    let y: [u8; 32] =
        hex_to_bytes("0x3b54289a2f14cfca051407c6c8c665f1fabed0b60dac273230d18d73bf42aa97");
    let proof = build_proof(
        "0x3ec0baeb5881545920addafa02f0952eb50cdce2937658480d5c3cde0f967325",
        "0x89eed617c24d8a8006b2e58884a93deb",
    );

    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "Test 6: Standard test case 3 should pass");
}

// =========================================================================
// Correct tests - should all pass verification
// =========================================================================
fn kzg_verify_tests_correct(crypto: &CustomEvmCrypto) {
    // verify_kzg_proof_case_correct_proof_02e696ada7d4631d
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_02e696ada7d4631d should pass");

    // verify_kzg_proof_case_correct_proof_05c1f3685f3393f0
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_05c1f3685f3393f0 should pass");

    // verify_kzg_proof_case_correct_proof_08f9e2f1cb3d39db
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_08f9e2f1cb3d39db should pass");

    // verify_kzg_proof_case_correct_proof_0cf79b17cb5f4ea2
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_0cf79b17cb5f4ea2 should pass");

    // verify_kzg_proof_case_correct_proof_177b58dc7a46b08f
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_177b58dc7a46b08f should pass");

    // verify_kzg_proof_case_correct_proof_1ce8e4f69d5df899
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x4b7ba36a0f40e2dc086bc4061c7f63249877db23297212991fd63e07b7ebc348",
        "0x92c51ff81dd71dab71cefecd79e8274b",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_1ce8e4f69d5df899 should pass");

    // verify_kzg_proof_case_correct_proof_26b753dec0560daa
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x73e66878b46ae3705eb6a46a89213de7d3686828bfce5c19400fffff00100001");
    let proof = build_proof(
        "0xf06d936551667c82f659b75f99d2da2068b81340823ee4e829a93c9fbed7810d",
        "0xb82ded761997f2c6f1bb3db1e1dada2e",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_26b753dec0560daa should pass");

    // verify_kzg_proof_case_correct_proof_2b76dc9e3abf42f3
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_2b76dc9e3abf42f3 should pass");

    // verify_kzg_proof_case_correct_proof_31ebd010e6098750
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9");
    let proof = build_proof(
        "0x75bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c",
        "0xa62ad71d14c5719385c0686f18714304",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_31ebd010e6098750 should pass");

    // verify_kzg_proof_case_correct_proof_3208425794224c3f
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_3208425794224c3f should pass");

    // verify_kzg_proof_case_correct_proof_36817bfd67de97a8
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_36817bfd67de97a8 should pass");

    // verify_kzg_proof_case_correct_proof_392169c16a2e5ef6
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x304962b3598a0adf33189fdfd9789feab1096ff40006900400000003fffffffc");
    let proof = build_proof(
        "0x499561f482419a3a372c42a636dad98262a2ce926d142fd7cfe26ca148efe8b4",
        "0xaa86c458b3065e7ec244033a2ade91a7",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_392169c16a2e5ef6 should pass");

    // verify_kzg_proof_case_correct_proof_395cf6d697d1a743
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_395cf6d697d1a743 should pass");

    // verify_kzg_proof_case_correct_proof_3ac8dc31e9aa6a70
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_3ac8dc31e9aa6a70 should pass");

    // verify_kzg_proof_case_correct_proof_3c1e8b38219e3e12
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x50625ad853cc21ba40594f79591e5d35c445ecf9453014da6524c0cf6367c359");
    let proof = build_proof(
        "0x8876b2b207f1d5e54dd62a14e3242d123b5a6db066181ff01a51c26c9d2f400b",
        "0xb72d80393dc39beea3857cb371927713",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_3c1e8b38219e3e12 should pass");

    // verify_kzg_proof_case_correct_proof_3c87ec986c2656c2
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x6d928e13fe443e957d82e3e71d48cb65d51028eb4483e719bf8efcdf12f7c321");
    let proof = build_proof(
        "0xbfe529f59247987cd1ab848d19de599a9052f1835fb0d0d44cf70183e19a68c9",
        "0xa444d6bb5aadc3ceb615b50d6606bd54",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_3c87ec986c2656c2 should pass");

    // verify_kzg_proof_case_correct_proof_3cd183d0bab85fb7
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_3cd183d0bab85fb7 should pass");

    // verify_kzg_proof_case_correct_proof_420f2a187ce77035
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x2bf4e1f980eb94661a21affc4d7e6e56f214fe3e7dc4d20b98c66ffd43cabeb0");
    let proof = build_proof(
        "0x444b83f54df1f5f274fb4312800a6505dd000ee8ec7b0ea6d72092a3daf0bffb",
        "0x89012990b0ca02775bd9df8145f6c936",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_420f2a187ce77035 should pass");

    // verify_kzg_proof_case_correct_proof_444b73ff54a19b44
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x443e7af5274b52214ea6c775908c54519fea957eecd98069165a8b771082fd51");
    let proof = build_proof(
        "0xcaf781080222e0209b4a0b074decca874afc5c41de3313d8ed217d905e6ada43",
        "0xa060b350ad63d61979b80b25258e7cc6",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_444b73ff54a19b44 should pass");

    // verify_kzg_proof_case_correct_proof_53a9bdf4f75196da
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_53a9bdf4f75196da should pass");

    // verify_kzg_proof_case_correct_proof_585454b31673dd62
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_585454b31673dd62 should pass");

    // verify_kzg_proof_case_correct_proof_7db4f140a955dd1a
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x58cdc98c4c44791bb8ba7e58a80324ef8c021c79c68e253c430fa2663188f7f2");
    let proof = build_proof(
        "0x8596854bac66b9cb2d6d361704f1735442d47ea09fda5e0984f0928ce7d2f5f6",
        "0x9506a8dc7f3f720a592a79a4e711e28d",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_7db4f140a955dd1a should pass");

    // verify_kzg_proof_case_correct_proof_83e53423a2dd93fe
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    let proof = build_proof(
        "0xf7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f",
        "0xb0c829a8d2d3405304fecbea193e6c67",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_83e53423a2dd93fe should pass");

    // verify_kzg_proof_case_correct_proof_9b24f8997145435c
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x2a6e3d47f96c0257bce642b70e8e375839a880864638669c6a709b414ab8bffc",
        "0xb9241c6816af6388d1014cd4d7dd2166",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_9b24f8997145435c should pass");

    // verify_kzg_proof_case_correct_proof_9b754afb690c47e1
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_9b754afb690c47e1 should pass");

    // verify_kzg_proof_case_correct_proof_a0be66af9a97ea52
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_a0be66af9a97ea52 should pass");

    // verify_kzg_proof_case_correct_proof_af669445747d2585
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x6c28d6edfea2f5e1638cb1a8be8197549d52e133fa9dae87e52abb45f7b192dd");
    let proof = build_proof(
        "0xc24e21d42b1df2bfe1c8e28431c6221a3f1d09808042f5624e857710cb24fb69",
        "0x8a46b67dcba4e3aa66f9952be69e1ecb",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_af669445747d2585 should pass");

    // verify_kzg_proof_case_correct_proof_af8b75f664ed7d43
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x64d3b6baf69395bde2abd1d43f99be66bc64581234fd363e2ae3a0d419cfc3fc");
    let proof = build_proof(
        "0x588f2c61031781367cfea2a2be4ef3090035623338711b3cf7eff4b4524df742",
        "0x893acd46552b81cc9e5ff6ca03dad873",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_af8b75f664ed7d43 should pass");

    // verify_kzg_proof_case_correct_proof_b6cb6698327d9835
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x6a75e4fe63e5e148c853462a680c3e3ccedea34719d28f19bf1b35ae4eea37d6");
    let proof = build_proof(
        "0x340c809baa0e1fed9deaabb11aa503062acbbe23fcbe620a21b40a83bfa71b89",
        "0xa38758fca85407078c0a7e5fd6d38b34",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_b6cb6698327d9835 should pass");

    // verify_kzg_proof_case_correct_proof_b6ec3736f9ff2c62
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0xc85b01076423a92c3335b93d10bf2fcb99b943a53adc1ab8feb6b475c4688948",
        "0xa256a681861974cdf6b116467044aa75",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_b6ec3736f9ff2c62 should pass");

    // verify_kzg_proof_case_correct_proof_becf2e1641bbd4e6
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_becf2e1641bbd4e6 should pass");

    // verify_kzg_proof_case_correct_proof_c3d4322ec17fe7cd
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_c3d4322ec17fe7cd should pass");

    // verify_kzg_proof_case_correct_proof_c5e1490d672d026d
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x24d25032e67a7e6a4910df5834b8fe70e6bcfeeac0352434196bdf4b2485d5a1");
    let proof = build_proof(
        "0xfa08e9fc25fb2d9a98527fc22a2c9612fbeafdad446cbc7bcdbdcd780af2c16a",
        "0x873033e038326e87ed3e1276fd140253",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_c5e1490d672d026d should pass");

    // verify_kzg_proof_case_correct_proof_cae5d3491190b777
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x2c9ae4f1d6d08558d7027df9cc6b248c21290075d2c0df8a4084d02090b3fa14");
    let proof = build_proof(
        "0x951b64b5f31bfe2fa825e18ff49a259953e734b3d57119ae66f7bd79de3027f6",
        "0xb059c60125debbbf29d041bac20fd853",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_cae5d3491190b777 should pass");

    // verify_kzg_proof_case_correct_proof_d0992bc0387790a4
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x4882cf0609af8c7cd4c256e63a35838c95a9ebbf6122540ab344b42fd66d32e1");
    let proof = build_proof(
        "0x0824ba7fea5af812721b2393354b0810a9dba2c231ea7ae30f26c412c7ea6e3a",
        "0x987ea6df69bbe97c23e0dd948cf2d449",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_d0992bc0387790a4 should pass");

    // verify_kzg_proof_case_correct_proof_d736268229bd87ec
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x5fd58150b731b4facfcdd89c0e393ff842f5f2071303eff99b51e103161cd233");
    let proof = build_proof(
        "0x0d3707a655718f968c57e225f0e4b8d5fd61878234f25ec59d090c07ea725cf4",
        "0x94425f5cf336685a6a4e806ad4601f4b",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_d736268229bd87ec should pass");

    // verify_kzg_proof_case_correct_proof_e68d7111a2364a49
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x549345dd3612e36fab0ab7baffe3faa5b820d56b71348c89ecaf63f7c4f85370");
    let proof = build_proof(
        "0x6548a14bc4af7127690a411f5e1cde2f73157365212dbcea6432e0e7869cb006",
        "0xa35c4f136a09a33c6437c26dc0c617ce",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_e68d7111a2364a49 should pass");

    // verify_kzg_proof_case_correct_proof_ed6b180ec759bcf6
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x5ee1e9a4a06a02ca6ea14b0ca73415a8ba0fba888f18dde56df499b480d4b9e0");
    let proof = build_proof(
        "0xb0738f6e15a3e0755057e7d5460406c7e148adb0e2d608982140d0ae42fe0b3b",
        "0xa1fcd37a924af9ec04143b44853c26f6",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_ed6b180ec759bcf6 should pass");

    // verify_kzg_proof_case_correct_proof_f0ed3dc11cdeb130
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x1ed7d14d1b3fb1a1890d67b81715531553ad798df2009b4311d9fe2bea6cb964");
    let proof = build_proof(
        "0x690d88d9629927dc80b0856093e08a372820248df5b8a43b6d98fd52a62fa376",
        "0xa71f21ca51b443ad35bb8a26d274223a",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_f0ed3dc11cdeb130 should pass");

    // verify_kzg_proof_case_correct_proof_f47eb9fc139f6bfd
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9");
    let proof = build_proof(
        "0x8fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
        "0xb30b3d1e4faccc380557792c9a0374d5",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_f47eb9fc139f6bfd should pass");

    // verify_kzg_proof_case_correct_proof_f7f44e1e864aa967
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x61157104410181bdc6eac224aa9436ac268bdcfeecb6badf71d228adda820af3");
    let proof = build_proof(
        "0xc2d5337109016f36a766886eade28d32f205311ff5def247c3ddba91896fae97",
        "0x809adfa8b078b0921cdb8696ca017a0c",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_f7f44e1e864aa967 should pass");

    // verify_kzg_proof_case_correct_proof_ffa6e97b97146517
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "correct_proof_ffa6e97b97146517 should pass");

    // =========================================================================
    // Point at infinity for twos poly tests
    // =========================================================================

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_05c1f3685f3393f0
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_twos_poly_05c1f3685f3393f0 should pass");

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_177b58dc7a46b08f
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_twos_poly_177b58dc7a46b08f should pass");

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_2b76dc9e3abf42f3
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_twos_poly_2b76dc9e3abf42f3 should pass");

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_395cf6d697d1a743
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_twos_poly_395cf6d697d1a743 should pass");

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_585454b31673dd62
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_twos_poly_585454b31673dd62 should pass");

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_a0be66af9a97ea52
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_twos_poly_a0be66af9a97ea52 should pass");

    // =========================================================================
    // Point at infinity for zero poly tests
    // =========================================================================

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_02e696ada7d4631d
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_zero_poly_02e696ada7d4631d should pass");

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_0cf79b17cb5f4ea2
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_zero_poly_0cf79b17cb5f4ea2 should pass");

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_3208425794224c3f
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_zero_poly_3208425794224c3f should pass");

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_3ac8dc31e9aa6a70
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_zero_poly_3ac8dc31e9aa6a70 should pass");

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_c3d4322ec17fe7cd
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_zero_poly_c3d4322ec17fe7cd should pass");

    // verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_ffa6e97b97146517
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_ok(), "point_at_infinity_for_zero_poly_ffa6e97b97146517 should pass");
}

// =========================================================================
// Incorrect tests - should all fail verification
// =========================================================================
fn kzg_verify_tests_incorrect(crypto: &CustomEvmCrypto) {
    // verify_kzg_proof_case_incorrect_proof_02e696ada7d4631d
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_02e696ada7d4631d should fail");

    // verify_kzg_proof_case_incorrect_proof_05c1f3685f3393f0
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_05c1f3685f3393f0 should fail");

    // verify_kzg_proof_case_incorrect_proof_08f9e2f1cb3d39db
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_08f9e2f1cb3d39db should fail");

    // verify_kzg_proof_case_incorrect_proof_0cf79b17cb5f4ea2
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_0cf79b17cb5f4ea2 should fail");

    // verify_kzg_proof_case_incorrect_proof_177b58dc7a46b08f
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_177b58dc7a46b08f should fail");

    // verify_kzg_proof_case_incorrect_proof_1ce8e4f69d5df899
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0xb2fe95bc3127ad9e6440d9e4d1e785b455f55fcfe80a3434dc40f8e6df85be88",
        "0x9779b8337f00de6aeac881256198bd2d",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_1ce8e4f69d5df899 should fail");

    // verify_kzg_proof_case_incorrect_proof_26b753dec0560daa
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x73e66878b46ae3705eb6a46a89213de7d3686828bfce5c19400fffff00100001");
    let proof = build_proof(
        "0x9ab03a78342c221cf6b2d6e465d01a3d47585a808c9d8d25dee885007deeb107",
        "0x90f53a4837bbde6ab0838fef0c0be533",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_26b753dec0560daa should fail");

    // verify_kzg_proof_case_incorrect_proof_2b76dc9e3abf42f3
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_2b76dc9e3abf42f3 should fail");

    // verify_kzg_proof_case_incorrect_proof_31ebd010e6098750
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9");
    let proof = build_proof(
        "0xe9c958edbebe9ead62e97e95e2dcdc4972729fb9661f0cae3532b71b2664a8c1",
        "0xb9b65c2ebc89e669cf19e82fb178f0d1",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_31ebd010e6098750 should fail");

    // verify_kzg_proof_case_incorrect_proof_3208425794224c3f
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_3208425794224c3f should fail");

    // verify_kzg_proof_case_incorrect_proof_36817bfd67de97a8
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_36817bfd67de97a8 should fail");

    // verify_kzg_proof_case_incorrect_proof_392169c16a2e5ef6
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x304962b3598a0adf33189fdfd9789feab1096ff40006900400000003fffffffc");
    let proof = build_proof(
        "0x8e8851d8cfd9ea71da1ab4233ad4217cffabd669dfa89c3ebf4c44f91694a2f4",
        "0xb08a5afbb1717334e08e05576b07bff5",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_392169c16a2e5ef6 should fail");

    // verify_kzg_proof_case_incorrect_proof_395cf6d697d1a743
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_395cf6d697d1a743 should fail");

    // verify_kzg_proof_case_incorrect_proof_3ac8dc31e9aa6a70
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_3ac8dc31e9aa6a70 should fail");

    // verify_kzg_proof_case_incorrect_proof_3c1e8b38219e3e12
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x50625ad853cc21ba40594f79591e5d35c445ecf9453014da6524c0cf6367c359");
    let proof = build_proof(
        "0xa58607777e09893f088e404eb2dc47c0269ed8e47c1be79ea07ae726abd921a8",
        "0x90559bfd8e58f5d144588a1a959c93ab",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_3c1e8b38219e3e12 should fail");

    // verify_kzg_proof_case_incorrect_proof_3c87ec986c2656c2
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x6d928e13fe443e957d82e3e71d48cb65d51028eb4483e719bf8efcdf12f7c321");
    let proof = build_proof(
        "0xced2ea6b622ebb6e289c7e05d85cc715b93eca244123c84a60b3ecbf33373903",
        "0x8d72dc4eec977090f452b412a6b0a3cd",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_3c87ec986c2656c2 should fail");

    // verify_kzg_proof_case_incorrect_proof_3cd183d0bab85fb7
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_3cd183d0bab85fb7 should fail");

    // verify_kzg_proof_case_incorrect_proof_420f2a187ce77035
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x2bf4e1f980eb94661a21affc4d7e6e56f214fe3e7dc4d20b98c66ffd43cabeb0");
    let proof = build_proof(
        "0xc43df1ddbd1dbd9d5b71f3c1798ef482f5e1fd84500b0e47c82f72a189ecd526",
        "0x99c282db3a79a9ec1553306515e6a71d",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_420f2a187ce77035 should fail");

    // verify_kzg_proof_case_incorrect_proof_444b73ff54a19b44
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x443e7af5274b52214ea6c775908c54519fea957eecd98069165a8b771082fd51");
    let proof = build_proof(
        "0x88317299333f091dd88675e84a550577bfa564b2f57cd2498e2acf875e0aaa40",
        "0xa7de1e32bb336b85e42ff50281670421",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_444b73ff54a19b44 should fail");

    // verify_kzg_proof_case_incorrect_proof_53a9bdf4f75196da
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_53a9bdf4f75196da should fail");

    // verify_kzg_proof_case_incorrect_proof_585454b31673dd62
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_585454b31673dd62 should fail");

    // verify_kzg_proof_case_incorrect_proof_7db4f140a955dd1a
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x58cdc98c4c44791bb8ba7e58a80324ef8c021c79c68e253c430fa2663188f7f2");
    let proof = build_proof(
        "0x8c127356567da1c456b9c38468909d4effe6b7faa11177e1f96ee5d2834df001",
        "0xb0ac600174134691bf9d91fee448b4d5",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_7db4f140a955dd1a should fail");

    // verify_kzg_proof_case_incorrect_proof_83e53423a2dd93fe
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    let proof = build_proof(
        "0x17d91cfc59be47cfaa7d09ef626242517541992c0f76091ddabf271682cc7c2c",
        "0x8e3069b19e6e71aed9b7dc8fbba13e42",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_83e53423a2dd93fe should fail");

    // verify_kzg_proof_case_incorrect_proof_9b24f8997145435c
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x5664bd4b6d52080460dd404dc2cb26269c24826d2bcd0152d0b55ee0a9e90289",
        "0xafc13cef6ed41f7abe142d32d7b5354e",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_9b24f8997145435c should fail");

    // verify_kzg_proof_case_incorrect_proof_9b754afb690c47e1
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_9b754afb690c47e1 should fail");

    // verify_kzg_proof_case_incorrect_proof_a0be66af9a97ea52
    let commitment = build_commitment(
        "0x9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "0xa572cbea904d67468808c8eb50a9450c",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_a0be66af9a97ea52 should fail");

    // verify_kzg_proof_case_incorrect_proof_af669445747d2585
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x6c28d6edfea2f5e1638cb1a8be8197549d52e133fa9dae87e52abb45f7b192dd");
    let proof = build_proof(
        "0x804bf7096dae003d821cc01c3b7d35c6d1fdae14e2db3c05e1cdcea7c7b7f262",
        "0xa88d68fe3ad0d09b07f4605b1364c8d4",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_af669445747d2585 should fail");

    // verify_kzg_proof_case_incorrect_proof_af8b75f664ed7d43
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x64d3b6baf69395bde2abd1d43f99be66bc64581234fd363e2ae3a0d419cfc3fc");
    let proof = build_proof(
        "0x30f238fc3cb2ecdbdc0bbb6419e3e60507e823ff7dcbd17394cea55bc514716c",
        "0xaf08cbca9deec336f2a56ca0b2029958",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_af8b75f664ed7d43 should fail");

    // verify_kzg_proof_case_incorrect_proof_b6cb6698327d9835
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x6a75e4fe63e5e148c853462a680c3e3ccedea34719d28f19bf1b35ae4eea37d6");
    let proof = build_proof(
        "0xecaf1db28384925d5007bcf7dff1a53b72bdf522610303075aeecab41685d720",
        "0x861a2aef7aa82db033bfa125b9f756af",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_b6cb6698327d9835 should fail");

    // verify_kzg_proof_case_incorrect_proof_b6ec3736f9ff2c62
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0x5b03a872a10829236d184fe1872767c391c2aa7e3b85babb1e6093b7224e7732",
        "0x82f1cd05471ab6ff21bcfd5c3369cba0",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_b6ec3736f9ff2c62 should fail");

    // verify_kzg_proof_case_incorrect_proof_becf2e1641bbd4e6
    let commitment = build_commitment(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0xb7f1d3a73197d7942695638c4fa9ac0f",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_becf2e1641bbd4e6 should fail");

    // verify_kzg_proof_case_incorrect_proof_c3d4322ec17fe7cd
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_c3d4322ec17fe7cd should fail");

    // verify_kzg_proof_case_incorrect_proof_c5e1490d672d026d
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x24d25032e67a7e6a4910df5834b8fe70e6bcfeeac0352434196bdf4b2485d5a1");
    let proof = build_proof(
        "0x993da2646e87140e12631e2914d9e6c676466aa3adfc91b61f84255544cab544",
        "0xacd56791e0ab0d1b3802021862013418",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_c5e1490d672d026d should fail");

    // verify_kzg_proof_case_incorrect_proof_cae5d3491190b777
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x2c9ae4f1d6d08558d7027df9cc6b248c21290075d2c0df8a4084d02090b3fa14");
    let proof = build_proof(
        "0x6da3ab8d2c15070f323e5a13a8178fe07c8f89686e5fd16565247b520028251b",
        "0xa4cc8c419ade0cf043cbf30f43c8f7ee",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_cae5d3491190b777 should fail");

    // verify_kzg_proof_case_incorrect_proof_d0992bc0387790a4
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x4882cf0609af8c7cd4c256e63a35838c95a9ebbf6122540ab344b42fd66d32e1");
    let proof = build_proof(
        "0x0e933e3a881b208de54149714ece74a599503f84c6249b5fd8a7c70189882a6b",
        "0xb8f731ba6a52e419ffc843c50d2947d3",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_d0992bc0387790a4 should fail");

    // verify_kzg_proof_case_incorrect_proof_d736268229bd87ec
    let commitment = build_commitment(
        "0x74e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556",
        "0x93efc82d2017e9c57834a1246463e647",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x5fd58150b731b4facfcdd89c0e393ff842f5f2071303eff99b51e103161cd233");
    let proof = build_proof(
        "0x6dedc08fd467f41fabae6bb042c2d0dbdbcd5f7532c475e479588eec5820fd37",
        "0x84c349506215a2d55f9d06f475b8229c",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_d736268229bd87ec should fail");

    // verify_kzg_proof_case_incorrect_proof_e68d7111a2364a49
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x549345dd3612e36fab0ab7baffe3faa5b820d56b71348c89ecaf63f7c4f85370");
    let proof = build_proof(
        "0xe96f7d25f8b4fe885059ec24af36f801ffbf68ec4604ef6e5f5f800f5cf31238",
        "0x94fce36bf7e9f0ed981728fcd829013d",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_e68d7111a2364a49 should fail");

    // verify_kzg_proof_case_incorrect_proof_ed6b180ec759bcf6
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x5ee1e9a4a06a02ca6ea14b0ca73415a8ba0fba888f18dde56df499b480d4b9e0");
    let proof = build_proof(
        "0x6d52613c59502a3d2df58217f4e366cd9ef37dee55bf2c705a2b08e7808b6fa0",
        "0xb3477fc9a5bfab5fdb5523251818ee5a",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_ed6b180ec759bcf6 should fail");

    // verify_kzg_proof_case_incorrect_proof_f0ed3dc11cdeb130
    let commitment = build_commitment(
        "0x432b47e7e4cd50b02cdddb4e0c1460517e8df02e4e64dc55e3d8ca192d57193a",
        "0xb49d88afcd7f6c61a8ea69eff5f609d2",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x1ed7d14d1b3fb1a1890d67b81715531553ad798df2009b4311d9fe2bea6cb964");
    let proof = build_proof(
        "0xc7743f7e5a19ee4b557471c005600f56d78e3dd887b2f5b87d76405b80dd2115",
        "0x98e15cbf800b69b90bfcaf1d907a9889",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_f0ed3dc11cdeb130 should fail");

    // verify_kzg_proof_case_incorrect_proof_f47eb9fc139f6bfd
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9");
    let proof = build_proof(
        "0xf52870e6565307ff9e32327196d7a03c428fc51a9abedc97de2a68daa1274b50",
        "0x98613e9e1b1ed52fc2fdc54e945b863f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_f47eb9fc139f6bfd should fail");

    // verify_kzg_proof_case_incorrect_proof_f7f44e1e864aa967
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x61157104410181bdc6eac224aa9436ac268bdcfeecb6badf71d228adda820af3");
    let proof = build_proof(
        "0xde681b51b312bf718821937e5088cd8ee002b718264027d10c5c5855dabe0353",
        "0xa1d8f2a5ab22acdfc1a9492ee2e1c2cb",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_f7f44e1e864aa967 should fail");

    // verify_kzg_proof_case_incorrect_proof_ffa6e97b97146517
    let commitment = build_commitment(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let proof = build_proof(
        "0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "0x97f1d3a73197d7942695638c4fa9ac0f",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_ffa6e97b97146517 should fail");

    // =========================================================================
    // Incorrect proof with point at infinity tests
    // =========================================================================

    // verify_kzg_proof_case_incorrect_proof_point_at_infinity_392169c16a2e5ef6
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y: [u8; 32] =
        hex_to_bytes("0x304962b3598a0adf33189fdfd9789feab1096ff40006900400000003fffffffc");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_point_at_infinity_392169c16a2e5ef6 should fail");

    // verify_kzg_proof_case_incorrect_proof_point_at_infinity_3c1e8b38219e3e12
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x50625ad853cc21ba40594f79591e5d35c445ecf9453014da6524c0cf6367c359");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_point_at_infinity_3c1e8b38219e3e12 should fail");

    // verify_kzg_proof_case_incorrect_proof_point_at_infinity_3c87ec986c2656c2
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306");
    let y: [u8; 32] =
        hex_to_bytes("0x6d928e13fe443e957d82e3e71d48cb65d51028eb4483e719bf8efcdf12f7c321");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_point_at_infinity_3c87ec986c2656c2 should fail");

    // verify_kzg_proof_case_incorrect_proof_point_at_infinity_420f2a187ce77035
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000002");
    let y: [u8; 32] =
        hex_to_bytes("0x2bf4e1f980eb94661a21affc4d7e6e56f214fe3e7dc4d20b98c66ffd43cabeb0");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_point_at_infinity_420f2a187ce77035 should fail");

    // verify_kzg_proof_case_incorrect_proof_point_at_infinity_83e53423a2dd93fe
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_point_at_infinity_83e53423a2dd93fe should fail");

    // verify_kzg_proof_case_incorrect_proof_point_at_infinity_ed6b180ec759bcf6
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62");
    let y: [u8; 32] =
        hex_to_bytes("0x5ee1e9a4a06a02ca6ea14b0ca73415a8ba0fba888f18dde56df499b480d4b9e0");
    let proof = build_proof(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xc0000000000000000000000000000000",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "incorrect_proof_point_at_infinity_ed6b180ec759bcf6 should fail");
}

// =========================================================================
// Invalid tests - malformed data that should be rejected
// =========================================================================
fn kzg_verify_tests_invalid(crypto: &CustomEvmCrypto) {
    // // verify_kzg_proof_case_invalid_commitment_3e55802a5ed3c757
    // // commit >= 2³⁸⁴
    // let commitment = build_commitment(
    //     "0x688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00",
    //     "0x97f1d3a73197d7942695638c4fa9ac0fc3",
    // );
    // let z: [u8; 32] =
    //     hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    // let y: [u8; 32] =
    //     hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    // let proof = build_proof(
    //     "0xf7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f",
    //     "0xb0c829a8d2d3405304fecbea193e6c67",
    // );
    // let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    // assert!(result.is_err(), "invalid_commitment_3e55802a5ed3c757: commit >= 2^384 should fail");

    // verify_kzg_proof_case_invalid_commitment_1b44e341d56c757d
    // invalid serialization
    let commitment = build_commitment(
        "0x0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6",
        "0x97f1d3a73197d7942695638c4fa9ac",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    let proof = build_proof(
        "0xf7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f",
        "0xb0c829a8d2d3405304fecbea193e6c67",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(
        result.is_err(),
        "invalid_commitment_1b44e341d56c757d: invalid serialization should fail"
    );

    // verify_kzg_proof_case_invalid_commitment_e9d3e9ec16fbc15f
    // invalid serialization
    let commitment = build_commitment(
        "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0",
        "0x8123456789abcdef0123456789abcdef",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    let proof = build_proof(
        "0xf7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f",
        "0xb0c829a8d2d3405304fecbea193e6c67",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(
        result.is_err(),
        "invalid_commitment_e9d3e9ec16fbc15f: invalid serialization should fail"
    );

    // verify_kzg_proof_case_invalid_commitment_32afa9561a4b3b91
    // commit - [y]₁ not in G1
    let commitment = build_commitment(
        "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "0x8123456789abcdef0123456789abcdef",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    let proof = build_proof(
        "0xf7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f",
        "0xb0c829a8d2d3405304fecbea193e6c67",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_commitment_32afa9561a4b3b91: commit not in G1 should fail");

    // // verify_kzg_proof_case_invalid_proof_3e55802a5ed3c757
    // // proof >= 2³⁸⁴
    // let commitment = build_commitment(
    //     "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
    //     "0xa421e229565952cfff4ef3517100a97d",
    // );
    // let z: [u8; 32] =
    //     hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    // let y: [u8; 32] =
    //     hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    // let proof = build_proof(
    //     "0x688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00",
    //     "0x97f1d3a73197d7942695638c4fa9ac0fc3",
    // );
    // let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    // assert!(result.is_err(), "invalid_proof_3e55802a5ed3c757: proof >= 2^384 should fail");

    // verify_kzg_proof_case_invalid_proof_1b44e341d56c757d
    // invalid serialization
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    let proof = build_proof(
        "0x0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6",
        "0x97f1d3a73197d7942695638c4fa9ac",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_proof_1b44e341d56c757d: invalid serialization should fail");

    // verify_kzg_proof_case_invalid_proof_e9d3e9ec16fbc15f
    // invalid serialization
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    let proof = build_proof(
        "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0",
        "0x8123456789abcdef0123456789abcdef",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_proof_e9d3e9ec16fbc15f: invalid serialization should fail");

    // verify_kzg_proof_case_invalid_proof_32afa9561a4b3b91
    // proof is not in G1
    let commitment = build_commitment(
        "0xa1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06",
        "0xa421e229565952cfff4ef3517100a97d",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
    let proof = build_proof(
        "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "0x8123456789abcdef0123456789abcdef",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_proof_32afa9561a4b3b91: proof not in G1 should fail");

    // verify_kzg_proof_case_invalid_y_35d08d612aad2197
    // y > r (all 0xff)
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let proof = build_proof(
        "0x8fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
        "0xb30b3d1e4faccc380557792c9a0374d5",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_y_35d08d612aad2197: y > r should fail");

    // verify_kzg_proof_case_invalid_y_4aa6def8c35c9097
    // y > r
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0xffffffffffffffffffffffffffffffff00000000000000000000000000000000");
    let proof = build_proof(
        "0x8fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
        "0xb30b3d1e4faccc380557792c9a0374d5",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_y_4aa6def8c35c9097: y > r should fail");

    // verify_kzg_proof_case_invalid_y_64b9ff2b8f7dddee
    // y = r + 1
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002");
    let proof = build_proof(
        "0x8fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
        "0xb30b3d1e4faccc380557792c9a0374d5",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_y_64b9ff2b8f7dddee: y = r + 1 should fail");

    // verify_kzg_proof_case_invalid_y_eb0601fec84cc5e9
    // y = r
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x0000000000000000000000000000000000000000000000000000000000000001");
    let y: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let proof = build_proof(
        "0x8fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
        "0xb30b3d1e4faccc380557792c9a0374d5",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_y_eb0601fec84cc5e9: y = r should fail");

    // verify_kzg_proof_case_invalid_z_35d08d612aad2197
    // z > r (all 0xff)
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let y: [u8; 32] =
        hex_to_bytes("0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9");
    let proof = build_proof(
        "0x8fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
        "0xb30b3d1e4faccc380557792c9a0374d5",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_z_35d08d612aad2197: z > r should fail");

    // verify_kzg_proof_case_invalid_z_4aa6def8c35c9097
    // z > r
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0xffffffffffffffffffffffffffffffff00000000000000000000000000000000");
    let y: [u8; 32] =
        hex_to_bytes("0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9");
    let proof = build_proof(
        "0x8fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
        "0xb30b3d1e4faccc380557792c9a0374d5",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_z_4aa6def8c35c9097: z > r should fail");

    // verify_kzg_proof_case_invalid_z_64b9ff2b8f7dddee
    // z = r + 1
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002");
    let y: [u8; 32] =
        hex_to_bytes("0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9");
    let proof = build_proof(
        "0x8fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
        "0xb30b3d1e4faccc380557792c9a0374d5",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_z_64b9ff2b8f7dddee: z = r + 1 should fail");

    // verify_kzg_proof_case_invalid_z_eb0601fec84cc5e9
    // z = r
    let commitment = build_commitment(
        "0x6db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7",
        "0x8f59a8d2a1a625a17f3fea0fe5eb8c89",
    );
    let z: [u8; 32] =
        hex_to_bytes("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let y: [u8; 32] =
        hex_to_bytes("0x60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9");
    let proof = build_proof(
        "0x8fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43",
        "0xb30b3d1e4faccc380557792c9a0374d5",
    );
    let result = crypto.verify_kzg_proof(&z, &y, &commitment, &proof);
    assert!(result.is_err(), "invalid_z_eb0601fec84cc5e9: z = r should fail");
}

#[derive(Debug)]
struct SuccessTestCase {
    name: String,
    input: Vec<u8>,
    expected: Vec<u8>,
}

#[derive(Debug)]
struct FailTestCase {
    name: String,
    input: Vec<u8>,
    expected_error: String,
}

fn hex_to_vec(hex: &str) -> Vec<u8> {
    let hex = hex.trim_start_matches("0x").trim();
    if hex.is_empty() {
        return Vec::new();
    }
    hex::decode(hex).expect("valid hex")
}

fn parse_success_yaml(yaml_content: &str) -> Vec<SuccessTestCase> {
    let mut tests = Vec::new();
    let mut current_input = String::new();
    let mut current_name = String::new();
    let mut current_expected = String::new();
    let mut collecting = None; // None, Some("input"), Some("expected")

    for line in yaml_content.lines() {
        let trimmed = line.trim();

        // Start of a new test case
        if trimmed.starts_with("- {") {
            // Save previous test if exists
            if !current_name.is_empty() {
                tests.push(SuccessTestCase {
                    name: current_name.clone(),
                    input: hex_to_vec(&current_input),
                    expected: hex_to_vec(&current_expected),
                });
            }
            current_input.clear();
            current_name.clear();
            current_expected.clear();
            collecting = None;
        }

        // Check for Input: field
        if let Some(idx) = trimmed.find("Input:") {
            collecting = Some("input");
            let rest = trimmed[idx + 6..].trim();
            // Handle quoted empty input
            if rest.starts_with("''") || rest.starts_with("\"\"") {
                current_input.clear();
                collecting = None;
            } else if rest.starts_with('\'') || rest.starts_with('"') {
                // Quoted value on same line
                let quote = rest.chars().next().unwrap();
                if let Some(end) = rest[1..].find(quote) {
                    current_input = rest[1..=end].to_string();
                    collecting = None;
                }
            } else {
                // Unquoted - might be multiline or same line
                let val = rest.split(',').next().unwrap_or("").trim();
                if !val.is_empty() {
                    current_input.push_str(val);
                }
            }
        }

        // Check for Name: field
        if let Some(idx) = trimmed.find("Name:") {
            collecting = None; // Stop collecting input
            let rest = trimmed[idx + 5..].trim();
            let end_chars = [',', '}'];
            let name_end = rest.find(|c| end_chars.contains(&c)).unwrap_or(rest.len());
            current_name = rest[..name_end].trim().trim_matches(['\'', '"']).to_string();
        }

        // Check for Expected: field
        if let Some(idx) = trimmed.find("Expected:") {
            collecting = Some("expected");
            let rest = trimmed[idx + 9..].trim();
            if rest.starts_with('\'') || rest.starts_with('"') {
                let quote = rest.chars().next().unwrap();
                if let Some(end) = rest[1..].find(quote) {
                    current_expected = rest[1..=end].to_string();
                    collecting = None;
                }
            } else {
                let val = rest.split(',').next().unwrap_or("").trim();
                if !val.is_empty() {
                    current_expected.push_str(val);
                }
            }
        }

        // Check for Gas: or NoBenchmark: - stop collecting
        if trimmed.starts_with("Gas:") || trimmed.starts_with("NoBenchmark:") {
            collecting = None;
        }

        // Continue collecting multiline hex if we're in collecting mode
        // and this line doesn't contain a field marker
        if collecting.is_some()
            && !trimmed.contains("Input:")
            && !trimmed.contains("Name:")
            && !trimmed.contains("Expected:")
            && !trimmed.contains("Gas:")
            && !trimmed.contains("NoBenchmark:")
            && !trimmed.starts_with("- {")
            && !trimmed.is_empty()
        {
            // Remove trailing comma if present
            let val = trimmed.trim_end_matches(',').trim();
            match collecting {
                Some("input") => current_input.push_str(val),
                Some("expected") => current_expected.push_str(val),
                _ => {}
            }
        }
    }

    // Don't forget the last test case
    if !current_name.is_empty() {
        tests.push(SuccessTestCase {
            name: current_name,
            input: hex_to_vec(&current_input),
            expected: hex_to_vec(&current_expected),
        });
    }

    tests
}

fn parse_fail_yaml(yaml_content: &str) -> Vec<FailTestCase> {
    let mut tests = Vec::new();
    let mut current_input = String::new();
    let mut current_name = String::new();
    let mut current_error = String::new();
    let mut collecting_input = false;

    for line in yaml_content.lines() {
        let trimmed = line.trim();

        // Start of a new test case
        if trimmed.starts_with("- {") {
            if !current_name.is_empty() {
                tests.push(FailTestCase {
                    name: current_name.clone(),
                    input: hex_to_vec(&current_input),
                    expected_error: current_error.clone(),
                });
            }
            current_input.clear();
            current_name.clear();
            current_error.clear();
            collecting_input = false;
        }

        // Check for Input: field
        if let Some(idx) = trimmed.find("Input:") {
            collecting_input = true;
            let rest = trimmed[idx + 6..].trim();
            if rest.starts_with("''") || rest.starts_with("\"\"") {
                current_input.clear();
                collecting_input = false;
            } else if rest.starts_with('\'') || rest.starts_with('"') {
                let quote = rest.chars().next().unwrap();
                if let Some(end) = rest[1..].find(quote) {
                    current_input = rest[1..=end].to_string();
                    collecting_input = false;
                }
            } else {
                let val = rest.split(',').next().unwrap_or("").trim();
                if !val.is_empty() {
                    current_input.push_str(val);
                }
            }
        }

        // Check for ExpectedError: field
        if let Some(idx) = trimmed.find("ExpectedError:") {
            collecting_input = false;
            let rest = trimmed[idx + 14..].trim();
            if rest.starts_with('\'') {
                if let Some(end) = rest[1..].find('\'') {
                    current_error = rest[1..=end].to_string();
                }
            } else {
                let err_end = rest.find([',', '}']).unwrap_or(rest.len());
                current_error = rest[..err_end].trim().to_string();
            }
        }

        // Check for Name: field
        if let Some(idx) = trimmed.find("Name:") {
            collecting_input = false;
            let rest = trimmed[idx + 5..].trim();
            let name_end = rest.find([',', '}']).unwrap_or(rest.len());
            current_name = rest[..name_end].trim().trim_matches(['\'', '"']).to_string();
        }

        // Continue collecting multiline hex
        if collecting_input
            && !trimmed.contains("Input:")
            && !trimmed.contains("Name:")
            && !trimmed.contains("ExpectedError:")
            && !trimmed.starts_with("- {")
            && !trimmed.is_empty()
        {
            let val = trimmed.trim_end_matches(',').trim();
            current_input.push_str(val);
        }
    }

    if !current_name.is_empty() {
        tests.push(FailTestCase {
            name: current_name,
            input: hex_to_vec(&current_input),
            expected_error: current_error,
        });
    }

    tests
}

type G1Point = ([u8; 48], [u8; 48]);
type G2Point = ([u8; 48], [u8; 48], [u8; 48], [u8; 48]);
type G1PointScalar = (G1Point, [u8; 32]);
type G2PointScalar = (G2Point, [u8; 32]);

/// Parse a 64-byte padded field element to 48 bytes (strips 16-byte zero prefix)
fn parse_fp_padded(input: &[u8]) -> [u8; 48] {
    let mut fp = [0u8; 48];
    // Skip first 16 bytes (zero padding), take next 48
    fp.copy_from_slice(&input[16..64]);
    fp
}

/// Parse a 128-byte padded G1 point to unpadded G1Point (two 48-byte coordinates)
fn parse_g1_point_padded(input: &[u8]) -> G1Point {
    let x = parse_fp_padded(&input[0..64]);
    let y = parse_fp_padded(&input[64..128]);
    (x, y)
}

/// Parse a 256-byte padded G2 point to unpadded G2Point (four 48-byte coordinates)
fn parse_g2_point_padded(input: &[u8]) -> G2Point {
    let x0 = parse_fp_padded(&input[0..64]);
    let x1 = parse_fp_padded(&input[64..128]);
    let y0 = parse_fp_padded(&input[128..192]);
    let y1 = parse_fp_padded(&input[192..256]);
    (x0, x1, y0, y1)
}

/// Parse G1 MSM input: each element is padded G1Point (128 bytes) + scalar (32 bytes) = 160 bytes
fn parse_g1_msm_pairs(input: &[u8]) -> Vec<G1PointScalar> {
    let mut pairs = Vec::new();
    let pair_size = 160; // 128 + 32
    let num_pairs = input.len() / pair_size;
    for i in 0..num_pairs {
        let offset = i * pair_size;
        let point = parse_g1_point_padded(&input[offset..offset + 128]);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&input[offset + 128..offset + 160]);
        pairs.push((point, scalar));
    }
    pairs
}

/// Parse G2 MSM input: each element is padded G2Point (256 bytes) + scalar (32 bytes) = 288 bytes
fn parse_g2_msm_pairs(input: &[u8]) -> Vec<G2PointScalar> {
    let mut pairs = Vec::new();
    let pair_size = 288; // 256 + 32
    let num_pairs = input.len() / pair_size;
    for i in 0..num_pairs {
        let offset = i * pair_size;
        let point = parse_g2_point_padded(&input[offset..offset + 256]);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&input[offset + 256..offset + 288]);
        pairs.push((point, scalar));
    }
    pairs
}

/// Parse pairing input: each pair is padded G1Point (128 bytes) + padded G2Point (256 bytes) = 384 bytes
fn parse_pairing_pairs(input: &[u8]) -> Vec<(G1Point, G2Point)> {
    let mut pairs = Vec::new();
    let pair_size = 384; // 128 + 256
    let num_pairs = input.len() / pair_size;
    for i in 0..num_pairs {
        let offset = i * pair_size;
        let g1 = parse_g1_point_padded(&input[offset..offset + 128]);
        let g2 = parse_g2_point_padded(&input[offset + 128..offset + 384]);
        pairs.push((g1, g2));
    }
    pairs
}

/// Convert 96-byte unpadded result to 128-byte padded format for comparison
fn pad_g1_result(unpadded: &[u8; 96]) -> [u8; 128] {
    let mut padded = [0u8; 128];
    // x: 16 zeros + 48 bytes
    padded[16..64].copy_from_slice(&unpadded[0..48]);
    // y: 16 zeros + 48 bytes
    padded[80..128].copy_from_slice(&unpadded[48..96]);
    padded
}

/// Convert 192-byte unpadded result to 256-byte padded format for comparison
fn pad_g2_result(unpadded: &[u8; 192]) -> [u8; 256] {
    let mut padded = [0u8; 256];
    padded[16..64].copy_from_slice(&unpadded[0..48]);
    padded[80..128].copy_from_slice(&unpadded[48..96]);
    padded[144..192].copy_from_slice(&unpadded[96..144]);
    padded[208..256].copy_from_slice(&unpadded[144..192]);
    padded
}

fn g1_add_tests(crypto: &CustomEvmCrypto) {
    let yaml_content = include_str!("bls-tests/add_G1/add_G1_bls.yaml");
    let tests = parse_success_yaml(yaml_content);

    for test in &tests {
        if test.input.len() != 256 {
            println!("Skipping {} - invalid input length {}", test.name, test.input.len());
            continue;
        }
        let a = parse_g1_point_padded(&test.input[..128]);
        let b = parse_g1_point_padded(&test.input[128..256]);
        let result = crypto.bls12_381_g1_add(a, b);
        assert!(result.is_ok(), "G1 Add {} should succeed", test.name);
        let result_padded = pad_g1_result(&result.unwrap());
        assert_eq!(
            result_padded.as_slice(),
            test.expected.as_slice(),
            "G1 Add {} mismatch",
            test.name
        );
    }

    let fail_yaml = include_str!("bls-tests/fail_add_G1/fail-add_G1_bls.yaml");
    let fail_tests = parse_fail_yaml(fail_yaml);

    for test in &fail_tests {
        if test.input.len() != 256 {
            continue;
        }
        let a = parse_g1_point_padded(&test.input[..128]);
        let b = parse_g1_point_padded(&test.input[128..256]);
        let result = crypto.bls12_381_g1_add(a, b);
        assert!(result.is_err(), "G1 Add {} should fail: {}", test.name, test.expected_error);
    }

    println!("All BLS12-381 G1 Add tests passed!");
}

fn g1_mul_tests(crypto: &CustomEvmCrypto) {
    let yaml_content = include_str!("bls-tests/mul_G1/mul_G1_bls.yaml");
    let tests = parse_success_yaml(yaml_content);

    for test in &tests {
        // G1 mul input is 160 bytes: padded G1Point (128) + scalar (32)
        if test.input.len() != 160 {
            println!("Skipping {} - invalid input length {}", test.name, test.input.len());
            continue;
        }
        let point = parse_g1_point_padded(&test.input[..128]);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&test.input[128..160]);
        let pairs = vec![(point, scalar)];
        let mut iter = pairs.into_iter().map(Ok);
        let result = crypto.bls12_381_g1_msm(&mut iter);
        assert!(result.is_ok(), "G1 Mul {} should succeed", test.name);
        let result_padded = pad_g1_result(&result.unwrap());
        assert_eq!(
            result_padded.as_slice(),
            test.expected.as_slice(),
            "G1 Mul {} mismatch",
            test.name
        );
    }
}

fn g1_msm_tests(crypto: &CustomEvmCrypto) {
    let yaml_content = include_str!("bls-tests/msm_G1/msm_G1_bls.yaml");
    let tests = parse_success_yaml(yaml_content);

    for test in &tests {
        // G1 MSM input: multiple (padded G1Point + scalar) pairs, each 160 bytes
        if test.input.len() % 160 != 0 || test.input.is_empty() {
            println!("Skipping {} - invalid input length {}", test.name, test.input.len());
            continue;
        }
        let pairs = parse_g1_msm_pairs(&test.input);
        let mut iter = pairs.into_iter().map(Ok);
        let result = crypto.bls12_381_g1_msm(&mut iter);
        assert!(result.is_ok(), "G1 MSM {} should succeed", test.name);
        let result_padded = pad_g1_result(&result.unwrap());
        assert_eq!(
            result_padded.as_slice(),
            test.expected.as_slice(),
            "G1 MSM {} mismatch",
            test.name
        );
    }

    let fail_yaml = include_str!("bls-tests/fail_msm_G1/fail-msm_G1_bls.yaml");
    let fail_tests = parse_fail_yaml(fail_yaml);

    for test in &fail_tests {
        if test.input.len() % 160 != 0 || test.input.is_empty() {
            continue;
        }
        let pairs = parse_g1_msm_pairs(&test.input);
        let mut iter = pairs.into_iter().map(Ok);
        let result = crypto.bls12_381_g1_msm(&mut iter);
        assert!(result.is_err(), "G1 MSM {} should fail: {}", test.name, test.expected_error);
    }

    println!("All BLS12-381 G1 MSM tests passed!");
}

fn g2_add_tests(crypto: &CustomEvmCrypto) {
    let yaml_content = include_str!("bls-tests/add_G2/add_G2_bls.yaml");
    let tests = parse_success_yaml(yaml_content);

    for test in &tests {
        // Padded G2 add input is 512 bytes: two padded G2Points (256 each)
        if test.input.len() != 512 {
            println!("Skipping {} - invalid input length {}", test.name, test.input.len());
            continue;
        }
        let a = parse_g2_point_padded(&test.input[..256]);
        let b = parse_g2_point_padded(&test.input[256..512]);
        let result = crypto.bls12_381_g2_add(a, b);
        assert!(result.is_ok(), "G2 Add {} should succeed", test.name);
        let result_padded = pad_g2_result(&result.unwrap());
        assert_eq!(
            result_padded.as_slice(),
            test.expected.as_slice(),
            "G2 Add {} mismatch",
            test.name
        );
    }

    let fail_yaml = include_str!("bls-tests/fail_add_G2/fail-add_G2_bls.yaml");
    let fail_tests = parse_fail_yaml(fail_yaml);

    for test in &fail_tests {
        if test.input.len() != 512 {
            continue;
        }
        let a = parse_g2_point_padded(&test.input[..256]);
        let b = parse_g2_point_padded(&test.input[256..512]);
        let result = crypto.bls12_381_g2_add(a, b);
        assert!(result.is_err(), "G2 Add {} should fail: {}", test.name, test.expected_error);
    }

    println!("All BLS12-381 G2 Add tests passed!");
}

fn g2_mul_tests(crypto: &CustomEvmCrypto) {
    let yaml_content = include_str!("bls-tests/mul_G2/mul_G2_bls.yaml");
    let tests = parse_success_yaml(yaml_content);

    for test in &tests {
        // G2 mul input is 288 bytes: padded G2Point (256) + scalar (32)
        if test.input.len() != 288 {
            println!("Skipping {} - invalid input length {}", test.name, test.input.len());
            continue;
        }
        let point = parse_g2_point_padded(&test.input[..256]);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&test.input[256..288]);
        let pairs = vec![(point, scalar)];
        let mut iter = pairs.into_iter().map(Ok);
        let result = crypto.bls12_381_g2_msm(&mut iter);
        assert!(result.is_ok(), "G2 Mul {} should succeed", test.name);
        let result_padded = pad_g2_result(&result.unwrap());
        assert_eq!(
            result_padded.as_slice(),
            test.expected.as_slice(),
            "G2 Mul {} mismatch",
            test.name
        );
    }
}

fn g2_msm_tests(crypto: &CustomEvmCrypto) {
    let yaml_content = include_str!("bls-tests/msm_G2/msm_G2_bls.yaml");
    let tests = parse_success_yaml(yaml_content);

    for test in &tests {
        // G2 MSM input: multiple (padded G2Point + scalar) pairs, each 288 bytes
        if test.input.len() % 288 != 0 || test.input.is_empty() {
            println!("Skipping {} - invalid input length {}", test.name, test.input.len());
            continue;
        }
        let pairs = parse_g2_msm_pairs(&test.input);
        let mut iter = pairs.into_iter().map(Ok);
        let result = crypto.bls12_381_g2_msm(&mut iter);
        assert!(result.is_ok(), "G2 MSM {} should succeed", test.name);
        let result_padded = pad_g2_result(&result.unwrap());
        assert_eq!(
            result_padded.as_slice(),
            test.expected.as_slice(),
            "G2 MSM {} mismatch",
            test.name
        );
    }

    let fail_yaml = include_str!("bls-tests/fail_msm_G2/fail-msm_G2_bls.yaml");
    let fail_tests = parse_fail_yaml(fail_yaml);

    for test in &fail_tests {
        if test.input.len() % 288 != 0 || test.input.is_empty() {
            continue;
        }
        let pairs = parse_g2_msm_pairs(&test.input);
        let mut iter = pairs.into_iter().map(Ok);
        let result = crypto.bls12_381_g2_msm(&mut iter);
        assert!(result.is_err(), "G2 MSM {} should fail: {}", test.name, test.expected_error);
    }

    println!("All BLS12-381 G2 MSM tests passed!");
}

fn pairing_check_tests(crypto: &CustomEvmCrypto) {
    let yaml_content = include_str!("bls-tests/pairing_check/pairing_check_bls.yaml");
    let tests = parse_success_yaml(yaml_content);

    for test in &tests {
        // Pairing input: multiple (padded G1 + padded G2) pairs, each 384 bytes
        if test.input.len() % 384 != 0 {
            println!("Skipping {} - invalid input length {}", test.name, test.input.len());
            continue;
        }
        let pairs = parse_pairing_pairs(&test.input);
        let result = crypto.bls12_381_pairing_check(&pairs);
        assert!(result.is_ok(), "Pairing {} should succeed", test.name);
        // Expected is 32 bytes: 0x01 = true, 0x00 = false
        let expected_result = test.expected.len() == 32 && test.expected[31] == 1;
        assert_eq!(result.unwrap(), expected_result, "Pairing {} mismatch", test.name);
    }

    let fail_yaml = include_str!("bls-tests/fail_pairing_check/fail-pairing_check_bls.yaml");
    let fail_tests = parse_fail_yaml(fail_yaml);

    for test in &fail_tests {
        if test.input.len() % 384 != 0 {
            continue;
        }
        let pairs = parse_pairing_pairs(&test.input);
        let result = crypto.bls12_381_pairing_check(&pairs);
        assert!(result.is_err(), "Pairing {} should fail: {}", test.name, test.expected_error);
    }

    println!("All BLS12-381 Pairing tests passed!");
}
