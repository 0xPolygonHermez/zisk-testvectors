#![no_main]
ziskos::entrypoint!(main);

use blst::*;

// --------------------
// P1 affine point (not on curve)
// --------------------
const FP_BYTES: usize = 48;

fn fp_from_u8_be(bytes: &[u8; FP_BYTES]) -> blst_fp {
    let mut out = blst_fp::default();
    unsafe {
        blst_fp_from_bendian(&mut out, bytes.as_ptr());
    }
    out
}

fn fp_zero() -> blst_fp {
    blst_fp::default()
}

fn fp_one() -> blst_fp {
    let mut b = [0u8; FP_BYTES];
    b[FP_BYTES - 1] = 1;
    fp_from_u8_be(&b)
}

fn p1_affine_infinity() -> blst_p1_affine {
    blst_p1_affine::default()
}

fn p1_affine_gen() -> blst_p1_affine {
    unsafe { BLS12_381_G1 }
}

fn p1_from_affine(aff: &blst_p1_affine) -> blst_p1 {
    let mut out = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut out, aff) };
    out
}

fn p1_to_affine(p: &blst_p1) -> blst_p1_affine {
    let mut out = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut out, p) };
    out
}

fn p2_affine_infinity() -> blst_p2_affine {
    blst_p2_affine::default()
}

fn p2_affine_gen() -> blst_p2_affine {
    unsafe { BLS12_381_G2 }
}

fn p2_from_affine(aff: &blst_p2_affine) -> blst_p2 {
    let mut out = blst_p2::default();
    unsafe { blst_p2_from_affine(&mut out, aff) };
    out
}

fn p2_to_affine(p: &blst_p2) -> blst_p2_affine {
    let mut out = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut out, p) };
    out
}

fn scalar_from_u64(val: u64) -> blst_scalar {
    let mut s = blst_scalar::default();
    s.b[0] = (val & 0xFF) as u8;
    s.b[1] = ((val >> 8) & 0xFF) as u8;
    s.b[2] = ((val >> 16) & 0xFF) as u8;
    s.b[3] = ((val >> 24) & 0xFF) as u8;
    s.b[4] = ((val >> 32) & 0xFF) as u8;
    s.b[5] = ((val >> 40) & 0xFF) as u8;
    s.b[6] = ((val >> 48) & 0xFF) as u8;
    s.b[7] = ((val >> 56) & 0xFF) as u8;
    s
}

fn main() {
    // G1 tests
    test_p1_affine_on_curve();

    test_p1_affine_in_g1();

    test_p1_add_or_double_affine();

    test_p1_mult();

    test_p1_uncompress();

    // G2 tests
    test_p2_affine_on_curve();

    test_p2_affine_in_g2();

    test_p2_add_or_double_affine();

    test_p2_mult();

    test_p2_uncompress();

    // Fp12 tests
    test_fp12_mul();

    // Pairing tests
    test_miller_loop();

    test_final_exp();

    test_pairing_verification();
}

fn test_p1_affine_on_curve() {
    println!("=== Testing blst_p1_affine_on_curve ===");

    // Test 1: Infinity is on curve
    let inf = p1_affine_infinity();
    assert!(unsafe { blst_p1_affine_on_curve(&inf) }, "Infinity should be on curve");

    // Test 2: G1 generator is on curve
    let g1 = p1_affine_gen();
    assert!(unsafe { blst_p1_affine_on_curve(&g1) }, "G1 generator should be on curve");

    // Test 3: Point not on curve (x=0, y=1)
    let not_on_curve = blst_p1_affine { x: fp_zero(), y: fp_one() };
    assert!(
        !unsafe { blst_p1_affine_on_curve(&not_on_curve) },
        "Point (0,1) should NOT be on curve"
    );

    // Test 4: Negated generator is on curve
    let neg_g1 = unsafe { BLS12_381_NEG_G1 };
    assert!(unsafe { blst_p1_affine_on_curve(&neg_g1) }, "Negated G1 should be on curve");
}

fn test_p1_affine_in_g1() {
    println!("=== Testing blst_p1_affine_in_g1 ===");

    // Test 1: Infinity is in G1
    let inf = p1_affine_infinity();
    assert!(unsafe { blst_p1_affine_in_g1(&inf) }, "Infinity should be in G1");

    // Test 2: G1 generator is in G1
    let g1 = p1_affine_gen();
    assert!(unsafe { blst_p1_affine_in_g1(&g1) }, "G1 generator should be in G1");

    // Test 3: Point not on curve is not in G1
    let not_on_curve = blst_p1_affine { x: fp_zero(), y: fp_one() };
    assert!(
        !unsafe { blst_p1_affine_in_g1(&not_on_curve) },
        "Point not on curve should NOT be in G1"
    );

    // Test 4: Negated generator is in G1
    let neg_g1 = unsafe { BLS12_381_NEG_G1 };
    assert!(unsafe { blst_p1_affine_in_g1(&neg_g1) }, "Negated G1 should be in G1");
}

fn test_p1_add_or_double_affine() {
    println!("=== Testing blst_p1_add_or_double_affine ===");

    let g1_aff = p1_affine_gen();
    let g1 = p1_from_affine(&g1_aff);
    let inf_aff = p1_affine_infinity();
    let inf = p1_from_affine(&inf_aff);

    // Test 1: G + O = G (add identity)
    let mut result = blst_p1::default();
    unsafe { blst_p1_add_or_double_affine(&mut result, &g1, &inf_aff) };
    let result_aff = p1_to_affine(&result);
    assert!(unsafe { blst_p1_affine_is_equal(&result_aff, &g1_aff) }, "G + O should equal G");

    // Test 2: O + G = G (identity + point)
    unsafe { blst_p1_add_or_double_affine(&mut result, &inf, &g1_aff) };
    let result_aff = p1_to_affine(&result);
    assert!(unsafe { blst_p1_affine_is_equal(&result_aff, &g1_aff) }, "O + G should equal G");

    // Test 3: O + O = O (identity + identity)
    unsafe { blst_p1_add_or_double_affine(&mut result, &inf, &inf_aff) };
    assert!(unsafe { blst_p1_is_inf(&result) }, "O + O should equal O");

    // Test 4: G + G = 2G (doubling)
    unsafe { blst_p1_add_or_double_affine(&mut result, &g1, &g1_aff) };
    assert!(!unsafe { blst_p1_is_inf(&result) }, "G + G should not be infinity");
    assert!(unsafe { blst_p1_in_g1(&result) }, "2G should be in G1");

    // Test 5: G + (-G) = O (inverse)
    let neg_g1_aff = unsafe { BLS12_381_NEG_G1 };
    unsafe { blst_p1_add_or_double_affine(&mut result, &g1, &neg_g1_aff) };
    assert!(unsafe { blst_p1_is_inf(&result) }, "G + (-G) should equal O");

    // Test 6: 2G + G = 3G (add different points)
    let mut two_g = blst_p1::default();
    unsafe { blst_p1_add_or_double_affine(&mut two_g, &g1, &g1_aff) };
    unsafe { blst_p1_add_or_double_affine(&mut result, &two_g, &g1_aff) };
    assert!(unsafe { blst_p1_in_g1(&result) }, "3G should be in G1");
}

fn test_p1_mult() {
    println!("=== Testing blst_p1_mult ===");

    let g1_aff = p1_affine_gen();
    let g1 = p1_from_affine(&g1_aff);
    let inf = p1_from_affine(&p1_affine_infinity());

    // Test 1: G * 0 = O
    let zero = scalar_from_u64(0);
    let mut result = blst_p1::default();
    unsafe { blst_p1_mult(&mut result, &g1, zero.b.as_ptr(), 256) };
    assert!(unsafe { blst_p1_is_inf(&result) }, "G * 0 should equal O");

    // Test 2: G * 1 = G
    let one = scalar_from_u64(1);
    unsafe { blst_p1_mult(&mut result, &g1, one.b.as_ptr(), 256) };
    let result_aff = p1_to_affine(&result);
    assert!(unsafe { blst_p1_affine_is_equal(&result_aff, &g1_aff) }, "G * 1 should equal G");

    // Test 3: G * 2 = 2G (same as G + G)
    let two = scalar_from_u64(2);
    unsafe { blst_p1_mult(&mut result, &g1, two.b.as_ptr(), 256) };
    let mut two_g_add = blst_p1::default();
    unsafe { blst_p1_add_or_double_affine(&mut two_g_add, &g1, &g1_aff) };
    assert!(unsafe { blst_p1_is_equal(&result, &two_g_add) }, "G * 2 should equal G + G");

    // Test 4: O * k = O (infinity times any scalar)
    let k = scalar_from_u64(12345);
    unsafe { blst_p1_mult(&mut result, &inf, k.b.as_ptr(), 256) };
    assert!(unsafe { blst_p1_is_inf(&result) }, "O * k should equal O");

    // Test 5: G * 3 = 3G
    let three = scalar_from_u64(3);
    unsafe { blst_p1_mult(&mut result, &g1, three.b.as_ptr(), 256) };
    let mut three_g_add = blst_p1::default();
    unsafe { blst_p1_add_or_double_affine(&mut three_g_add, &two_g_add, &g1_aff) };
    assert!(unsafe { blst_p1_is_equal(&result, &three_g_add) }, "G * 3 should equal 3G");

    // Test 6: G * large scalar
    let large = scalar_from_u64(0xFFFF_FFFF_FFFF_FFFF);
    unsafe { blst_p1_mult(&mut result, &g1, large.b.as_ptr(), 256) };
    assert!(unsafe { blst_p1_in_g1(&result) }, "G * large scalar should be in G1");
}

fn test_p1_uncompress() {
    println!("=== Testing blst_p1_uncompress ===");

    // Test 1: Compress then uncompress G1 generator
    let g1_aff = p1_affine_gen();
    let mut compressed = [0u8; 48];
    unsafe { blst_p1_affine_compress(compressed.as_mut_ptr(), &g1_aff) };

    let mut decompressed = blst_p1_affine::default();
    let err = unsafe { blst_p1_uncompress(&mut decompressed, compressed.as_ptr()) };
    assert!(matches!(err, BLST_ERROR::BLST_SUCCESS), "Uncompress should succeed");
    assert!(
        unsafe { blst_p1_affine_is_equal(&decompressed, &g1_aff) },
        "Decompressed should equal original"
    );

    // Test 2: Compress then uncompress infinity
    let inf = p1_affine_infinity();
    unsafe { blst_p1_affine_compress(compressed.as_mut_ptr(), &inf) };
    let err = unsafe { blst_p1_uncompress(&mut decompressed, compressed.as_ptr()) };
    assert!(matches!(err, BLST_ERROR::BLST_SUCCESS), "Uncompress infinity should succeed");
    assert!(unsafe { blst_p1_affine_is_inf(&decompressed) }, "Decompressed should be infinity");

    // Test 3: Compress then uncompress negated G1
    let neg_g1 = unsafe { BLS12_381_NEG_G1 };
    unsafe { blst_p1_affine_compress(compressed.as_mut_ptr(), &neg_g1) };
    let err = unsafe { blst_p1_uncompress(&mut decompressed, compressed.as_ptr()) };
    assert!(matches!(err, BLST_ERROR::BLST_SUCCESS), "Uncompress -G1 should succeed");
    assert!(
        unsafe { blst_p1_affine_is_equal(&decompressed, &neg_g1) },
        "Decompressed should equal -G1"
    );

    // Test 4: Invalid compressed data should fail
    let invalid = [0xFFu8; 48];
    let err = unsafe { blst_p1_uncompress(&mut decompressed, invalid.as_ptr()) };
    assert!(matches!(err, BLST_ERROR::BLST_BAD_ENCODING), "Invalid data should fail");

    let invalid = [0xFFu8; 48];
    let err = unsafe { blst_p1_uncompress(&mut decompressed, invalid.as_ptr()) };
    assert!(matches!(err, BLST_ERROR::BLST_BAD_ENCODING), "Invalid data should fail");
}

fn test_p2_affine_on_curve() {
    println!("=== Testing blst_p2_affine_on_curve ===");

    // Test 1: Infinity is on curve
    let inf = p2_affine_infinity();
    assert!(unsafe { blst_p2_affine_on_curve(&inf) }, "Infinity should be on curve");

    // Test 2: G2 generator is on curve
    let g2 = p2_affine_gen();
    assert!(unsafe { blst_p2_affine_on_curve(&g2) }, "G2 generator should be on curve");

    // Test 3: Negated generator is on curve
    let neg_g2 = unsafe { BLS12_381_NEG_G2 };
    assert!(unsafe { blst_p2_affine_on_curve(&neg_g2) }, "Negated G2 should be on curve");
}

fn test_p2_affine_in_g2() {
    println!("=== Testing blst_p2_affine_in_g2 ===");

    // Test 1: Infinity is in G2
    let inf = p2_affine_infinity();
    assert!(unsafe { blst_p2_affine_in_g2(&inf) }, "Infinity should be in G2");

    // Test 2: G2 generator is in G2
    let g2 = p2_affine_gen();
    assert!(unsafe { blst_p2_affine_in_g2(&g2) }, "G2 generator should be in G2");

    // Test 3: Negated generator is in G2
    let neg_g2 = unsafe { BLS12_381_NEG_G2 };
    assert!(unsafe { blst_p2_affine_in_g2(&neg_g2) }, "Negated G2 should be in G2");
}

fn test_p2_add_or_double_affine() {
    println!("=== Testing blst_p2_add_or_double_affine ===");

    let g2_aff = p2_affine_gen();
    let g2 = p2_from_affine(&g2_aff);
    let inf_aff = p2_affine_infinity();
    let inf = p2_from_affine(&inf_aff);

    // Test 1: G + O = G
    let mut result = blst_p2::default();
    unsafe { blst_p2_add_or_double_affine(&mut result, &g2, &inf_aff) };
    let result_aff = p2_to_affine(&result);
    assert!(unsafe { blst_p2_affine_is_equal(&result_aff, &g2_aff) }, "G + O should equal G");

    // Test 2: O + G = G
    unsafe { blst_p2_add_or_double_affine(&mut result, &inf, &g2_aff) };
    let result_aff = p2_to_affine(&result);
    assert!(unsafe { blst_p2_affine_is_equal(&result_aff, &g2_aff) }, "O + G should equal G");

    // Test 3: O + O = O
    unsafe { blst_p2_add_or_double_affine(&mut result, &inf, &inf_aff) };
    assert!(unsafe { blst_p2_is_inf(&result) }, "O + O should equal O");

    // Test 4: G + G = 2G
    unsafe { blst_p2_add_or_double_affine(&mut result, &g2, &g2_aff) };
    assert!(!unsafe { blst_p2_is_inf(&result) }, "G + G should not be infinity");
    assert!(unsafe { blst_p2_in_g2(&result) }, "2G should be in G2");

    // Test 5: G + (-G) = O
    let neg_g2_aff = unsafe { BLS12_381_NEG_G2 };
    unsafe { blst_p2_add_or_double_affine(&mut result, &g2, &neg_g2_aff) };
    assert!(unsafe { blst_p2_is_inf(&result) }, "G + (-G) should equal O");
}

fn test_p2_mult() {
    println!("=== Testing blst_p2_mult ===");

    let g2_aff = p2_affine_gen();
    let g2 = p2_from_affine(&g2_aff);
    let inf = p2_from_affine(&p2_affine_infinity());

    // Test 1: G * 0 = O
    let zero = scalar_from_u64(0);
    let mut result = blst_p2::default();
    unsafe { blst_p2_mult(&mut result, &g2, zero.b.as_ptr(), 256) };
    assert!(unsafe { blst_p2_is_inf(&result) }, "G * 0 should equal O");

    // Test 2: G * 1 = G
    let one = scalar_from_u64(1);
    unsafe { blst_p2_mult(&mut result, &g2, one.b.as_ptr(), 256) };
    let result_aff = p2_to_affine(&result);
    assert!(unsafe { blst_p2_affine_is_equal(&result_aff, &g2_aff) }, "G * 1 should equal G");

    // Test 3: G * 2 = 2G
    let two = scalar_from_u64(2);
    unsafe { blst_p2_mult(&mut result, &g2, two.b.as_ptr(), 256) };
    let mut two_g_add = blst_p2::default();
    unsafe { blst_p2_add_or_double_affine(&mut two_g_add, &g2, &g2_aff) };
    assert!(unsafe { blst_p2_is_equal(&result, &two_g_add) }, "G * 2 should equal G + G");

    // Test 4: O * k = O
    let k = scalar_from_u64(12345);
    unsafe { blst_p2_mult(&mut result, &inf, k.b.as_ptr(), 256) };
    assert!(unsafe { blst_p2_is_inf(&result) }, "O * k should equal O");

    // Test 5: G * large scalar is in G2
    let large = scalar_from_u64(0xFFFF_FFFF_FFFF_FFFF);
    unsafe { blst_p2_mult(&mut result, &g2, large.b.as_ptr(), 256) };
    assert!(unsafe { blst_p2_in_g2(&result) }, "G * large scalar should be in G2");
}

fn test_p2_uncompress() {
    println!("=== Testing blst_p2_uncompress ===");

    // Test 1: Compress then uncompress G2 generator
    let g2_aff = p2_affine_gen();
    let mut compressed = [0u8; 96];
    unsafe { blst_p2_affine_compress(compressed.as_mut_ptr(), &g2_aff) };

    let mut decompressed = blst_p2_affine::default();
    let err = unsafe { blst_p2_uncompress(&mut decompressed, compressed.as_ptr()) };
    assert!(matches!(err, BLST_ERROR::BLST_SUCCESS), "Uncompress should succeed");
    assert!(
        unsafe { blst_p2_affine_is_equal(&decompressed, &g2_aff) },
        "Decompressed should equal original"
    );

    // Test 2: Compress then uncompress infinity
    let inf = p2_affine_infinity();
    unsafe { blst_p2_affine_compress(compressed.as_mut_ptr(), &inf) };
    let err = unsafe { blst_p2_uncompress(&mut decompressed, compressed.as_ptr()) };
    assert!(matches!(err, BLST_ERROR::BLST_SUCCESS), "Uncompress infinity should succeed");
    assert!(unsafe { blst_p2_affine_is_inf(&decompressed) }, "Decompressed should be infinity");

    // Test 3: Compress then uncompress negated G2
    let neg_g2 = unsafe { BLS12_381_NEG_G2 };
    unsafe { blst_p2_affine_compress(compressed.as_mut_ptr(), &neg_g2) };
    let err = unsafe { blst_p2_uncompress(&mut decompressed, compressed.as_ptr()) };
    assert!(matches!(err, BLST_ERROR::BLST_SUCCESS), "Uncompress -G2 should succeed");
    assert!(
        unsafe { blst_p2_affine_is_equal(&decompressed, &neg_g2) },
        "Decompressed should equal -G2"
    );

    // Test 4: Invalid compressed data should fail
    let invalid = [0xFFu8; 96];
    let err = unsafe { blst_p2_uncompress(&mut decompressed, invalid.as_ptr()) };
    assert!(matches!(err, BLST_ERROR::BLST_BAD_ENCODING), "Invalid data should fail");

    let valid = [
        147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208,
        208, 153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93,
        87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39, 45,
        197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122, 227, 209, 119, 11,
        172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184,
    ];
    let err = unsafe { blst_p2_uncompress(&mut decompressed, valid.as_ptr()) };
    assert!(matches!(err, BLST_ERROR::BLST_SUCCESS), "Valid data should succeed");
}

fn test_fp12_mul() {
    println!("=== Testing blst_fp12_mul ===");

    // Test 1: 1 * 1 = 1
    let one = unsafe { *blst_fp12_one() };
    let mut result = blst_fp12::default();
    unsafe { blst_fp12_mul(&mut result, &one, &one) };
    assert!(unsafe { blst_fp12_is_one(&result) }, "1 * 1 should equal 1");

    // Test 2: Generate fp12 from pairing, then test multiplication
    let g1 = p1_affine_gen();
    let g2 = p2_affine_gen();
    let mut f = blst_fp12::default();
    unsafe { blst_miller_loop(&mut f, &g2, &g1) };

    // f * 1 = f
    unsafe { blst_fp12_mul(&mut result, &f, &one) };
    assert!(unsafe { blst_fp12_is_equal(&result, &f) }, "f * 1 should equal f");

    // Test 3: f * f = f^2
    let mut f_squared_mul = blst_fp12::default();
    unsafe { blst_fp12_mul(&mut f_squared_mul, &f, &f) };
    let mut f_squared_sqr = blst_fp12::default();
    unsafe { blst_fp12_sqr(&mut f_squared_sqr, &f) };
    assert!(unsafe { blst_fp12_is_equal(&f_squared_mul, &f_squared_sqr) }, "f * f should equal f^2");

    // Test 4: Associativity: (a * b) * c = a * (b * c)
    let mut ab = blst_fp12::default();
    let mut ab_c = blst_fp12::default();
    let mut bc = blst_fp12::default();
    let mut a_bc = blst_fp12::default();
    
    // Use f, f^2, and another pairing result
    let g1_neg = unsafe { BLS12_381_NEG_G1 };
    let mut c = blst_fp12::default();
    unsafe { blst_miller_loop(&mut c, &g2, &g1_neg) };
    
    unsafe { blst_fp12_mul(&mut ab, &f, &f_squared_mul) };
    unsafe { blst_fp12_mul(&mut ab_c, &ab, &c) };
    unsafe { blst_fp12_mul(&mut bc, &f_squared_mul, &c) };
    unsafe { blst_fp12_mul(&mut a_bc, &f, &bc) };
    assert!(unsafe { blst_fp12_is_equal(&ab_c, &a_bc) }, "Multiplication should be associative");
}

fn test_miller_loop() {
    println!("=== Testing blst_miller_loop ===");

    let g1 = p1_affine_gen();
    let g2 = p2_affine_gen();
    let inf_p1 = p1_affine_infinity();
    let inf_p2 = p2_affine_infinity();

    // Test 1: Miller loop with P = infinity returns 1
    let mut result = blst_fp12::default();
    unsafe { blst_miller_loop(&mut result, &g2, &inf_p1) };
    assert!(unsafe { blst_fp12_is_one(&result) }, "Miller loop with P=inf should return 1");

    // Test 2: Miller loop with Q = infinity returns 1
    unsafe { blst_miller_loop(&mut result, &inf_p2, &g1) };
    assert!(unsafe { blst_fp12_is_one(&result) }, "Miller loop with Q=inf should return 1");

    // Test 3: Miller loop with generators produces non-trivial result
    unsafe { blst_miller_loop(&mut result, &g2, &g1) };
    assert!(!unsafe { blst_fp12_is_one(&result) }, "Miller loop with generators should not be 1");

    // Test 4: e(P, Q) * e(P, -Q) should give 1 after final exp (bilinearity check)
    let neg_g2 = unsafe { BLS12_381_NEG_G2 };
    let mut f1 = blst_fp12::default();
    let mut f2 = blst_fp12::default();
    unsafe { blst_miller_loop(&mut f1, &g2, &g1) };
    unsafe { blst_miller_loop(&mut f2, &neg_g2, &g1) };
    
    let mut product = blst_fp12::default();
    unsafe { blst_fp12_mul(&mut product, &f1, &f2) };
    
    let mut final_result = blst_fp12::default();
    unsafe { blst_final_exp(&mut final_result, &product) };
    assert!(unsafe { blst_fp12_is_one(&final_result) }, "e(G1, G2) * e(G1, -G2) should be 1");
}

fn test_final_exp() {
    println!("=== Testing blst_final_exp ===");

    // Test 1: final_exp(1) = 1
    let one = unsafe { *blst_fp12_one() };
    let mut result = blst_fp12::default();
    unsafe { blst_final_exp(&mut result, &one) };
    assert!(unsafe { blst_fp12_is_one(&result) }, "final_exp(1) should be 1");

    // Test 2: Result of final_exp should be in the cyclotomic subgroup
    let g1 = p1_affine_gen();
    let g2 = p2_affine_gen();
    let mut f = blst_fp12::default();
    unsafe { blst_miller_loop(&mut f, &g2, &g1) };
    unsafe { blst_final_exp(&mut result, &f) };
    assert!(unsafe { blst_fp12_in_group(&result) }, "final_exp result should be in GT");

    // Test 3: Pairing verification: e(2G1, G2) = e(G1, 2G2)
    // First compute 2G1 and 2G2
    let g1_proj = p1_from_affine(&g1);
    let g2_proj = p2_from_affine(&g2);
    
    let two = scalar_from_u64(2);
    let mut two_g1 = blst_p1::default();
    let mut two_g2 = blst_p2::default();
    unsafe { blst_p1_mult(&mut two_g1, &g1_proj, two.b.as_ptr(), 256) };
    unsafe { blst_p2_mult(&mut two_g2, &g2_proj, two.b.as_ptr(), 256) };
    
    let two_g1_aff = p1_to_affine(&two_g1);
    let two_g2_aff = p2_to_affine(&two_g2);
    
    let mut f1 = blst_fp12::default();
    let mut f2 = blst_fp12::default();
    unsafe { blst_miller_loop(&mut f1, &g2, &two_g1_aff) };     // e(2G1, G2)
    unsafe { blst_miller_loop(&mut f2, &two_g2_aff, &g1) };     // e(G1, 2G2)
    
    let mut e1 = blst_fp12::default();
    let mut e2 = blst_fp12::default();
    unsafe { blst_final_exp(&mut e1, &f1) };
    unsafe { blst_final_exp(&mut e2, &f2) };
    
    assert!(unsafe { blst_fp12_is_equal(&e1, &e2) }, "e(2G1, G2) should equal e(G1, 2G2)");

    // Test 4: e(G1, G2)^2 = e(2G1, G2)
    let mut e_g1_g2 = blst_fp12::default();
    unsafe { blst_miller_loop(&mut f, &g2, &g1) };
    unsafe { blst_final_exp(&mut e_g1_g2, &f) };
    
    let mut e_squared = blst_fp12::default();
    unsafe { blst_fp12_sqr(&mut e_squared, &e_g1_g2) };
    
    assert!(unsafe { blst_fp12_is_equal(&e_squared, &e1) }, "e(G1, G2)^2 should equal e(2G1, G2)");
}

fn test_pairing_verification() {
    println!("=== Testing Full Pairing Verification ===");

    let g1 = p1_affine_gen();
    let g2 = p2_affine_gen();
    
    // Test BLS signature verification simulation:
    // Verify that e(P, H) = e(G1, S) where S = sk * H and P = sk * G1
    // This is equivalent to checking e(G1, G2)^sk
    
    let sk = scalar_from_u64(42); // secret key
    
    // Compute pk = sk * G1
    let g1_proj = p1_from_affine(&g1);
    let mut pk_proj = blst_p1::default();
    unsafe { blst_p1_mult(&mut pk_proj, &g1_proj, sk.b.as_ptr(), 256) };
    let pk = p1_to_affine(&pk_proj);
    
    // Compute sig = sk * G2 (using G2 as "hash" for simplicity)
    let g2_proj = p2_from_affine(&g2);
    let mut sig_proj = blst_p2::default();
    unsafe { blst_p2_mult(&mut sig_proj, &g2_proj, sk.b.as_ptr(), 256) };
    let sig = p2_to_affine(&sig_proj);
    
    // Verify: e(pk, G2) = e(G1, sig)
    // Or equivalently: e(pk, G2) * e(-G1, sig) = 1
    let neg_g1 = unsafe { BLS12_381_NEG_G1 };
    
    let mut f1 = blst_fp12::default();
    let mut f2 = blst_fp12::default();
    unsafe { blst_miller_loop(&mut f1, &g2, &pk) };
    unsafe { blst_miller_loop(&mut f2, &sig, &neg_g1) };
    
    let mut product = blst_fp12::default();
    unsafe { blst_fp12_mul(&mut product, &f1, &f2) };
    
    let mut result = blst_fp12::default();
    unsafe { blst_final_exp(&mut result, &product) };
    
    assert!(unsafe { blst_fp12_is_one(&result) }, "BLS signature verification should pass");

    // Also verify using blst_fp12_finalverify
    let mut e_pk_g2 = blst_fp12::default();
    let mut e_g1_sig = blst_fp12::default();
    unsafe { blst_miller_loop(&mut f1, &g2, &pk) };
    unsafe { blst_final_exp(&mut e_pk_g2, &f1) };
    unsafe { blst_miller_loop(&mut f2, &sig, &g1) };
    unsafe { blst_final_exp(&mut e_g1_sig, &f2) };
    
    assert!(unsafe { blst_fp12_finalverify(&e_pk_g2, &e_g1_sig) }, "finalverify should confirm equality");
}
