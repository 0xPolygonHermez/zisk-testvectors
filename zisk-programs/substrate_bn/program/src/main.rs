#![no_main]
ziskos::entrypoint!(main);

use substrate_bn::*;

fn main() {
    // G1 tests
    test_g1_add();
    test_g1_mul();
    test_affine_g1_new();
    test_affine_g1_from_jacobian();

    // G2 tests
    test_g2_add();
    test_g2_mul();
    test_affine_g2_new();

    // Pairing tests
    test_pairing_batch();
    test_pairing_bilinearity();
}

// =============================================================================
// G1 Tests
// =============================================================================

fn test_g1_add() {
    println!("=== Testing G1 addition (add_bn254_c) ===");

    let g = G1::one();
    let zero = G1::zero();

    // Test 1: G + O = G
    let result = g + zero;
    assert_eq!(g, result, "G + O should equal G");

    // Test 2: G + G = 2G
    let two_g = g + g;
    assert!(!two_g.is_zero(), "G + G should not be zero");

    // Test 3: 2G + G = 3G
    let three_g = two_g + g;
    assert!(!three_g.is_zero(), "2G + G should not be zero");

    // Test 4: G + (-G) = O
    let neg_g = -g;
    let result = g + neg_g;
    assert!(result.is_zero(), "G + (-G) should equal O");

    // Test 5: (-G) + G = O
    let result = neg_g + g;
    assert!(result.is_zero(), "(-G) + G should equal O");

    // Test 6: 2G + (-G) = G
    let result = two_g + neg_g;
    assert_eq!(g, result, "2G + (-G) should equal G");
}

fn test_g1_mul() {
    println!("=== Testing G1 scalar multiplication (mul_bn254_c) ===");

    let g = G1::one();
    let zero = G1::zero();

    // Test 1: G * 0 = O
    let zero_fr = Fr::zero();
    let result = g * zero_fr;
    assert!(result.is_zero(), "G * 0 should equal O");

    // Test 2: G * 1 = G
    let one_fr = Fr::one();
    let result = g * one_fr;
    assert_eq!(g, result, "G * 1 should equal G");

    // Test 3: G * 2 = G + G
    let two_fr = Fr::one() + Fr::one();
    let result_mul = g * two_fr;
    let result_add = g + g;
    assert_eq!(result_mul, result_add, "G * 2 should equal G + G");

    // Test 4: G * 3 = G + G + G
    let three_fr = two_fr + Fr::one();
    let result_mul = g * three_fr;
    let result_add = result_add + g;
    assert_eq!(result_mul, result_add, "G * 3 should equal G + G + G");

    // Test 5: O * k = O (infinity times any scalar)
    let k = Fr::from_str("12345").unwrap();
    let result = zero * k;
    assert!(result.is_zero(), "O * k should equal O");

    // Test 6: G * large scalar
    let large = Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495616").unwrap(); // BN254 scalar field order - 1
    let result = g * large;
    assert!(!result.is_zero(), "G * large should not be zero");
}

fn test_affine_g1_new() {
    println!("=== Testing AffineG1::new (is_on_curve_bn254_c) ===");

    // Test 1: Generator point is on curve
    let g = G1::one();
    let g_aff = AffineG1::from_jacobian(g).expect("Generator should convert to affine");
    let reconstructed = AffineG1::new(g_aff.x(), g_aff.y());
    assert!(reconstructed.is_ok(), "Generator coordinates should be on curve");

    // Test 2: Point not on curve should fail
    let invalid = AffineG1::new(Fq::zero(), Fq::one());
    assert!(invalid.is_err(), "Point (0, 1) should NOT be on curve");

    // Test 3: Zero point (represented as (0, 0) is not valid for AffineG1::new)
    // Note: Infinity in Jacobian is z=0, affine form doesn't have explicit infinity

    // Test 4: 2G is also on curve
    let two_g = g + g;
    let two_g_aff = AffineG1::from_jacobian(two_g).expect("2G should convert to affine");
    let reconstructed = AffineG1::new(two_g_aff.x(), two_g_aff.y());
    assert!(reconstructed.is_ok(), "2G coordinates should be on curve");
}

fn test_affine_g1_from_jacobian() {
    println!("=== Testing AffineG1::from_jacobian (to_affine_bn254_c) ===");

    // Test 1: Convert generator to affine
    let g = G1::one();
    let g_aff = AffineG1::from_jacobian(g);
    assert!(g_aff.is_some(), "Generator should convert to affine");

    // Test 2: Convert zero to affine (returns None)
    let zero = G1::zero();
    let zero_aff = AffineG1::from_jacobian(zero);
    assert!(zero_aff.is_none(), "Zero should return None when converting to affine");

    // Test 3: Convert 2G to affine
    let two_g = g + g;
    let two_g_aff = AffineG1::from_jacobian(two_g);
    assert!(two_g_aff.is_some(), "2G should convert to affine");

    // Test 4: Convert back to Jacobian and verify
    let g_aff = AffineG1::from_jacobian(g).unwrap();
    let g_back: G1 = g_aff.into();
    assert_eq!(g, g_back, "Affine->Jacobian roundtrip should preserve point");
}

// =============================================================================
// G2 Tests
// =============================================================================

fn test_g2_add() {
    println!("=== Testing G2 addition ===");

    let g = G2::one();
    let zero = G2::zero();

    // Test 1: G + O = G
    let result = g + zero;
    assert_eq!(g, result, "G + O should equal G");

    // Test 2: G + G = 2G
    let two_g = g + g;
    assert!(!two_g.is_zero(), "G + G should not be zero");

    // Test 3: G + (-G) = O
    let neg_g = -g;
    let result = g + neg_g;
    assert!(result.is_zero(), "G + (-G) should equal O");
}

fn test_g2_mul() {
    println!("=== Testing G2 scalar multiplication ===");

    let g = G2::one();

    // Test 1: G * 0 = O
    let zero_fr = Fr::zero();
    let result = g * zero_fr;
    assert!(result.is_zero(), "G * 0 should equal O");

    // Test 2: G * 1 = G
    let one_fr = Fr::one();
    let result = g * one_fr;
    assert_eq!(g, result, "G * 1 should equal G");

    // Test 3: G * 2 = G + G
    let two_fr = Fr::one() + Fr::one();
    let result_mul = g * two_fr;
    let result_add = g + g;
    assert_eq!(result_mul, result_add, "G * 2 should equal G + G");
}

fn test_affine_g2_new() {
    println!("=== Testing AffineG2::new (is_on_curve_twist_bn254_c, is_on_subgroup_twist_bn254_c) ===");

    // Test 1: Generator point is on curve and in subgroup
    let g = G2::one();
    let g_aff = AffineG2::from_jacobian(g).expect("Generator should convert to affine");
    let reconstructed = AffineG2::new(g_aff.x(), g_aff.y());
    assert!(reconstructed.is_ok(), "G2 generator should be on curve and in subgroup");

    // Test 2: Point not on curve should fail
    let invalid = AffineG2::new(Fq2::zero(), Fq2::one());
    assert!(invalid.is_err(), "Point (0, 1) should NOT be on twist curve");

    // Test 3: 2G is also on curve and in subgroup
    let two_g = g + g;
    let two_g_aff = AffineG2::from_jacobian(two_g).expect("2G should convert to affine");
    let reconstructed = AffineG2::new(two_g_aff.x(), two_g_aff.y());
    assert!(reconstructed.is_ok(), "2G should be on curve and in subgroup");
}

// =============================================================================
// Pairing Tests
// =============================================================================

fn test_pairing_batch() {
    println!("=== Testing pairing_batch (pairing_batch_bn254_c) ===");

    let g1 = G1::one();
    let g2 = G2::one();
    let zero_g1 = G1::zero();
    let zero_g2 = G2::zero();

    // Test 1: e(G1, G2) is not trivial
    let result = pairing_batch(&[(g1, g2)]);
    assert!(result != Gt::one(), "e(G1, G2) should not be 1");

    // Test 2: e(O, G2) = 1
    let result = pairing_batch(&[(zero_g1, g2)]);
    assert!(result == Gt::one(), "e(O, G2) should be 1");

    // Test 3: e(G1, O) = 1
    let result = pairing_batch(&[(g1, zero_g2)]);
    assert!(result == Gt::one(), "e(G1, O) should be 1");

    // Test 4: e(O, O) = 1
    let result = pairing_batch(&[(zero_g1, zero_g2)]);
    assert!(result == Gt::one(), "e(O, O) should be 1");

    // Test 5: e(G1, G2) * e(G1, -G2) = 1
    let neg_g2 = -g2;
    let result = pairing_batch(&[(g1, g2), (g1, neg_g2)]);
    assert!(result == Gt::one(), "e(G1, G2) * e(G1, -G2) should be 1");

    // Test 6: e(-G1, G2) * e(G1, G2) = 1
    let neg_g1 = -g1;
    let result = pairing_batch(&[(neg_g1, g2), (g1, g2)]);
    assert!(result == Gt::one(), "e(-G1, G2) * e(G1, G2) should be 1");
}

fn test_pairing_bilinearity() {
    println!("=== Testing pairing bilinearity ===");

    let g1 = G1::one();
    let g2 = G2::one();
    let two = Fr::one() + Fr::one();
    let three = two + Fr::one();

    // Bilinearity: e(aP, bQ) = e(P, Q)^(ab)
    
    // Test 1: e(2G1, G2) = e(G1, 2G2)
    let two_g1 = g1 * two;
    let two_g2 = g2 * two;
    let e1 = pairing_batch(&[(two_g1, g2)]);
    let e2 = pairing_batch(&[(g1, two_g2)]);
    assert!(e1 == e2, "e(2G1, G2) should equal e(G1, 2G2)");

    // Test 2: e(3G1, G2) = e(G1, 3G2)
    let three_g1 = g1 * three;
    let three_g2 = g2 * three;
    let e1 = pairing_batch(&[(three_g1, g2)]);
    let e2 = pairing_batch(&[(g1, three_g2)]);
    assert!(e1 == e2, "e(3G1, G2) should equal e(G1, 3G2)");

    // Test 3: e(2G1, 3G2) = e(6G1, G2) = e(G1, 6G2)
    let six = two * three;
    let six_g1 = g1 * six;
    let six_g2 = g2 * six;
    let e1 = pairing_batch(&[(two_g1, three_g2)]);
    let e2 = pairing_batch(&[(six_g1, g2)]);
    let e3 = pairing_batch(&[(g1, six_g2)]);
    assert!(e1 == e2, "e(2G1, 3G2) should equal e(6G1, G2)");
    assert!(e2 == e3, "e(6G1, G2) should equal e(G1, 6G2)");

    // Test 4: e(G1, G2)^2 = e(2G1, G2)
    let e_base = pairing_batch(&[(g1, g2)]);
    let e_squared = e_base * e_base;
    let e_2g1 = pairing_batch(&[(two_g1, g2)]);
    assert!(e_squared == e_2g1, "e(G1, G2)^2 should equal e(2G1, G2)");
}