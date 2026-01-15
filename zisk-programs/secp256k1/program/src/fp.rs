use ziskos::zisklib::{
    secp256k1_fp_add, secp256k1_fp_inv, secp256k1_fp_mul, secp256k1_fp_mul_scalar,
    secp256k1_fp_negate, secp256k1_fp_reduce, secp256k1_fp_sqrt, secp256k1_fp_square,
};

/*
sage: p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
sage: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
sage: F = GF(p)
sage: Fn = GF(n)
sage: E = EllipticCurve(F, [0,7])
sage: G = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
*/
pub fn fp_tests() {
    // Reduction
    let a = [0xffffffff1da63df0, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff];
    let res = secp256k1_fp_reduce(&a);
    let res_exp = [0x1da641c1, 0x0, 0x0, 0x0];
    assert_eq!(res, res_exp);

    // Addition
    let a = [0x87d832983725d224, 0x798a9dbd05c98c74, 0x26624bb5fadfb817, 0x59622b41ba03b966];
    let b = [0x5f9f231bdd127ca1, 0xd61a40325833f333, 0x329f2b6e5826f1fb, 0x814e6375b67b17db];
    let res = secp256k1_fp_add(&a, &b);
    let res_exp = [0xe77755b414384ec5, 0x4fa4ddef5dfd7fa7, 0x590177245306aa13, 0xdab08eb7707ed141];
    assert_eq!(res, res_exp);

    // Negation
    let a = [0; 4];
    let res = secp256k1_fp_negate(&a);
    let res_exp = a;
    assert_eq!(res, res_exp);

    let a = [0x87d832983725d224, 0x798a9dbd05c98c74, 0x26624bb5fadfb817, 0x59622b41ba03b966];
    let res = secp256k1_fp_negate(&a);
    let res_exp = [0x7827cd66c8da2a0b, 0x86756242fa36738b, 0xd99db44a052047e8, 0xa69dd4be45fc4699];
    assert_eq!(res, res_exp);

    // Multiplication
    let a = [0x87d832983725d224, 0x798a9dbd05c98c74, 0x26624bb5fadfb817, 0x59622b41ba03b966];
    let b = [0x5f9f231bdd127ca1, 0xd61a40325833f333, 0x329f2b6e5826f1fb, 0x814e6375b67b17db];
    let res = secp256k1_fp_mul(&a, &b);
    let res_exp = [0xaa2f9bcd686d24f6, 0x53ba237580c1ed1b, 0xae9ba1df41e261b8, 0xc85a601351bf65b9];
    assert_eq!(res, res_exp);

    // Scalar Multiplication
    let s = 0x203fda29c764dc92;
    let a = [0x87d832983725d224, 0x798a9dbd05c98c74, 0x26624bb5fadfb817, 0x59622b41ba03b966];
    let res = secp256k1_fp_mul_scalar(&a, s);
    let res_exp = [0xa09df7924f7f6759, 0xae7d848f5716f5cd, 0x53ca2ef672353cf5, 0xafd81f9d588cb857];
    assert_eq!(res, res_exp);

    // Squaring
    let a = [0x87d832983725d224, 0x798a9dbd05c98c74, 0x26624bb5fadfb817, 0x59622b41ba03b966];
    let res = secp256k1_fp_square(&a);
    let res_exp = [0x5dd3ad79e6737710, 0x7c6751b4ccd98b47, 0xfdc1575042b02a45, 0x691593f2fd2c7012];
    assert_eq!(res, res_exp);

    // Inversion
    let a = [0x87d832983725d224, 0x798a9dbd05c98c74, 0x26624bb5fadfb817, 0x59622b41ba03b966];
    let res = secp256k1_fp_inv(&a);
    let res_exp = [0xdf9a81f172f51d5a, 0x1eea8322085ccf8f, 0x2fc62744b282a462, 0x13a1b9de6eb5c5e];
    assert_eq!(res, res_exp);

    // Square Root
    let a = [0x87d832983725d226, 0x798a9dbd05c98c74, 0x26624bb5fadfb817, 0x59622b41ba03b966];
    let (res, is_quadratic) = secp256k1_fp_sqrt(&a, 0);
    let res_exp = [0xc75120f0e36700fe, 0x1ec8dac5f19fb98a, 0x276e4812fa862ed6, 0x438dbd7d330e4295];
    assert_eq!(res, res_exp);
    assert!(is_quadratic);

    let (res, is_quadratic) = secp256k1_fp_sqrt(&a, 1);
    let res_exp = [0x38aedf0e1c98fb31, 0xe137253a0e604675, 0xd891b7ed0579d129, 0xbc724282ccf1bd6a];
    assert_eq!(res, res_exp);
    assert!(is_quadratic);

    let a = [0x87d832983725d224, 0x798a9dbd05c98c74, 0x26624bb5fadfb817, 0x59622b41ba03b966];
    let (_, is_quadratic) = secp256k1_fp_sqrt(&a, 0);
    assert!(!is_quadratic);
}
