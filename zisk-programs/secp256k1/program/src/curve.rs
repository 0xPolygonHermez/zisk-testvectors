use ziskos::zisklib::{
    secp256k1_decompress, secp256k1_double_scalar_mul_with_g, secp256k1_is_on_curve,
    secp256k1_scalar_mul, secp256k1_to_affine, secp256k1_triple_scalar_mul_with_g,
};

use crate::constants::{G, G_NEG, G_X, G_Y, IDENTITY};

pub fn curve_tests() {
    // Decompress
    let p_x = G_X;
    let res = match secp256k1_decompress(&p_x, false) {
        Ok(point) => point,
        Err(_) => panic!("Decompress failed"),
    };
    let res_exp = (G_X, G_Y);
    assert_eq!(res, res_exp);

    // To Affine
    let p = [
        0x29868c37ceb8e39c,
        0x177be3b49c3f6fa4,
        0x2a3774442bf633f,
        0x47b19a76c8c2990f,
        0x7b92ff367ac68a1f,
        0xb18003a9900fdeb3,
        0xe06693957bcbe9d2,
        0x9e350a911345b6b0,
        0x3,
        0x0,
        0x0,
        0x0,
    ];
    let res = secp256k1_to_affine(&p);
    let res_exp = G;
    assert_eq!(res, res_exp);

    // Is on curve
    let p = IDENTITY;
    let res = secp256k1_is_on_curve(&p);
    assert_eq!(res, false);

    let p = G;
    let res = secp256k1_is_on_curve(&p);
    assert_eq!(res, true);

    // Scalar multiplication
    let s = [0x53abb24c9f99136, 0x3c3ba88ce76f629e, 0xe9056abea1783a93, 0x6841f6b8ac6be1d];
    let p = G;
    let res = match secp256k1_scalar_mul(&s, &p) {
        Some(point) => point,
        None => panic!("Scalar multiplication failed"),
    };
    let res_exp = [
        0xca9cbc09c949b822,
        0xcf7cd8156abf9fc2,
        0x493d8feaee4890a5,
        0xb6da83ed96d53183,
        0x9ba9c4d02851f15f,
        0xc59ee8217ea643ed,
        0x92738c7c8ee06f97,
        0x4f32ad5172c6f18b,
    ];
    assert_eq!(res, res_exp);

    // Double scalar multiplication with G
    let k1 = [0xf447e442a44c829e, 0xe979220cfe9824d3, 0x673913d78b5bdbfe, 0xd961172287f69999];
    let k2 = [0x9249014d999485b7, 0xdfd89459c31678cb, 0x4436e3fc08fe4970, 0x849f0f75e5ce061b];
    let p = [
        0x40f75c3e90ebbf56,
        0x624e6e788fc9bc12,
        0x589431000df07902,
        0x9aef459e48a7ac73,
        0xa67dfc6202a89424,
        0x988adb52057842c0,
        0x7925243213523fe3,
        0xfef27a458a531028,
    ];
    let res = match secp256k1_double_scalar_mul_with_g(&k1, &k2, &p) {
        Some(point) => point,
        None => panic!("Double scalar multiplication with G failed"),
    };
    let res_exp = [
        0xd143c0e9ecf996a3,
        0xd974781400a006bf,
        0xf960eebd7c128a95,
        0x5e44767ac9426e5,
        0x53a5e16a27f9d9e6,
        0xbf5f20add02485f0,
        0x51a51aef05543d52,
        0x5afd5c6d73b4597d,
    ];
    assert_eq!(res, res_exp);

    let k1 = [0xf447e442a44c829e, 0xe979220cfe9824d3, 0x673913d78b5bdbfe, 0xd961172287f69999];
    let k2 = k1;
    let p = G_NEG;
    let res = secp256k1_double_scalar_mul_with_g(&k1, &k2, &p);
    assert_eq!(res, None);

    // Triple scalar multiplication with G
    let k1 = [0xf447e442a44c829e, 0xe979220cfe9824d3, 0x673913d78b5bdbfe, 0xd961172287f69999];
    let k2 = [0x9249014d999485b7, 0xdfd89459c31678cb, 0x4436e3fc08fe4970, 0x849f0f75e5ce061b];
    let k3 = [0xbfa9bf56ca443f1e, 0x9b50eab82f329ea5, 0x758838002e2f0ec7, 0x1fa7537a493bfc54];
    let p1 = [
        0xa788ee5f10cbc291,
        0x6af1ddc9d28a6bab,
        0xff3e4552da155c76,
        0x3c48bf5204cae202,
        0xc0e321b0a95f3718,
        0xd6066c35e911e6f9,
        0x2a2729c989df1b7a,
        0xc164f9a22d75f28a,
    ];
    let p2 = [
        0xba0aef283da9511f,
        0x338fc0e20058abd9,
        0xdbbab22ebbd85b8b,
        0x27f1f6f149df380,
        0xf7071745a8c53811,
        0xd679049d3e9fcaec,
        0x9c7b341d8e786c0b,
        0x9f0cc337af475073,
    ];
    let res = match secp256k1_triple_scalar_mul_with_g(&k1, &k2, &k3, &p1, &p2) {
        Some(point) => point,
        None => panic!("Triple scalar multiplication with G failed"),
    };
    let res_exp = [
        0xb38b093ab1a13d9d,
        0x2131b316f94cbaa,
        0xc0b8f15af154896a,
        0xb02d2c4f67d314e4,
        0x4835bbe53ae1b3c5,
        0x67c8b2325238c219,
        0xe83023f64dff7323,
        0xd0d7b9cce4e97db5,
    ];
    assert_eq!(res, res_exp);

    let k1 = [0xf447e442a44c829e, 0xe979220cfe9824d3, 0x673913d78b5bdbfe, 0xd961172287f69999];
    let k2 = [0xc5ae6c6b7e0ffff2, 0x45f24be02ffc8dd1, 0x4c6376143a5211ff, 0x934f746ebc04b333];
    let k3 = k2;
    let p1 = G;
    let p2 = G;
    let res = secp256k1_triple_scalar_mul_with_g(&k1, &k2, &k3, &p1, &p2);
    assert_eq!(res, None);
}
