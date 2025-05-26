use ziskos::ecmul;

use crate::constants::{P, R};

pub fn ecmul_valid_tests() {
    // 0·𝒪 = 𝒪
    let k = [0, 0, 0, 0];
    let p = [0, 0, 0, 0, 0, 0, 0, 0];
    let (q, error_code) = ecmul(&k, &p);
    let q_expected = [0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(error_code, 0);
    assert_eq!(q, q_expected);

    // k·𝒪 = 𝒪, where k != 0
    let k = [1, 0, 0, 0];
    let p = [0, 0, 0, 0, 0, 0, 0, 0];
    let (q, error_code) = ecmul(&k, &p);
    let q_expected = [0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(error_code, 0);
    assert_eq!(q, q_expected);

    // 0·P = 𝒪, where P != 𝒪
    let k = [0, 0, 0, 0];
    let p = [1, 0, 0, 0, 2, 0, 0, 0];
    let (q, error_code) = ecmul(&k, &p);
    let q_expected = [0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(error_code, 0);
    assert_eq!(q, q_expected);

    // k·P when k != 0 and P != 𝒪
    let k = [1, 0, 0, 0];
    let p = [1, 0, 0, 0, 2, 0, 0, 0];
    let (q, error_code) = ecmul(&k, &p);
    let q_expected = [1, 0, 0, 0, 2, 0, 0, 0];
    assert_eq!(error_code, 0);
    assert_eq!(q, q_expected);

    let k = [2, 0, 0, 0];
    let p = [1, 0, 0, 0, 2, 0, 0, 0];
    let (q, error_code) = ecmul(&k, &p);
    let q_expected = [
        15258768114343989203,
        15670299818918878376,
        11206368038416291205,
        217937391675185666,
        18392348460446163652,
        7540895263331946439,
        16682564020534680586,
        1580046089645096082,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(q, q_expected);

    let k = [65, 0, 0, 0];
    let p = [1, 0, 0, 0, 2, 0, 0, 0];
    let (q, error_code) = ecmul(&k, &p);
    let q_expected = [
        8195076390219496543,
        8289391821638708272,
        18037447704984080797,
        3374890662841577118,
        670674282718561046,
        7579481645594290350,
        2301945329315106112,
        2687697338620005361,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(q, q_expected);

    let k = [10000000089, 0, 0, 0];
    let p = [1, 0, 0, 0, 2, 0, 0, 0];
    let (q, error_code) = ecmul(&k, &p);
    let q_expected = [
        1042773852928783270,
        6268184252792522204,
        6870116993717456050,
        759593353979327191,
        387106785234510255,
        2400345854079117057,
        12133110714749551147,
        3407518127655649593,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(q, q_expected);

    let k = [R[0] - 1, R[1], R[2], R[3]];
    let p = [1, 0, 0, 0, 2, 0, 0, 0];
    let (q, error_code) = ecmul(&k, &p);
    let q_expected = [1, 0, 0, 0, P[0] - 2, P[1], P[2], P[3]];
    assert_eq!(error_code, 0);
    assert_eq!(q, q_expected);

    let k = [18446744073709551615, 18446744073709551615, 18446744073709551615, 3458764513820540927];
    let p = [1, 0, 0, 0, 2, 0, 0, 0];
    let (q, error_code) = ecmul(&k, &p);
    let q_expected = [
        1462628685044502770,
        7099398193046143051,
        15916049576335382296,
        1281076595997227309,
        14778535986360639515,
        4771694179072732811,
        13682343422956937683,
        3178887445732921185,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(q, q_expected);
}

pub fn ecmul_invalid_tests() {
    // P not in range
    let k = [0, 0, 0, 0];
    let p = [P[0], P[1], P[2], P[3], 0, 0, 0, 0];
    let (_, error_code) = ecmul(&k, &p);
    assert_eq!(error_code, 1);

    let k = [0, 0, 0, 0];
    let p = [0, 0, 0, 0, P[0], P[1], P[2], P[3]];
    let (_, error_code) = ecmul(&k, &p);
    assert_eq!(error_code, 2);

    // k not in range
    let k = [R[0], R[1], R[2], R[3]];
    let p = [0, 0, 0, 0, 0, 0, 0, 0];
    let (_, error_code) = ecmul(&k, &p);
    assert_eq!(error_code, 3);

    // P not in E
    let k = [0, 0, 0, 0];
    let p = [1, 0, 0, 0, 0, 0, 0, 0];
    let (_, error_code) = ecmul(&k, &p);
    assert_eq!(error_code, 4);
}
