use ziskos::ecadd;

use crate::constants::P;

pub fn ecadd_valid_tests() {
    // 𝒪 + 𝒪 = 𝒪
    let p1 = [0, 0, 0, 0, 0, 0, 0, 0];
    let p2 = [0, 0, 0, 0, 0, 0, 0, 0];
    let (p3, error_code) = ecadd(&p1, &p2);
    let p3_expected = [0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(error_code, 0);
    assert_eq!(p3, p3_expected);

    // 𝒪 + P = P
    let p1 = [0, 0, 0, 0, 0, 0, 0, 0];
    let p2 = [1, 0, 0, 0, 2, 0, 0, 0];
    let (p3, error_code) = ecadd(&p1, &p2);
    let p3_expected = [1, 0, 0, 0, 2, 0, 0, 0];
    assert_eq!(error_code, 0);
    assert_eq!(p3, p3_expected);

    // P + 𝒪 = P
    let p1 = [1, 0, 0, 0, 2, 0, 0, 0];
    let p2 = [0, 0, 0, 0, 0, 0, 0, 0];
    let (p3, error_code) = ecadd(&p1, &p2);
    let p3_expected = [1, 0, 0, 0, 2, 0, 0, 0];
    assert_eq!(error_code, 0);
    assert_eq!(p3, p3_expected);

    // P + (-P) = 𝒪
    let p1 = [1, 0, 0, 0, 2, 0, 0, 0];
    let p2 = [1, 0, 0, 0, P[0] - 2, P[1], P[2], P[3]];
    let (p3, error_code) = ecadd(&p1, &p2);
    let p3_expected = [0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(error_code, 0);
    assert_eq!(p3, p3_expected);

    // P + P
    let p1 = [1, 0, 0, 0, 2, 0, 0, 0];
    let p2 = [1, 0, 0, 0, 2, 0, 0, 0];
    let (p3, error_code) = ecadd(&p1, &p2);
    let p3_expected = [
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
    assert_eq!(p3, p3_expected);

    // P + Q when P != Q
    let p1 = [1, 0, 0, 0, 2, 0, 0, 0];
    let p2 = [
        2,
        0,
        0,
        0,
        14190647196187918132,
        5868525459186109257,
        7228818382018665824,
        928517317684515200,
    ];
    let (p3, error_code) = ecadd(&p1, &p2);
    let p3_expected = [
        7242877178936294858,
        16806890525920880627,
        16093854448184277817,
        3259927262867880529,
        14627821532041215758,
        9340993363459877077,
        16126578744131724299,
        3280160564812035186,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(p3, p3_expected);
}

pub fn ecadd_invalid_tests() {
    // P1 not in range
    let p1 = [P[0], P[1], P[2], P[3], 0, 0, 0, 0];
    let p2 = [0, 0, 0, 0, 0, 0, 0, 0];
    let (_, error_code) = ecadd(&p1, &p2);
    assert_eq!(error_code, 1);

    let p1 = [0, 0, 0, 0, P[0], P[1], P[2], P[3]];
    let p2 = [0, 0, 0, 0, 0, 0, 0, 0];
    let (_, error_code) = ecadd(&p1, &p2);
    assert_eq!(error_code, 2);

    // P2 not in range
    let p1 = [0, 0, 0, 0, 0, 0, 0, 0];
    let p2 = [P[0], P[1], P[2], P[3], 0, 0, 0, 0];
    let (_, error_code) = ecadd(&p1, &p2);
    assert_eq!(error_code, 3);

    let p1 = [0, 0, 0, 0, 0, 0, 0, 0];
    let p2 = [0, 0, 0, 0, P[0], P[1], P[2], P[3]];
    let (_, error_code) = ecadd(&p1, &p2);
    assert_eq!(error_code, 4);

    // P1 not in E
    let p1 = [1, 0, 0, 0, 0, 0, 0, 0];
    let p2 = [0, 0, 0, 0, 0, 0, 0, 0];
    let (_, error_code) = ecadd(&p1, &p2);
    assert_eq!(error_code, 5);

    let p1 = [1, 0, 0, 0, 0, 0, 0, 0];
    let p2 = [1, 0, 0, 0, 2, 0, 0, 0];
    let (_, error_code) = ecadd(&p1, &p2);
    assert_eq!(error_code, 5);

    // P2 not in E
    let p1 = [0, 0, 0, 0, 0, 0, 0, 0];
    let p2 = [1, 0, 0, 0, 0, 0, 0, 0];
    let (_, error_code) = ecadd(&p1, &p2);
    assert_eq!(error_code, 6);

    let p1 = [1, 0, 0, 0, 2, 0, 0, 0];
    let p2 = [1, 0, 0, 0, 0, 0, 0, 0];
    let (_, error_code) = ecadd(&p1, &p2);
    assert_eq!(error_code, 6);
}
