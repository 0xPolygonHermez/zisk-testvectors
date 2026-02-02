use ziskos::zisklib::secp256r1_ecdsa_verify;

pub fn ecdsa_tests() {
    // Verify (valids)
    let pk = [
        0x69c8c4df6c732838,
        0x2903269919f70860,
        0xdcfe467828128bad,
        0x2927b10512bae3ed,
        0x8d1a974e7341513e,
        0x6766b3d968500155,
        0x921fb1498a60f460,
        0xc7787964eaac00e5,
    ];
    let z = [0x7a419feca605023, 0x36e7c32b270c88, 0xed4361f59422a1e3, 0xbb5a52f42f9c9261];
    let r = [0xb8cc6af9bd5c2e18, 0xffe50d85a1eee859, 0x80a6d9d1190a436e, 0x2ba3a8be6b94d5ec];
    let s = [0x77a67f79e6fadd76, 0x525fe710fab9aa7c, 0x3c7b11eb6c4e0ae7, 0x4cd60b855d442f5b];
    let res = secp256r1_ecdsa_verify(&pk, &z, &r, &s);
    assert!(res);
}
