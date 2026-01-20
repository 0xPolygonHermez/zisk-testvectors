// Auto-generated Prover Killer test cases

#![no_main]
ziskos::entrypoint!(main);

use ziskos::zisklib::{modexp, U256};

fn main() {
    // Test #0: test_worst_compute.py::test_worst_modexp[fork_Prague-benchmark-gas-value_10M-blockchain_test_from_state_test-mod_vul_marius_1_even]
    let base = vec![U256::from_u64s(&[0xffffff, 0x0, 0x0, 0x0])];
    let exp = vec![
        0xffffff4000007d7d,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xcffffffff,
        0x0,
        0x0,
        0x0,
        0x2100000000,
        0x0,
        0x0,
        0x0,
        0x300000000,
        0x0,
        0x0,
        0x0,
        0x7d7d7d5b00000000,
        0x7d7d7d7d7d7d7d7d,
        0x877d7d827d407d79,
        0x7d83828282348286,
        0xffffffe000007d7d,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xff,
        0x0,
        0x0,
        0x0,
    ];
    let modulus = vec![U256::from_u64s(&[0x82348286877d7d82, 0x7d838282, 0x0, 0x0])];
    for _ in 0..400 {
        modexp(&base, &exp, &modulus);
    }
    let result = modexp(&base, &exp, &modulus);
    let expected = vec![U256::from_u64s(&[0x17859b5e178d3ab9, 0x36a385a4, 0x0, 0x0])];
    assert_eq!(result.len(), 1);
    assert_eq!(result, expected);
}
