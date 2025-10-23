#![no_main]
#![cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
ziskos::entrypoint!(main);

use ziskos::add256::{syscall_add256, SyscallAdd256Params};

const P: [u64; 4] =
    [0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF];

const P_COMP: u64 = 0x1000003D1;

const P_MINUS_ONE: [u64; 4] = [P[0] - 1, P[1], P[2], P[3]];

const P_PLUS_ONE: [u64; 4] = [P[0] + 1, P[1], P[2], P[3]];

const MASK_256: [u64; 4] =
    [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF];

fn main() {
    let mut a: [u64; 4] = [0, 0, 0, 0];
    let mut b: [u64; 4] = [0, 0, 0, 0];
    let mut c: [u64; 4] = [0, 0, 0, 0];

    let mut params = SyscallAdd256Params { a: &mut a, b: &mut b, cin: 0, c: &mut c };

    // arith384_mod test rows: 0-23

    params.a = &[11, 9, 7, 5];
    params.b = &[12, 10, 8, 6];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [23, 19, 15, 11];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    params.a = &[
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    params.b = &[1, 2, 3, 4];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 2, 3, 4];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 1);

    params.a = &[
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFE,
    ];
    params.b = &[1, 0, 0, 0];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 0, 0, 0xFFFF_FFFF_FFFF_FFFF];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 4: Simple addition with carry in
    params.a = &[100, 200, 300, 400];
    params.b = &[50, 75, 125, 175];
    params.cin = 1;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [151, 275, 425, 575];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 5: Zero addition
    params.a = &[0, 0, 0, 0];
    params.b = &[0, 0, 0, 0];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 0, 0, 0];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 6: Zero addition with carry in
    params.a = &[0, 0, 0, 0];
    params.b = &[0, 0, 0, 0];
    params.cin = 1;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [1, 0, 0, 0];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 7: Large numbers without overflow
    params.a = &[
        0x8000_0000_0000_0000,
        0x4000_0000_0000_0000,
        0x2000_0000_0000_0000,
        0x1000_0000_0000_0000,
    ];
    params.b = &[
        0x1000_0000_0000_0000,
        0x2000_0000_0000_0000,
        0x4000_0000_0000_0000,
        0x8000_0000_0000_0000,
    ];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [
        0x9000_0000_0000_0000,
        0x6000_0000_0000_0000,
        0x6000_0000_0000_0000,
        0x9000_0000_0000_0000,
    ];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 8: Overflow in first limb
    params.a = &[0xFFFF_FFFF_FFFF_FFFF, 0, 0, 0];
    params.b = &[1, 0, 0, 0];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 1, 0, 0];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 9: Overflow in second limb
    params.a = &[0, 0xFFFF_FFFF_FFFF_FFFF, 0, 0];
    params.b = &[0, 1, 0, 0];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 0, 1, 0];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 10: Overflow in third limb
    params.a = &[0, 0, 0xFFFF_FFFF_FFFF_FFFF, 0];
    params.b = &[0, 0, 1, 0];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 0, 0, 1];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 11: Cascading carries
    params.a = &[0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0];
    params.b = &[1, 0, 0, 0];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 0, 0, 1];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 12: Adding one to maximum value
    params.a = &[
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    params.b = &[1, 0, 0, 0];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 0, 0, 0];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 1);

    // Test case 13: Powers of 2
    params.a = &[1, 2, 4, 8];
    params.b = &[16, 32, 64, 128];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [17, 34, 68, 136];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 14: Alternating patterns
    params.a = &[
        0xAAAA_AAAA_AAAA_AAAA,
        0x5555_5555_5555_5555,
        0xAAAA_AAAA_AAAA_AAAA,
        0x5555_5555_5555_5555,
    ];
    params.b = &[
        0x5555_5555_5555_5555,
        0xAAAA_AAAA_AAAA_AAAA,
        0x5555_5555_5555_5555,
        0xAAAA_AAAA_AAAA_AAAA,
    ];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 15: Random-like values
    params.a = &[
        0x1234_5678_9ABC_DEF0,
        0xFEDC_BA98_7654_3210,
        0x1111_2222_3333_4444,
        0x4444_5555_6666_7777,
    ];
    params.b = &[
        0x0FED_CBA9_8765_4321,
        0x0123_4567_89AB_CDEF,
        0x9999_AAAA_BBBB_CCCC,
        0x2222_3333_4444_5555,
    ];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [
        0x2222_2222_2222_2211,
        0xFFFF_FFFF_FFFF_FFFF,
        0xAAAA_CCCC_EEEF_1110,
        0x6666_8888_AAAA_CCCC,
    ];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 16: All bits set in one operand
    params.a = &[
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    params.b = &[0, 0, 0, 0];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 17: Small incremental values
    params.a = &[1, 1, 1, 1];
    params.b = &[1, 1, 1, 1];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [2, 2, 2, 2];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 18: Half maximum values
    params.a = &[
        0x7FFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
    ];
    params.b = &[
        0x7FFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
    ];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    // Each limb: 0x7FFF_FFFF_FFFF_FFFF + 0x7FFF_FFFF_FFFF_FFFF = 0xFFFF_FFFF_FFFF_FFFE (no carries)
    let expected_c: [u64; 4] = [
        0xFFFF_FFFF_FFFF_FFFE,
        0xFFFF_FFFF_FFFF_FFFE,
        0xFFFF_FFFF_FFFF_FFFE,
        0xFFFF_FFFF_FFFF_FFFE,
    ];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 19: Edge case with carry propagation
    params.a = &[0xFFFF_FFFF_FFFF_FFFE, 0xFFFF_FFFF_FFFF_FFFF, 0, 0];
    params.b = &[2, 0, 0, 0];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 0, 1, 0];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 20: Sequential numbers
    params.a = &[1, 2, 3, 4];
    params.b = &[5, 6, 7, 8];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [6, 8, 10, 12];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 21: Powers of 10
    params.a = &[10, 100, 1000, 10000];
    params.b = &[1, 10, 100, 1000];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [11, 110, 1100, 11000];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 22: Fibonacci-like sequence
    params.a = &[1, 1, 2, 3];
    params.b = &[5, 8, 13, 21];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [6, 9, 15, 24];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 23: Prime numbers
    params.a = &[2, 3, 5, 7];
    params.b = &[11, 13, 17, 19];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [13, 16, 22, 26];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 24: Hex patterns
    params.a = &[0xDEAD_BEEF, 0xCAFE_BABE, 0xFACE_B00C, 0xC0DE_D00D];
    params.b = &[0xBAD_C0DE, 0xFEED_FACE, 0x1337_BEEF, 0xDEAD_BEEF];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0xEA5B7FCD, 0x1C9ECB58C, 0x10E066EFB, 0x19F8C8EFC];

    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 25: Single bit set in each limb
    params.a = &[
        0x0000_0000_0000_0001,
        0x0000_0000_0000_0002,
        0x0000_0000_0000_0004,
        0x0000_0000_0000_0008,
    ];
    params.b = &[
        0x0000_0000_0000_0010,
        0x0000_0000_0000_0020,
        0x0000_0000_0000_0040,
        0x0000_0000_0000_0080,
    ];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [
        0x0000_0000_0000_0011,
        0x0000_0000_0000_0022,
        0x0000_0000_0000_0044,
        0x0000_0000_0000_0088,
    ];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 26: High bit set
    params.a = &[
        0x8000_0000_0000_0000,
        0x8000_0000_0000_0000,
        0x8000_0000_0000_0000,
        0x8000_0000_0000_0000,
    ];
    params.b = &[
        0x7FFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
    ];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 27: Carry from first to last limb
    params.a = &[
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
    ];
    params.b = &[0, 0, 0, 0x8000_0000_0000_0000];
    params.cin = 1;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 0, 0, 0];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 1);

    // Test case 28: Alternating high and low bits
    params.a = &[
        0xF0F0_F0F0_F0F0_F0F0,
        0x0F0F_0F0F_0F0F_0F0F,
        0xF0F0_F0F0_F0F0_F0F0,
        0x0F0F_0F0F_0F0F_0F0F,
    ];
    params.b = &[
        0x0F0F_0F0F_0F0F_0F0F,
        0xF0F0_F0F0_F0F0_F0F0,
        0x0F0F_0F0F_0F0F_0F0F,
        0xF0F0_F0F0_F0F0_F0F0,
    ];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 29: Large round numbers
    params.a = &[1000000, 2000000, 3000000, 4000000];
    params.b = &[500000, 750000, 1250000, 1750000];
    params.cin = 0;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [1500000, 2750000, 4250000, 5750000];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 30: Maximum possible carry chain with carry in
    params.a = &[
        0xFFFF_FFFF_FFFF_FFFE,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    params.b = &[0, 0, 0, 0];
    params.cin = 1;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 31: Boundary condition - almost overflow with carry in
    params.a = &[
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFE,
    ];
    params.b = &[0, 0, 0, 0];
    params.cin = 1;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 0, 0, 0xFFFF_FFFF_FFFF_FFFF];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    // Test case 32: Mixed carry scenarios
    params.a = &[
        0x1111_1111_1111_1111,
        0x2222_2222_2222_2222,
        0x3333_3333_3333_3333,
        0x4444_4444_4444_4444,
    ];
    params.b = &[
        0xEEEE_EEEE_EEEE_EEEE,
        0xDDDD_DDDD_DDDD_DDDD,
        0xCCCC_CCCC_CCCC_CCCC,
        0xBBBB_BBBB_BBBB_BBBB,
    ];
    params.cin = 1;
    let cout = syscall_add256(&mut params);
    let expected_c: [u64; 4] = [0, 0, 0, 0];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 1);

    // Test case 33: Testing corner case values
    params.a = &[42, 1337, 0xDEADBEEF, 0x8BADF00D];
    params.b = &[13, 42, 0x12345678, 0x87654321];
    params.cin = 0;
    let cout = syscall_add256(&mut params);

    let mut expected_c: [u64; 4] = [0x37, 0x563, 0xF0E21567, 0x11313332E];
    assert_eq!(params.c, &expected_c);
    assert_eq!(cout, 0);

    for i in 0..(1 << 21) {
        let a: [u64; 4] = [42, 1337, 0xDEADBEEF, i];
        let b: [u64; 4] = [13, 42, 0x12345678, 2 * i];
        let mut c: [u64; 4] = [0, 0, 0, 0];
        let mut params = SyscallAdd256Params { a: &a, b: &b, cin: 0, c: &mut c };
        let cout = syscall_add256(&mut params);
        // assert_eq!(params.c[3], 3 * i);
        // assert_eq!(params.c[2], 0xF0E21567);
        // assert_eq!(params.c[1], 0x563);
        // assert_eq!(params.c[0], 0x37);
        expected_c[3] = 3 * i;
        assert_eq!(params.c, &expected_c);
        assert_eq!(cout, 0);
    }

    test_secp256k1_fp();
}

fn test_secp256k1_fp() {
    assert_eq!(secp256k1_fp_reduce(&[0, 0, 0, 0]), [0, 0, 0, 0]);

    assert_eq!(secp256k1_fp_reduce(&P_MINUS_ONE), P_MINUS_ONE);

    assert_eq!(secp256k1_fp_reduce(&P), [0, 0, 0, 0]);

    assert_eq!(secp256k1_fp_reduce(&P_PLUS_ONE), [1, 0, 0, 0]);

    assert_eq!(secp256k1_fp_reduce(&MASK_256), [4294968272, 0, 0, 0]);

    // Test case: P - 1 + P - 1 = 2P - 2 = P - 2 (mod P)
    let p_minus_1 = [P[0] - 1, P[1], P[2], P[3]];
    let result = secp256k1_fp_add(&p_minus_1, &p_minus_1);
    let expected = [P[0] - 2, P[1], P[2], P[3]];
    assert_eq!(result, expected);

    // Test case: P - 1 + 1 = 0 (mod P)
    let result = secp256k1_fp_add(&p_minus_1, &[1, 0, 0, 0]);
    assert_eq!(result, [0, 0, 0, 0]);

    // Test case: P - 1 + 2 = 1 (mod P)
    let result = secp256k1_fp_add(&p_minus_1, &[2, 0, 0, 0]);
    assert_eq!(result, [1, 0, 0, 0]);

    // Test case: Large values that cause overflow
    let large1 = [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0];
    let large2 = [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0];
    let result = secp256k1_fp_add(&large1, &large2);
    assert_eq!(result, [0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 1, 0]);

    // Test case: Adding P to any value should give the same value
    let test_val = [0x123456789ABCDEF0, 0xFEDCBA9876543210, 0x1111222233334444, 0x4444555566667777];
    let result = secp256k1_fp_add(&test_val, &P);
    assert_eq!(result, test_val);

    // Test case: Edge case near modulus
    let near_p = [P[0] - 100, P[1], P[2], P[3]];
    let small_val = [200, 0, 0, 0];
    let result = secp256k1_fp_add(&near_p, &small_val);
    let expected = [100, 0, 0, 0]; // (P - 100 + 200) mod P = 100 mod P = 100
    assert_eq!(result, expected);

    // Test case: Maximum possible values
    let max_val = [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF];
    let result = secp256k1_fp_add(&max_val, &[1, 0, 0, 0]);
    let expected = [P_COMP, 0, 0, 0];
    assert_eq!(result, expected);

    // Test case: Multiple P_COMP additions
    let test_val = [P_COMP - 1, 0, 0, 0];
    let result = secp256k1_fp_add(&max_val, &test_val);
    let expected = [0x2000007a0, 0, 0, 0];
    assert_eq!(result, expected);

    // Test case: Verify P_COMP correctness
    // P_COMP should equal 2^256 - P
    let mut params =
        SyscallAdd256Params { a: &P, b: &[P_COMP, 0, 0, 0], cin: 0, c: &mut [0, 0, 0, 0] };
    let cout = syscall_add256(&mut params);
    assert_eq!(*params.c, [0, 0, 0, 0]);
    assert_eq!(cout, 1); // Should overflow to exactly 2^256

    // Test case: Associativity check
    let a = [0x123456789ABCDEF0, 0, 0, 0];
    let b = [0xFEDCBA9876543210, 0, 0, 0];
    let c = [0x1111222233334444, 0, 0, 0];

    let ab_c = secp256k1_fp_add(&secp256k1_fp_add(&a, &b), &c);
    let a_bc = secp256k1_fp_add(&a, &secp256k1_fp_add(&b, &c));
    assert_eq!(ab_c, a_bc);

    // Test case: Commutativity check
    let x = [0xDEADBEEFCAFEBABE, 0x123456789ABCDEF0, 0, 0];
    let y = [0xFACEB00CC0DED00D, 0xFEDCBA9876543210, 0, 0];

    let xy = secp256k1_fp_add(&x, &y);
    let yx = secp256k1_fp_add(&y, &x);
    assert_eq!(xy, yx);

    // Test case: Identity element
    let test_val = [0xABCDEF0123456789, 0x9876543210FEDCBA, 0x1234567890ABCDEF, 0xFEDCBA0987654321];
    let result = secp256k1_fp_add(&test_val, &[0, 0, 0, 0]);
    assert_eq!(result, test_val);
}

pub fn secp256k1_fp_add_with_pcomp(x: &[u64; 4]) -> [u64; 4] {
    let mut params =
        SyscallAdd256Params { a: x, b: &[P_COMP, 0, 0, 0], cin: 0, c: &mut [0, 0, 0, 0] };
    syscall_add256(&mut params);
    *params.c
}

pub fn secp256k1_fp_reduce(x: &[u64; 4]) -> [u64; 4] {
    if lt(x, &P) {
        return *x;
    }

    // Since p <= x < 2·p (because 2·p > 2^256), computing x (mod p) = x - p = x + (2^256 - p) (mod 2^256)
    secp256k1_fp_add_with_pcomp(x)
}

pub fn secp256k1_fp_add(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    // x + y
    let mut params = SyscallAdd256Params { a: x, b: y, cin: 0, c: &mut [0, 0, 0, 0] };
    let cout = syscall_add256(&mut params);
    let mut s = *params.c;

    // Let s = (x + y) mod 2^256
    // There are 4 possible cases:
    // 1. If s < p and cout == 0, then result = s
    // 2. If s >= p and cout == 0, then result = s (mod p)
    // 3. If s < p and cout == 1, then result = s
    // 4. If s >= p and cout == 1, this is not possible
    if cout == 0 {
        if !lt(&s, &P) {
            s = secp256k1_fp_add_with_pcomp(&s);
        }
        return s;
    }

    // Here we have x + y = s + 2^256, with s < p
    // Since 2^256 = p_comp (mod p), we only need to compute (s + p_comp) mod p
    // Moreover, since s < p, we have s + p_comp <= p - 1 + p_comp = 2^256 - 1
    params.a = &s;
    params.b = &[P_COMP, 0, 0, 0];
    syscall_add256(&mut params);
    *params.c
}

fn lt(x: &[u64], y: &[u64]) -> bool {
    let len = x.len();
    assert_eq!(len, y.len(), "x and y must have the same length");

    for i in (0..len).rev() {
        if x[i] < y[i] {
            return true;
        } else if x[i] > y[i] {
            return false;
        }
    }
    false
}
