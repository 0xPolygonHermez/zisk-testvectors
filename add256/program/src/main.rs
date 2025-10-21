#![no_main]
#![cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
ziskos::entrypoint!(main);

use ziskos::add256::{syscall_add256, SyscallAdd256Params};

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
}
