#![cfg(all(target_os = "zkvm", target_vendor = "zisk"))]

use std::arch::asm;
use std::num::Wrapping;

pub fn diagnostic_riscv_ima() {
    // minu belongs to Zbb extension, not IMA

    // {
    //     let a: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    //     let b: u64 = 0xFFFF_FFFF_FFFF_FFFE;
    //     let c: u64;

    //     // Use inline assembly to ensure minu instruction is called
    //     unsafe {
    //         std::arch::asm!(
    //             "minu {result}, {input1}, {input2}",
    //             result = out(reg) c,
    //             input1 = in(reg) a,
    //             input2 = in(reg) b,
    //         );
    //     }

    //     assert_eq!(c, 0xFFFF_FFFF_FFFF_FFFE);
    // }

    diagnostic_riscv_ima_branch();

    or(0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF);
    or(0xFFFF_FFFF_FFFF_FFF1, 0xFFFF_FFFF_FFFF_FFFE, 0xFFFF_FFFF_FFFF_FFFF);
    or(0xFFFF_0000_FFFF_0000, 0xFFFF_0000_0000_0000, 0xFFFF_0000_FFFF_0000);
    or(0x0000_0000_0000_0000, 0xFFFF_0000_0000_0000, 0xFFFF_0000_0000_0000);
    or(0x0000_0000_0000_0000, 0x0000_0000_0000_0000, 0x0000_0000_0000_0000);

    xor(0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x0000_0000_0000_0000);
    xor(0xFFFF_0000_FFFF_0000, 0xFFFF_FFFF_0000_0000, 0x0000_FFFF_FFFF_0000);
    xor(0x0000_0000_0000_0000, 0xFFFF_FFFF_0000_0000, 0xFFFF_FFFF_0000_0000);
    xor(0x0000_0000_0000_0000, 0x0000_0000_0000_0000, 0x0000_0000_0000_0000);

    and(0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF);
    and(0xFFFF_0000_FFFF_0000, 0xFFFF_FFFF_0000_0000, 0xFFFF_0000_0000_0000);
    and(0x0000_0000_0000_0000, 0xFFFF_FFFF_0000_0000, 0x0000_0000_0000_0000);
    and(0x0000_0000_0000_0000, 0x0000_0000_0000_0000, 0x0000_0000_0000_0000);

    div(0xFFFF_FFFF_FFFF, 0x1_0000_0000, 0xFFFF);
    divu(0xFFFF_FFFF_FFFF_FFFF, 0x1_0000_0000, 0xFFFF_FFFF);
    div_w(0xFF_FFFF, 0x1_0000, 0xFF);
    divu_w(0xFF_FFFF, 0x1_0000, 0xFF);

    rem(0xFFFF_0000_FFFF, 0x1_0000_0000, 0xFFFF);
    remu(0xFFFF_0000_FFFF, 0x1_0000_0000, 0xFFFF);
    rem_w(0xFF_00FF, 0x1_0000, 0xFF);
    remu_w(0xFF_00FF, 0x1_0000, 0xFF);

    mul(0xFFFF_FFFF, 0x1_0000, 0xFFFF_FFFF_0000);
    mulh(0xFFFF_FFFF, 0x1_0000, 0x0);
    mulh(0xFFFF_FFFF_0000, 0x1_0000_0000, 0xFFFF);
    muluh(0xFFFF_FFFF_0000_0000, 0x1_0000_0000, 0xFFFF_FFFF);
    mulsuh(0xFFFF_FFFF_FFFF_FFFFu64 as i64, 0x1, 0xFFFF_FFFF_FFFF_FFFFu64 as i64);
    mul_w(0xFFFF, 0x100, 0xFF_FF00);

    sll_w(0x1_0000, 2, 0x4_0000);
    srl_w(0x4000_0000, 2, 0x1000_0000);
    srl_w(0x8000_0000, 0, 0xFFFF_FFFF_8000_0000);
    sra_w(0x8000_0000, 0, 0xFFFF_FFFF_8000_0000);

    add_w(0, 0, 0);
    add_w(1, 2, 3);
    add_w(2, 2, 4);
    add_w(0xFFFF, 0x1, 0x1_0000);
    add_w(0xFFFF_FFFF, 0x1, 0);

    sub_w(0, 0, 0);
    sub_w(3, 2, 1);
    sub_w(0x1_0000, 1, 0xFFFF);
    sub_w(0x1_0000, 0x1, 0xFFFF);
    sub_w(0, 0x1, 0xFFFF_FFFF_FFFF_FFFF);

    amomax_d(0x0000_0001, 0x0000_0002, 0x0000_0002);
    amomin_d(0x0000_0001, 0x0000_0002, 0x0000_0001);
    amomaxu_d(0x0000_0001, 0x0000_0002, 0x0000_0002);
    amominu_d(0x0000_0001, 0x0000_0002, 0x0000_0001);

    amomax_w(0x0000_0001, 0x0000_0002, 0x0000_0002);
    amomin_w(0x0000_0001, 0x0000_0002, 0x0000_0001);
    amomaxu_w(0x0000_0001, 0x0000_0002, 0x0000_0002);
    amominu_w(0x0000_0001, 0x0000_0002, 0x0000_0001);

    amoand_d(0x0000_0001, 0x0000_0002, 0x0000_0000);
    amoor_d(0x0000_0001, 0x0000_0002, 0x0000_0003);
    amoxor_d(0x1000_0001, 0x1000_0002, 0x0000_0003);

    amoand_w(0x0000_0000, 0x0000_0000, 0x0000_0000);
    amoand_w(0x0000_0001, 0x0000_0002, 0x0000_0000);
    amoand_w(0x0000_FFFF, 0x0000_FF00, 0x0000_FF00);
    amoand_w(0xFF00_FF00, 0x0000_FFFF, 0x0000_FF00);
    amoand_w(0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF);

    amoor_w(0x0000_0000, 0x0000_0000, 0x0000_0000);
    amoor_w(0x0000_0001, 0x0000_0002, 0x0000_0003);
    amoor_w(0x0000_FF00, 0x00FF_0000, 0x00FF_FF00);
    amoor_w(0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF);

    amoxor_w(0x0000_0000, 0x0000_0000, 0x0000_0000);
    amoxor_w(0x1000_0001, 0x1000_0002, 0x0000_0003);
    amoxor_w(0xFFFF_0000, 0xFF00_FF00, 0x00FF_FF00);
    amoxor_w(0xFFFF_FFFF, 0xFFFF_FFFF, 0x0000_0000);

    amoadd_d(0, 0, 0);
    amoadd_d(0, 1, 1);
    amoadd_d(1, 2, 3);
    amoadd_d(2, 2, 4);
    amoadd_d(0xFFFF_FFFF_FFFF_0000, 0xFFFF, 0xFFFF_FFFF_FFFF_FFFF);

    amoadd_w(0, 0, 0);
    amoadd_w(0, 1, 1);
    amoadd_w(1, 2, 3);
    amoadd_w(2, 2, 4);
    amoadd_w(0xFFFF_0000, 0xFFFF, 0xFFFF_FFFF);

    amoswap_d(1, 2, 1);
    amoswap_d(0, 0xFFFF_FFFF_FFFF_FFFF, 0);
    amoswap_d(0xFFFF_FFFF_FFFF_FFFF, 0, 0xFFFF_FFFF_FFFF_FFFF);

    amoswap_w(1, 2, 1);
    amoswap_w(0, 0xFFFF_FFFF, 0);
    amoswap_w(0xFFFF_FFFF, 0, 0xFFFF_FFFF);

    signextend_b(127, 127);
    signextend_b(1, 1);
    signextend_b(0, 0);
    signextend_b(-1, -1);
    signextend_b(-128, -128);

    signextend_h(32767, 32767);
    signextend_h(1, 1);
    signextend_h(0, 0);
    signextend_h(-1, -1);
    signextend_h(-32768, -32768);

    signextend_w(2147483647, 2147483647);
    signextend_w(1, 1);
    signextend_w(0, 0);
    signextend_w(-1, -1);
    signextend_w(-2147483648, -2147483648);

    // TODO: not mapped from RISCV to ZisK
    // leu, le, ltu_w, lt_w, eq_w, leu_w, le_w, mulu

    // TODO: they require Zbb extension
    // minu, min, maxu, max,

    // arith384_mod, bls12_381_curve_add, bls12_381_curve_dbl, bls12_381_complex_add, bls12_381_complex_sub, bls12_381_complex_mul, add256, keccak, arith256, arith256_mod, secp256k1_add, secp256k1_dbl, sha256, bn254_curve_add, bn254_curve_dbl, bn254_complex_add, bn254_complex_sub, bn254_complex_mul, halt, ]

    println!("diagnostic_riscv_ima() success");
}

/******************/
/* or / xor / and */
/******************/

// or (RISCV) -> or (ZisK)
fn or(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    c = a | b;

    // // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "or {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// xor (RISCV) -> xor (ZisK)
fn xor(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    c = a ^ b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "xor {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// and (RISCV) -> and (ZisK)
fn and(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    c = a & b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "and {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

/*******/
/* div */
/*******/

// div (RISCV) -> div (ZisK)
fn div(input_a: i64, input_b: i64, expected_c: i64) {
    let a: i64 = input_a;
    let b: i64 = input_b;
    let c: i64;
    c = a / b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "divu {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// divu (RISCV) -> divu (ZisK)
fn divu(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    c = a / b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "divu {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// divw (RISCV) -> div_w (ZisK)
fn div_w(input_a: i32, input_b: i32, expected_c: i32) {
    let a: i32 = input_a;
    let b: i32 = input_b;
    let c: i32;
    c = a / b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "divw {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// divuw (RISCV) -> divu_w (ZisK)
fn divu_w(input_a: u32, input_b: u32, expected_c: u32) {
    let a: u32 = input_a;
    let b: u32 = input_b;
    let c: u32;
    c = a / b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "divuw {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

/*******/
/* rem */
/*******/

// rem (RISCV) -> rem (ZisK)
fn rem(input_a: i64, input_b: i64, expected_c: i64) {
    let a: i64 = input_a;
    let b: i64 = input_b;
    let c: i64;
    c = a % b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "rem {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// remu (RISCV) -> remu (ZisK)
fn remu(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    c = a % b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "remu {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// remw (RISCV) -> rem_w (ZisK)
fn rem_w(input_a: i32, input_b: i32, expected_c: i32) {
    let a: i32 = input_a;
    let b: i32 = input_b;
    let c: i32;
    c = a % b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "remw {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// remu_w (RISCV) -> remu_w (ZisK)
fn remu_w(input_a: u32, input_b: u32, expected_c: u32) {
    let a: u32 = input_a;
    let b: u32 = input_b;
    let c: u32;
    c = a % b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "remuw {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

/*******/
/* mul */
/*******/

// mul (RISCV) -> mul (ZisK)
fn mul(input_a: i64, input_b: i64, expected_c: i64) {
    let a: i64 = input_a;
    let b: i64 = input_b;
    let c: i64;
    c = a * b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    /*unsafe {
        std::arch::asm!(
            "mul {result}, {input1}, {input2}",
            result = out(reg) c,
            input1 = in(reg) a,
            input2 = in(reg) b,
        );
    }*/

    assert_eq!(c, expected_c); // Check we branched correctly
}

// mulh (RISCV) -> mulh (ZisK)
fn mulh(input_a: i64, input_b: i64, expected_c: i64) {
    let a: i64 = input_a;
    let b: i64 = input_b;
    let c: i64;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    unsafe {
        std::arch::asm!(
            "mulh {result}, {input1}, {input2}",
            result = out(reg) c,
            input1 = in(reg) a,
            input2 = in(reg) b,
        );
    }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// mulhu (RISCV) -> muluh (ZisK)
fn muluh(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    unsafe {
        std::arch::asm!(
            "mulhu {result}, {input1}, {input2}",
            result = out(reg) c,
            input1 = in(reg) a,
            input2 = in(reg) b,
        );
    }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// mulhsu (RISCV) -> mulsuh (ZisK)
fn mulsuh(input_a: i64, input_b: u64, expected_c: i64) {
    let a: i64 = input_a;
    let b: u64 = input_b;
    let c: i64;
    //c = a * b as i64;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    unsafe {
        std::arch::asm!(
            "mulhsu {result}, {input1}, {input2}",
            result = out(reg) c,
            input1 = in(reg) a,
            input2 = in(reg) b,
        );
    }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// mulw (RISCV) -> mul_w (ZisK)
fn mul_w(input_a: i32, input_b: i32, expected_c: i32) {
    let a: i32 = input_a;
    let b: i32 = input_b;
    let c: i32;
    c = a * b;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    /*unsafe {
        std::arch::asm!(
            "mulw {result}, {input1}, {input2}",
            result = out(reg) c,
            input1 = in(reg) a,
            input2 = in(reg) b,
        );
    }*/

    assert_eq!(c, expected_c); // Check we branched correctly
}

// fn signextend_b(input_a: i8, expected: i64) {
//     let a: i8 = input_a;
//     let c: i64;

//     // Use RISCV inline assembly to ensure ZisK instruction is called
//     unsafe {
//         std::arch::asm!(
//             "lb {result}, {input1}",
//             result = out(reg) c,
//             input1 = in(reg) a,
//         );
//     }

//     assert_eq!(c, expected);
// }

/*********/
/* shift */
/*********/

// sllw (RISCV) -> sll_w (ZisK)
fn sll_w(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    c = ((Wrapping(a as u32) << (b & 0x3f) as usize).0 as i32) as u64;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "sllw {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }
    println!("sll_w: {} << {} = {}", a, b, c);

    assert_eq!(c, expected_c); // Check we branched correctly
}

// srlw (RISCV) -> srl_w (ZisK)
fn srl_w(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    c = ((Wrapping(a as u32) >> (b & 0x3f) as usize).0 as i32) as u64;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "srlw {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

// sraw (RISCV) -> sra_w (ZisK)
fn sra_w(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    c = (Wrapping(a as i32) >> (b & 0x3f) as usize).0 as u64;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "sraw {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

/*************/
/* add / sub */
/*************/

// subw (RISCV) -> sub_w (ZisK)
fn sub_w(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    c = (Wrapping(a as i32) - Wrapping(b as i32)).0 as u64;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "subw {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}
// addw (RISCV) -> add_w (ZisK)
fn add_w(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    c = (Wrapping(a as i32) + Wrapping(b as i32)).0 as u64;

    // Use RISCV inline assembly to ensure ZisK instruction is called
    // unsafe {
    //     std::arch::asm!(
    //         "addw {result}, {input1}, {input2}",
    //         result = out(reg) c,
    //         input1 = in(reg) a,
    //         input2 = in(reg) b,
    //     );
    // }

    assert_eq!(c, expected_c); // Check we branched correctly
}

/*******************/
/* amomin / amomax */
/*******************/

fn amomax_d(input_a: i64, input_b: i64, expected_c: i64) {
    let a: i64 = input_a;
    let b: i64 = input_b;
    let c: i64;
    unsafe {
        asm!(
            "amomax.d {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amomin_d(input_a: i64, input_b: i64, expected_c: i64) {
    let a: i64 = input_a;
    let b: i64 = input_b;
    let c: i64;
    unsafe {
        asm!(
            "amomin.d {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amomaxu_d(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    unsafe {
        asm!(
            "amomaxu.d {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amominu_d(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    unsafe {
        asm!(
            "amominu.d {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amomax_w(input_a: i32, input_b: i32, expected_c: i32) {
    let a: i32 = input_a;
    let b: i32 = input_b;
    let c: i32;
    unsafe {
        asm!(
            "amomax.w {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amomin_w(input_a: i32, input_b: i32, expected_c: i32) {
    let a: i32 = input_a;
    let b: i32 = input_b;
    let c: i32;
    unsafe {
        asm!(
            "amomin.w {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amomaxu_w(input_a: u32, input_b: u32, expected_c: u32) {
    let a: u32 = input_a;
    let b: u32 = input_b;
    let c: u32;
    unsafe {
        asm!(
            "amomaxu.w {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amominu_w(input_a: u32, input_b: u32, expected_c: u32) {
    let a: u32 = input_a;
    let b: u32 = input_b;
    let c: u32;
    unsafe {
        asm!(
            "amominu.w {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

/***************************/
/* amoand / amoor / amoxor */
/***************************/

fn amoand_d(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    unsafe {
        asm!(
            "amoand.d {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amoor_d(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    unsafe {
        asm!(
            "amoor.d {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amoxor_d(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    unsafe {
        asm!(
            "amoxor.d {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amoand_w(input_a: u32, input_b: u32, expected_c: u32) {
    let a: u32 = input_a;
    let b: u32 = input_b;
    let c: u32;
    unsafe {
        asm!(
            "amoand.w {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amoor_w(input_a: u32, input_b: u32, expected_c: u32) {
    let a: u32 = input_a;
    let b: u32 = input_b;
    let c: u32;
    unsafe {
        asm!(
            "amoor.w {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amoxor_w(input_a: u32, input_b: u32, expected_c: u32) {
    let a: u32 = input_a;
    let b: u32 = input_b;
    let c: u32;
    unsafe {
        asm!(
            "amoxor.w {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

/**********/
/* amoadd */
/**********/

fn amoadd_d(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    unsafe {
        asm!(
            "amoadd.d {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amoadd_w(input_a: u32, input_b: u32, expected_c: u32) {
    let a: u32 = input_a;
    let b: u32 = input_b;
    let c: u32;
    unsafe {
        asm!(
            "amoadd.w {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

/***********/
/* amoswap */
/***********/

fn amoswap_d(input_a: u64, input_b: u64, expected_c: u64) {
    let a: u64 = input_a;
    let b: u64 = input_b;
    let c: u64;
    unsafe {
        asm!(
            "amoswap.d {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

fn amoswap_w(input_a: u32, input_b: u32, expected_c: u32) {
    let a: u32 = input_a;
    let b: u32 = input_b;
    let c: u32;
    unsafe {
        asm!(
            "amoswap.w {result}, {value}, ({ptr})",
            result = out(reg) c,
            value = in(reg) a,
            ptr = in(reg) &b,
        );
    }
    assert_eq!(c, input_b);
    assert_eq!(b, expected_c);
}

/**************/
/* signextend */
/**************/

fn signextend_b(input_a: i8, expected_c: i64) {
    let a: i8 = input_a;
    let c: i64;
    unsafe {
        asm!(
            "lb {result}, 0({ptr})",
            result = out(reg) c,
            ptr = in(reg) &a,
        );
    }
    assert_eq!(c, expected_c);
}

fn signextend_h(input_a: i16, expected_c: i64) {
    let a: i16 = input_a;
    let c: i64;
    unsafe {
        asm!(
            "lh {result}, 0({ptr})",
            result = out(reg) c,
            ptr = in(reg) &a,
        );
    }
    assert_eq!(c, expected_c);
}

fn signextend_w(input_a: i32, expected_c: i64) {
    let a: i32 = input_a;
    let c: i64;
    unsafe {
        asm!(
            "lw {result}, 0({ptr})",
            result = out(reg) c,
            ptr = in(reg) &a,
        );
    }
    assert_eq!(c, expected_c);
}

/**********/
/* branch */
/**********/

fn diagnostic_riscv_ima_branch() {
    // bltu (RISCV) -> ltu (ZisK)
    {
        let a: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        let b: u64 = 0xFFFF_FFFF_FFFF_FFFE;
        let c: u64;

        // Use RISCV inline assembly to ensure ZisK instruction is called
        unsafe {
            std::arch::asm!(
                "mv {result}, {input1}",          // Initialize result with a
                "bltu {input2}, {input1}, 2f",     // If b < a, skip next instruction
                "mv {result}, {input2}",          // Otherwise, set result to b (minimum)
                "2:",                             // Label for branch target
                result = out(reg) c,
                input1 = in(reg) a,
                input2 = in(reg) b,
            );
        }

        assert_eq!(c, 0xFFFF_FFFF_FFFF_FFFF); // Check we branched correctly
    }
    println!("diagnostic_riscv_ima() success");

    // blt (RISCV) -> lt (ZisK)
    {
        let a: i64 = 0xFF_FFFF_FFFF_FFFF;
        let b: i64 = 0xFF_FFFF_FFFF_FFFE;
        let c: i64;

        // Use RISCV inline assembly to ensure ZisK instruction is called
        unsafe {
            std::arch::asm!(
                "mv {result}, {input1}",          // Initialize result with a
                "blt {input2}, {input1}, 2f",     // If b < a, skip next instruction
                "mv {result}, {input2}",          // Otherwise, set result to b (minimum)
                "2:",                             // Label for branch target
                result = out(reg) c,
                input1 = in(reg) a,
                input2 = in(reg) b,
            );
        }

        assert_eq!(c, 0xFF_FFFF_FFFF_FFFF); // Check we branched correctly
    }
}
