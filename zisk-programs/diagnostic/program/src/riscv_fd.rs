#![cfg(all(target_os = "zkvm", target_vendor = "zisk"))]

//use std::arch::asm;

pub fn diagnostic_riscv_fd() {
    {
        let a = 1.1;
        let b = 2.2;
        let c = a + b;
        assert!(c > 3.2 && c < 3.4);
    }
    fadd_d(1.1, 2.2, 3.3);
    fadd_s(1.1, 2.2, 3.3);
    fsub_d(1.1, 2.2, -1.1);
    fsub_s(1.1, 2.2, -1.1);
    fmul_d(1.1, 2.2, 2.42);
    fmul_s(1.1, 2.2, 2.42);
    fdiv_d(4.4, 2.2, 2.0);
    fdiv_s(4.4, 2.2, 2.0);
    fsqrt_d(4.0, 2.0);
    fsqrt_s(4.0, 2.0);
    fmax_d(1.1, 2.2, 2.2);
    fmax_s(1.1, 2.2, 2.2);
    fmin_d(1.1, 2.2, 1.1);
    fmin_s(1.1, 2.2, 1.1);

    feq_d(1.1, 1.1, true);
    feq_d(1.1, 1.2, false);
    feq_s(1.1, 1.1, true);
    feq_s(1.1, 1.2, false);
    fle_d(1.1, 2.2, true);
    fle_d(2.2, 2.2, true);
    fle_d(2.2, 1.1, false);
    fle_s(1.1, 2.2, true);
    fle_s(2.2, 2.2, true);
    fle_s(2.2, 1.1, false);
    flt_d(1.1, 2.2, true);
    flt_d(2.2, 2.2, false);
    flt_d(2.2, 1.1, false);
    flt_s(1.1, 2.2, true);
    flt_s(2.2, 2.2, false);
    flt_s(2.2, 1.1, false);

    println!("diagnostic_riscv_fd() success");
}

// fadd.d fadd.s fsub.d fsub.s fmul.d fmul.s fdiv.d fdiv.s fsqrt.d fsqrt.s
// fmax.d fmax.s fmin.d fmin.s
// feq.d feq.s fle.d fle.s flt.d flt.s
//fclass.d fclass.s fcvt.d.l fcvt.d.lu fcvt.d.s fcvt.d.w fcvt.d.wu fcvt.l.d fcvt.l.s fcvt.lu.d fcvt.lu.s fcvt.s.d fcvt.s.l fcvt.s.lu fcvt.s.w fcvt.s.wu fcvt.w.d fcvt.w.s fcvt.wu.d fcvt.wu.s fld flw fmadd.d fmadd.s fmsub.d fmsub.s fmv.w.x fmv.x.w fnmadd.d fnmadd.s fnmsub.d fnmsub.s fsd fsgnj.d fsgnj.s fsgnjn.d fsgnjn.s fsgnjx.d fsgnjx.s fsw

const F64_TOLERANCE: f64 = 0.001;
const F32_TOLERANCE: f32 = 0.001;

// let a: u64 = input_a.to_bits() as u64;
// let b: u64 = input_b.to_bits() as u64;
// let expected_c: u64 = expected_c.to_bits() as u64;
// let c: u64;
// unsafe {
//     asm!(
//         "fld ft2, double_val, {1}",
//         "fld ft3, double_val, {2}",
//         "fadd.d ft4, ft2, ft3",
//         "fsd {0}, ft4",
//         out(reg) c,
//         in(reg) a,
//         in(reg) b,
//     );
// }

/*************/
/* add / sub */
/*************/

fn fadd_d(a: f64, b: f64, expected_c: f64) {
    let c = a + b;
    assert!(c >= expected_c - F64_TOLERANCE);
    assert!(c <= expected_c + F64_TOLERANCE);
}

fn fadd_s(a: f32, b: f32, expected_c: f32) {
    let c = a + b;
    assert!(c >= expected_c - F32_TOLERANCE);
    assert!(c <= expected_c + F32_TOLERANCE);
}

fn fsub_d(a: f64, b: f64, expected_c: f64) {
    let c = a - b;
    assert!(c >= expected_c - F64_TOLERANCE);
    assert!(c <= expected_c + F64_TOLERANCE);
}

fn fsub_s(a: f32, b: f32, expected_c: f32) {
    let c = a - b;
    assert!(c >= expected_c - F32_TOLERANCE);
    assert!(c <= expected_c + F32_TOLERANCE);
}

/********************/
/* mul / div / sqrt */
/********************/

fn fmul_d(a: f64, b: f64, expected_c: f64) {
    let c = a * b;
    assert!(c >= expected_c - F64_TOLERANCE);
    assert!(c <= expected_c + F64_TOLERANCE);
}

fn fmul_s(a: f32, b: f32, expected_c: f32) {
    let c = a * b;
    assert!(c >= expected_c - F32_TOLERANCE);
    assert!(c <= expected_c + F32_TOLERANCE);
}

fn fdiv_d(a: f64, b: f64, expected_c: f64) {
    let c = a / b;
    assert!(c >= expected_c - F64_TOLERANCE);
    assert!(c <= expected_c + F64_TOLERANCE);
}

fn fdiv_s(a: f32, b: f32, expected_c: f32) {
    let c = a / b;
    assert!(c >= expected_c - F32_TOLERANCE);
    assert!(c <= expected_c + F32_TOLERANCE);
}

fn fsqrt_d(a: f64, expected_c: f64) {
    let c = a.sqrt();
    assert!(c >= expected_c - F64_TOLERANCE);
    assert!(c <= expected_c + F64_TOLERANCE);
}

fn fsqrt_s(a: f32, expected_c: f32) {
    let c = a.sqrt();
    assert!(c >= expected_c - F32_TOLERANCE);
    assert!(c <= expected_c + F32_TOLERANCE);
}

/*************/
/* max / min */
/*************/

fn fmax_d(a: f64, b: f64, expected_c: f64) {
    let c = a.max(b);
    assert!(c >= expected_c - F64_TOLERANCE);
    assert!(c <= expected_c + F64_TOLERANCE);
}

fn fmax_s(a: f32, b: f32, expected_c: f32) {
    let c = a.max(b);
    assert!(c >= expected_c - F32_TOLERANCE);
    assert!(c <= expected_c + F32_TOLERANCE);
}

fn fmin_d(a: f64, b: f64, expected_c: f64) {
    let c = a.min(b);
    assert!(c >= expected_c - F64_TOLERANCE);
    assert!(c <= expected_c + F64_TOLERANCE);
}

fn fmin_s(a: f32, b: f32, expected_c: f32) {
    let c = a.min(b);
    assert!(c >= expected_c - F32_TOLERANCE);
    assert!(c <= expected_c + F32_TOLERANCE);
}

/****************/
/* eq / lt / le */
/****************/

fn feq_d(a: f64, b: f64, expected: bool) {
    let result = a == b;
    assert!(result == expected);
}

fn feq_s(a: f32, b: f32, expected: bool) {
    let result = a == b;
    assert!(result == expected);
}

fn fle_d(a: f64, b: f64, expected: bool) {
    let result = a <= b;
    assert!(result == expected);
}

fn fle_s(a: f32, b: f32, expected: bool) {
    let result = a <= b;
    assert!(result == expected);
}

fn flt_d(a: f64, b: f64, expected: bool) {
    let result = a < b;
    assert!(result == expected);
}

fn flt_s(a: f32, b: f32, expected: bool) {
    let result = a < b;
    assert!(result == expected);
}
