use precomp_arith_eq_384::test_data::{
    get_arith384_mod_test_data, get_bls12_381_complex_add_test_data,
    get_bls12_381_complex_mul_test_data, get_bls12_381_complex_sub_test_data,
    get_bls12_381_curve_add_test_data, get_bls12_381_curve_dbl_test_data,
};

use std::path::Path;

use super::ProgramBuilder;

pub fn generate_arith_eq_384_tests(output_path: &Path, limit: Option<usize>) -> (String, String) {
    let mut builder = ProgramBuilder::new("ArithEq384");

    let limit = limit.unwrap_or(usize::MAX);

    // ========== Arith384 Test Group ==========
    builder.add_test_group("Arith384 Tests");
    builder.add_header_to_current_group(&[
        "let a: [u64; 6] = [0, 0, 0, 0, 0, 0];",
        "let b: [u64; 6] = [0, 0, 0, 0, 0, 0];",
        "let c: [u64; 6] = [0, 0, 0, 0, 0, 0];",
        "let module: [u64; 6] = [0, 0, 0, 0, 0, 0];",
        "let mut d: [u64; 6] = [0, 0, 0, 0, 0, 0];",
        "let mut params = SyscallArith384ModParams { a: &a, b: &b, c: &c, module: &module, d: &mut d };",
    ]);

    let mut index = 0;
    while let Some((a, b, c, module, d)) = get_arith384_mod_test_data(index) {
        if index >= limit {
            break;
        }

        builder.add_test_to_current_group(
            "arith384_mod",
            &[
                &format!("params.a = &{:?};", a),
                &format!("params.b = &{:?};", b),
                &format!("params.c = &{:?};", c),
                &format!("params.module = &{:?};", module),
                "syscall_arith384_mod(&mut params);",
                &format!("let expected_d: [u64; 6] = {:?};", d),
                "assert_eq!(params.d, &expected_d);",
            ],
        );
        index += 1;
    }

    // ========== BLS12-381 Add Test Group ==========
    builder.add_test_group("BLS12-381 Add Tests");
    builder.add_header_to_current_group(&[
        "let mut p1 = SyscallPoint384 { x: [0,0,0,0,0,0], y: [0,0,0,0,0,0] };",
        "let p2 = SyscallPoint384 { x: [0,0,0,0,0,0], y: [0,0,0,0,0,0] };",
        "let mut params = SyscallBls12_381CurveAddParams { p1: &mut p1, p2: &p2 };",
    ]);

    index = 0;
    while let Some((p1, p2, p3)) = get_bls12_381_curve_add_test_data(index) {
        if index >= limit {
            break;
        }

        let p1_x: [u64; 6] = p1[0..6].try_into().unwrap();
        let p1_y: [u64; 6] = p1[6..12].try_into().unwrap();
        let p2_x: [u64; 6] = p2[0..6].try_into().unwrap();
        let p2_y: [u64; 6] = p2[6..12].try_into().unwrap();
        let p3_x: [u64; 6] = p3[0..6].try_into().unwrap();
        let p3_y: [u64; 6] = p3[6..12].try_into().unwrap();

        builder.add_test_to_current_group(
            "bls12_381_curve_add",
            &[
                &format!("let mut p1 = SyscallPoint384 {{ x: {:?}, y: {:?} }};", p1_x, p1_y),
                &format!("let p2 = SyscallPoint384 {{ x: {:?}, y: {:?} }};", p2_x, p2_y),
                "params.p1 = &mut p1;",
                "params.p2 = &p2;",
                "syscall_bls12_381_curve_add(&mut params);",
                &format!("let p3 = SyscallPoint384 {{ x: {:?}, y: {:?} }};", p3_x, p3_y),
                "assert_eq!(params.p1.x, p3.x);",
                "assert_eq!(params.p1.y, p3.y);",
            ],
        );
        index += 1;
    }

    // ========== BLS12-381 Dbl Test Group ==========
    builder.add_test_group("BLS12-381 Dbl Tests");

    index = 0;
    while let Some((p1, p3)) = get_bls12_381_curve_dbl_test_data(index) {
        if index >= limit {
            break;
        }

        let p1_x: [u64; 6] = p1[0..6].try_into().unwrap();
        let p1_y: [u64; 6] = p1[6..12].try_into().unwrap();
        let p3_x: [u64; 6] = p3[0..6].try_into().unwrap();
        let p3_y: [u64; 6] = p3[6..12].try_into().unwrap();

        builder.add_test_to_current_group(
            "bls12_381_curve_dbl",
            &[
                &format!("let mut p1 = SyscallPoint384 {{ x: {:?}, y: {:?} }};", p1_x, p1_y),
                "syscall_bls12_381_curve_dbl(&mut p1);",
                &format!("let p3 = SyscallPoint384 {{ x: {:?}, y: {:?} }};", p3_x, p3_y),
                "assert_eq!(p1.x, p3.x);",
                "assert_eq!(p1.y, p3.y);",
            ],
        );
        index += 1;
    }

    // ========== Complex Add Test Group ==========
    builder.add_test_group("Complex Add Tests");
    builder.add_header_to_current_group(&[
        "let mut f1 = SyscallComplex384 { x: [0,0,0,0,0,0], y: [0,0,0,0,0,0] };",
        "let f2 = SyscallComplex384 { x: [0,0,0,0,0,0], y: [0,0,0,0,0,0] };",
        "let mut params = SyscallBls12_381ComplexAddParams { f1: &mut f1, f2: &f2 };",
    ]);

    index = 0;
    while let Some((f1, f2, f3)) = get_bls12_381_complex_add_test_data(index) {
        if index >= limit {
            break;
        }

        let f1_x: [u64; 6] = f1[0..6].try_into().unwrap();
        let f1_y: [u64; 6] = f1[6..12].try_into().unwrap();
        let f2_x: [u64; 6] = f2[0..6].try_into().unwrap();
        let f2_y: [u64; 6] = f2[6..12].try_into().unwrap();
        let f3_x: [u64; 6] = f3[0..6].try_into().unwrap();
        let f3_y: [u64; 6] = f3[6..12].try_into().unwrap();

        builder.add_test_to_current_group(
            "bls12_381_complex_add",
            &[
                &format!("let mut f1 = SyscallComplex384 {{ x: {:?}, y: {:?} }};", f1_x, f1_y),
                &format!("let f2 = SyscallComplex384 {{ x: {:?}, y: {:?} }};", f2_x, f2_y),
                "params.f1 = &mut f1;",
                "params.f2 = &f2;",
                "syscall_bls12_381_complex_add(&mut params);",
                &format!("let f3 = SyscallComplex384 {{ x: {:?}, y: {:?} }};", f3_x, f3_y),
                "assert_eq!(params.f1.x, f3.x);",
                "assert_eq!(params.f1.y, f3.y);",
            ],
        );
        index += 1;
    }

    // ========== Complex Sub Test Group ==========
    builder.add_test_group("Complex Sub Tests");
    builder.add_header_to_current_group(&[
        "let mut params = SyscallBls12_381ComplexSubParams { f1: &mut f1, f2: &f2 };",
    ]);

    index = 0;
    while let Some((f1, f2, f3)) = get_bls12_381_complex_sub_test_data(index) {
        if index >= limit {
            break;
        }

        let f1_x: [u64; 6] = f1[0..6].try_into().unwrap();
        let f1_y: [u64; 6] = f1[6..12].try_into().unwrap();
        let f2_x: [u64; 6] = f2[0..6].try_into().unwrap();
        let f2_y: [u64; 6] = f2[6..12].try_into().unwrap();
        let f3_x: [u64; 6] = f3[0..6].try_into().unwrap();
        let f3_y: [u64; 6] = f3[6..12].try_into().unwrap();

        builder.add_test_to_current_group(
            "bls12_381_complex_sub",
            &[
                &format!("let mut f1 = SyscallComplex384 {{ x: {:?}, y: {:?} }};", f1_x, f1_y),
                &format!("let f2 = SyscallComplex384 {{ x: {:?}, y: {:?} }};", f2_x, f2_y),
                "params.f1 = &mut f1;",
                "params.f2 = &f2;",
                "syscall_bls12_381_complex_sub(&mut params);",
                &format!("let f3 = SyscallComplex384 {{ x: {:?}, y: {:?} }};", f3_x, f3_y),
                "assert_eq!(params.f1.x, f3.x);",
                "assert_eq!(params.f1.y, f3.y);",
            ],
        );
        index += 1;
    }

    // ========== Complex Mul Test Group ==========
    builder.add_test_group("Complex Mul Tests");
    builder.add_header_to_current_group(&[
        "let mut params = SyscallBls12_381ComplexMulParams { f1: &mut f1, f2: &f2 };",
    ]);

    index = 0;
    while let Some((f1, f2, f3)) = get_bls12_381_complex_mul_test_data(index) {
        if index >= limit {
            break;
        }

        let f1_x: [u64; 6] = f1[0..6].try_into().unwrap();
        let f1_y: [u64; 6] = f1[6..12].try_into().unwrap();
        let f2_x: [u64; 6] = f2[0..6].try_into().unwrap();
        let f2_y: [u64; 6] = f2[6..12].try_into().unwrap();
        let f3_x: [u64; 6] = f3[0..6].try_into().unwrap();
        let f3_y: [u64; 6] = f3[6..12].try_into().unwrap();

        builder.add_test_to_current_group(
            "bls12_381_complex_mul",
            &[
                &format!("let mut f1 = SyscallComplex384 {{ x: {:?}, y: {:?} }};", f1_x, f1_y),
                &format!("let f2 = SyscallComplex384 {{ x: {:?}, y: {:?} }};", f2_x, f2_y),
                "params.f1 = &mut f1;",
                "params.f2 = &f2;",
                "syscall_bls12_381_complex_mul(&mut params);",
                &format!("let f3 = SyscallComplex384 {{ x: {:?}, y: {:?} }};", f3_x, f3_y),
                "assert_eq!(params.f1.x, f3.x);",
                "assert_eq!(params.f1.y, f3.y);",
            ],
        );
        index += 1;
    }

    // Write to file
    let file_name = "arith_eq_384_tests";
    let fn_name = "test_arith_eq_384";
    let output_file = output_path.join(format!("{}.rs", file_name));
    builder.generate_to_file(output_file.to_str().unwrap(), fn_name);
    (file_name.to_string(), fn_name.to_string())
}
