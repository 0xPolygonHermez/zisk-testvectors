use precomp_arith_eq::test_data::{
    get_bn254_complex_add_test_data, get_bn254_complex_mul_test_data,
    get_bn254_complex_sub_test_data, get_bn254_curve_add_test_data, get_bn254_curve_dbl_test_data,
};
use std::path::Path;

use super::ProgramBuilder;

pub fn generate_bn254_tests(output_path: &Path, limit: Option<usize>) -> (String, String) {
    let mut builder = ProgramBuilder::new("Bn254");

    let limit = limit.unwrap_or(usize::MAX);

    // ========== Bn254 Add Test Group ==========
    builder.add_test_group("Bn254 Add Tests");
    builder.add_header_to_current_group(&[
        "let mut p1 = SyscallPoint256 { x: [0,0,0,0], y: [0,0,0,0] };",
        "let p2 = SyscallPoint256 { x: [0,0,0,0], y: [0,0,0,0] };",
        "let mut params = SyscallBn254CurveAddParams { p1: &mut p1, p2: &p2 };",
    ]);

    let mut index = 0;
    while let Some((p1, p2, p3)) = get_bn254_curve_add_test_data(index) {
        if index >= limit {
            break;
        }

        let p1_x: [u64; 4] = p1[0..4].try_into().unwrap();
        let p1_y: [u64; 4] = p1[4..8].try_into().unwrap();
        let p2_x: [u64; 4] = p2[0..4].try_into().unwrap();
        let p2_y: [u64; 4] = p2[4..8].try_into().unwrap();
        let p3_x: [u64; 4] = p3[0..4].try_into().unwrap();
        let p3_y: [u64; 4] = p3[4..8].try_into().unwrap();

        builder.add_test_to_current_group(
            "bn254_curve_add",
            &[
                &format!("let mut p1 = SyscallPoint256 {{ x: {:?}, y: {:?} }};", p1_x, p1_y),
                &format!("let p2 = SyscallPoint256 {{ x: {:?}, y: {:?} }};", p2_x, p2_y),
                "params.p1 = &mut p1;",
                "params.p2 = &p2;",
                "syscall_bn254_curve_add(&mut params);",
                &format!("let p3 = SyscallPoint256 {{ x: {:?}, y: {:?} }};", p3_x, p3_y),
                "assert_eq!(params.p1.x, p3.x);",
                "assert_eq!(params.p1.y, p3.y);",
            ],
        );
        index += 1;
    }

    // ========== Bn254 Dbl Test Group ==========
    builder.add_test_group("Bn254 Dbl Tests");

    index = 0;
    while let Some((p1, p3)) = get_bn254_curve_dbl_test_data(index) {
        if index >= limit {
            break;
        }

        let p1_x: [u64; 4] = p1[0..4].try_into().unwrap();
        let p1_y: [u64; 4] = p1[4..8].try_into().unwrap();
        let p3_x: [u64; 4] = p3[0..4].try_into().unwrap();
        let p3_y: [u64; 4] = p3[4..8].try_into().unwrap();

        builder.add_test_to_current_group(
            "bn254_curve_dbl",
            &[
                &format!("let mut p1 = SyscallPoint256 {{ x: {:?}, y: {:?} }};", p1_x, p1_y),
                "syscall_bn254_curve_dbl(&mut p1);",
                &format!("let p3 = SyscallPoint256 {{ x: {:?}, y: {:?} }};", p3_x, p3_y),
                "assert_eq!(p1.x, p3.x);",
                "assert_eq!(p1.y, p3.y);",
            ],
        );
        index += 1;
    }

    // ========== Complex Add Test Group ==========
    builder.add_test_group("Complex Add Tests");
    builder.add_header_to_current_group(&[
        "let mut f1 = SyscallComplex256 { x: [0,0,0,0], y: [0,0,0,0] };",
        "let f2 = SyscallComplex256 { x: [0,0,0,0], y: [0,0,0,0] };",
        "let mut params = SyscallBn254ComplexAddParams { f1: &mut f1, f2: &f2 };",
    ]);

    index = 0;
    while let Some((f1, f2, f3)) = get_bn254_complex_add_test_data(index) {
        if index >= limit {
            break;
        }

        let f1_x: [u64; 4] = f1[0..4].try_into().unwrap();
        let f1_y: [u64; 4] = f1[4..8].try_into().unwrap();
        let f2_x: [u64; 4] = f2[0..4].try_into().unwrap();
        let f2_y: [u64; 4] = f2[4..8].try_into().unwrap();
        let f3_x: [u64; 4] = f3[0..4].try_into().unwrap();
        let f3_y: [u64; 4] = f3[4..8].try_into().unwrap();

        builder.add_test_to_current_group(
            "bn254_complex_add",
            &[
                &format!("let mut f1 = SyscallComplex256 {{ x: {:?}, y: {:?} }};", f1_x, f1_y),
                &format!("let f2 = SyscallComplex256 {{ x: {:?}, y: {:?} }};", f2_x, f2_y),
                "params.f1 = &mut f1;",
                "params.f2 = &f2;",
                "syscall_bn254_complex_add(&mut params);",
                &format!("let f3 = SyscallComplex256 {{ x: {:?}, y: {:?} }};", f3_x, f3_y),
                "assert_eq!(params.f1.x, f3.x);",
                "assert_eq!(params.f1.y, f3.y);",
            ],
        );
        index += 1;
    }

    // ========== Complex Sub Test Group ==========
    builder.add_test_group("Complex Sub Tests");
    builder.add_header_to_current_group(&[
        "let mut params = SyscallBn254ComplexSubParams { f1: &mut f1, f2: &f2 };",
    ]);

    index = 0;
    while let Some((f1, f2, f3)) = get_bn254_complex_sub_test_data(index) {
        if index >= limit {
            break;
        }

        let f1_x: [u64; 4] = f1[0..4].try_into().unwrap();
        let f1_y: [u64; 4] = f1[4..8].try_into().unwrap();
        let f2_x: [u64; 4] = f2[0..4].try_into().unwrap();
        let f2_y: [u64; 4] = f2[4..8].try_into().unwrap();
        let f3_x: [u64; 4] = f3[0..4].try_into().unwrap();
        let f3_y: [u64; 4] = f3[4..8].try_into().unwrap();

        builder.add_test_to_current_group(
            "bn254_complex_sub",
            &[
                &format!("let mut f1 = SyscallComplex256 {{ x: {:?}, y: {:?} }};", f1_x, f1_y),
                &format!("let f2 = SyscallComplex256 {{ x: {:?}, y: {:?} }};", f2_x, f2_y),
                "params.f1 = &mut f1;",
                "params.f2 = &f2;",
                "syscall_bn254_complex_sub(&mut params);",
                &format!("let f3 = SyscallComplex256 {{ x: {:?}, y: {:?} }};", f3_x, f3_y),
                "assert_eq!(params.f1.x, f3.x);",
                "assert_eq!(params.f1.y, f3.y);",
            ],
        );
        index += 1;
    }

    // ========== Complex Mul Test Group ==========
    builder.add_test_group("Complex Mul Tests");
    builder.add_header_to_current_group(&[
        "let mut params = SyscallBn254ComplexMulParams { f1: &mut f1, f2: &f2 };",
    ]);

    index = 0;
    while let Some((f1, f2, f3)) = get_bn254_complex_mul_test_data(index) {
        if index >= limit {
            break;
        }

        let f1_x: [u64; 4] = f1[0..4].try_into().unwrap();
        let f1_y: [u64; 4] = f1[4..8].try_into().unwrap();
        let f2_x: [u64; 4] = f2[0..4].try_into().unwrap();
        let f2_y: [u64; 4] = f2[4..8].try_into().unwrap();
        let f3_x: [u64; 4] = f3[0..4].try_into().unwrap();
        let f3_y: [u64; 4] = f3[4..8].try_into().unwrap();

        builder.add_test_to_current_group(
            "bn254_complex_mul",
            &[
                &format!("let mut f1 = SyscallComplex256 {{ x: {:?}, y: {:?} }};", f1_x, f1_y),
                &format!("let f2 = SyscallComplex256 {{ x: {:?}, y: {:?} }};", f2_x, f2_y),
                "params.f1 = &mut f1;",
                "params.f2 = &f2;",
                "syscall_bn254_complex_mul(&mut params);",
                &format!("let f3 = SyscallComplex256 {{ x: {:?}, y: {:?} }};", f3_x, f3_y),
                "assert_eq!(params.f1.x, f3.x);",
                "assert_eq!(params.f1.y, f3.y);",
            ],
        );
        index += 1;
    }

    // Write to file
    let file_name = "bn254";
    let fn_name = "test_bn254";
    let output_file = output_path.join(format!("{}.rs", file_name));
    builder.generate_to_file(output_file.to_str().unwrap(), fn_name);
    (file_name.to_string(), fn_name.to_string())
}
