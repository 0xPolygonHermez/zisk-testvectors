use precomp_arith_eq::test_data::{get_secp256r1_add_test_data, get_secp256r1_dbl_test_data};
use std::path::Path;

use super::ProgramBuilder;

pub fn generate_secp256r1_tests(output_path: &Path, limit: Option<usize>) -> (String, String) {
    let mut builder = ProgramBuilder::new("Secp256r1");

    let limit = limit.unwrap_or(usize::MAX);

    // ========== Secp256r1 Add Test Group ==========
    builder.add_test_group("Secp256r1 Add Tests");
    builder.add_header_to_current_group(&[
        "let mut p1 = SyscallPoint256 { x: [0,0,0,0], y: [0,0,0,0] };",
        "let p2 = SyscallPoint256 { x: [0,0,0,0], y: [0,0,0,0] };",
        "let mut params = SyscallSecp256r1AddParams { p1: &mut p1, p2: &p2 };",
    ]);

    let mut index = 0;
    while let Some((p1, p2, p3)) = get_secp256r1_add_test_data(index) {
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
            "secp256r1_add",
            &[
                &format!("let mut p1 = SyscallPoint256 {{ x: {:?}, y: {:?} }};", p1_x, p1_y),
                &format!("let p2 = SyscallPoint256 {{ x: {:?}, y: {:?} }};", p2_x, p2_y),
                "params.p1 = &mut p1;",
                "params.p2 = &p2;",
                "syscall_secp256r1_add(&mut params);",
                &format!("let p3 = SyscallPoint256 {{ x: {:?}, y: {:?} }};", p3_x, p3_y),
                "assert_eq!(params.p1.x, p3.x);",
                "assert_eq!(params.p1.y, p3.y);",
            ],
        );
        index += 1;
    }

    // ========== Secp256r1 Dbl Test Group ==========
    builder.add_test_group("Secp256r1 Dbl Tests");

    index = 0;
    while let Some((p1, p3)) = get_secp256r1_dbl_test_data(index) {
        if index >= limit {
            break;
        }

        let p1_x: [u64; 4] = p1[0..4].try_into().unwrap();
        let p1_y: [u64; 4] = p1[4..8].try_into().unwrap();
        let p3_x: [u64; 4] = p3[0..4].try_into().unwrap();
        let p3_y: [u64; 4] = p3[4..8].try_into().unwrap();

        builder.add_test_to_current_group(
            "secp256r1_dbl",
            &[
                &format!("let mut p1 = SyscallPoint256 {{ x: {:?}, y: {:?} }};", p1_x, p1_y),
                "syscall_secp256r1_dbl(&mut p1);",
                &format!("let p3 = SyscallPoint256 {{ x: {:?}, y: {:?} }};", p3_x, p3_y),
                "assert_eq!(p1.x, p3.x);",
                "assert_eq!(p1.y, p3.y);",
            ],
        );
        index += 1;
    }

    // Write to file
    let file_name = "secp256r1";
    let fn_name = "test_secp256r1";
    let output_file = output_path.join(format!("{}.rs", file_name));
    builder.generate_to_file(output_file.to_str().unwrap(), fn_name);
    (file_name.to_string(), fn_name.to_string())
}
