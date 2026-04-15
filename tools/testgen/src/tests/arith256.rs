use precomp_arith_eq::test_data::{get_arith256_mod_test_data, get_arith256_test_data};
use std::path::Path;

use super::{load_test_data_from_json, ProgramBuilder, TestData};

pub fn generate_arith256_tests(output_path: &Path, limit: Option<usize>) -> (String, String) {
    let mut builder = ProgramBuilder::new("Arith256");

    let limit = limit.unwrap_or(usize::MAX);

    // ========== Add256 Test Group ==========
    let add256_data = match load_test_data_from_json("src/tests/test_data/add256_tests.json") {
        TestData::Add256(data) => data,
        other => panic!("Expected Add256 test data, but got: {:?}", other),
    };

    if !add256_data.is_empty() {
        builder.add_test_group("Add256 Tests");
        builder.add_header_to_current_group(&[
            "let a: [u64; 4] = [0, 0, 0, 0];",
            "let b: [u64; 4] = [0, 0, 0, 0];",
            "let mut c: [u64; 4] = [0, 0, 0, 0];",
            "let mut params = SyscallAdd256Params { a: &a, b: &b, cin: 0, c: &mut c };",
        ]);

        for (index, test) in add256_data.iter().enumerate() {
            if index >= limit {
                break;
            }

            builder.add_test_to_current_group(
                "add256",
                &[
                    &format!("params.a = &{:?};", test.a),
                    &format!("params.b = &{:?};", test.b),
                    &format!("params.cin = {:?};", test.cin),
                    "let cout = syscall_add256(&mut params);",
                    &format!("let expected_c: [u64; 4] = {:?};", test.c),
                    &format!("let expected_cout: u64 = {:?};", test.cout),
                    "assert_eq!(params.c, &expected_c);",
                    "assert_eq!(cout, expected_cout);",
                ],
            );
        }
    }

    // ========== Arith256 Test Group ==========
    builder.add_test_group("Arith256 Tests");
    builder.add_header_to_current_group(&[
        "let a: [u64; 4] = [0, 0, 0, 0];",
        "let b: [u64; 4] = [0, 0, 0, 0];",
        "let c: [u64; 4] = [0, 0, 0, 0];",
        "let mut dl: [u64; 4] = [0, 0, 0, 0];",
        "let mut dh: [u64; 4] = [0, 0, 0, 0];",
        "let mut params = SyscallArith256Params { a: &a, b: &b, c: &c, dl: &mut dl, dh: &mut dh };",
    ]);

    let mut index = 0;
    while let Some((a, b, c, dh, dl)) = get_arith256_test_data(index) {
        if index >= limit {
            break;
        }

        builder.add_test_to_current_group(
            "arith256",
            &[
                &format!("params.a = &{:?};", a),
                &format!("params.b = &{:?};", b),
                &format!("params.c = &{:?};", c),
                "syscall_arith256(&mut params);",
                &format!("let expected_dh: [u64; 4] = {:?};", dh),
                &format!("let expected_dl: [u64; 4] = {:?};", dl),
                "assert_eq!(params.dh, &expected_dh);",
                "assert_eq!(params.dl, &expected_dl);",
            ],
        );
        index += 1;
    }

    // ========== Arith256Mod Test Group ==========
    builder.add_test_group("Arith256Mod Tests");
    builder.add_header_to_current_group(&[
        "let a: [u64; 4] = [0, 0, 0, 0];",
        "let b: [u64; 4] = [0, 0, 0, 0];",
        "let c: [u64; 4] = [0, 0, 0, 0];",
        "let module:[u64;4] = [0,0,0,0];",
        "let mut d:[u64;4] = [0,0,0,0];",
        "let mut params = SyscallArith256ModParams { a: &a, b: &b, c: &c, module: &module, d: &mut d };",
    ]);

    index = 0;
    while let Some((a, b, c, module, d)) = get_arith256_mod_test_data(index) {
        if index >= limit {
            break;
        }

        builder.add_test_to_current_group(
            "arith256mod",
            &[
                &format!("params.a = &{:?};", a),
                &format!("params.b = &{:?};", b),
                &format!("params.c = &{:?};", c),
                &format!("params.module = &{:?};", module),
                "syscall_arith256_mod(&mut params);",
                &format!("let expected_d: [u64; 4] = {:?};", d),
                "assert_eq!(params.d, &expected_d);",
            ],
        );
        index += 1;
    }

    // Write to file
    let file_name = "arith256";
    let fn_name = "test_arith256";
    let output_file = output_path.join(format!("{}.rs", file_name));
    builder.generate_to_file(output_file.to_str().unwrap(), fn_name);
    (file_name.to_string(), fn_name.to_string())
}
