use std::path::Path;

use super::{load_bigint_test_data, ProgramBuilder};

pub fn generate_bigint_tests(output_path: &Path, limit: Option<usize>) -> (String, String) {
    let mut builder = ProgramBuilder::new("BigInt");

    let limit = limit.unwrap_or(usize::MAX);

    let test_data = load_bigint_test_data("src/tests/test_data/bigint_tests.json");

    // ========== Add256 Test Group ==========
    if !test_data.add256.is_empty() {
        builder.add_test_group("Add256 Tests");
        builder.add_header_to_current_group(&[
            "let a: [u64; 4] = [0, 0, 0, 0];",
            "let b: [u64; 4] = [0, 0, 0, 0];",
            "let mut c: [u64; 4] = [0, 0, 0, 0];",
            "let mut params = SyscallAdd256Params { a: &a, b: &b, cin: 0, c: &mut c };",
        ]);

        for (index, test) in test_data.add256.iter().enumerate() {
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

    // Write to file
    let file_name = "bigint_tests";
    let fn_name = "test_bigint";
    let output_file = output_path.join(format!("{}.rs", file_name));
    builder.generate_to_file(output_file.to_str().unwrap(), fn_name);
    (file_name.to_string(), fn_name.to_string())
}
