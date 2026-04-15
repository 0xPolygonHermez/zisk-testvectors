use std::path::Path;

use super::{load_test_data_from_json, ProgramBuilder, TestData};

pub fn generate_blake2_tests(output_path: &Path, limit: Option<usize>) -> (String, String) {
    let mut builder = ProgramBuilder::new("Blake2");

    let limit = limit.unwrap_or(usize::MAX);

    // ========== Blake2 Test Group ==========
    let test_data = match load_test_data_from_json("src/tests/test_data/blake2_tests.json") {
        TestData::Blake2(data) => data,
        other => panic!("Expected Blake2 test data, but got: {:?}", other),
    };

    if !test_data.is_empty() {
        builder.add_test_group("Blake2 Tests");
        builder.add_header_to_current_group(&[
            "let index: u64 = 0;",
            "let mut state: [u64; 16] = [0; 16];",
            "let input: [u64; 16] = [0; 16];",
            "let mut params = SyscallBlake2bRoundParams { index, state: &mut state, input: &input };",
        ]);

        for (index, test) in test_data.iter().enumerate() {
            if index >= limit {
                break;
            }

            builder.add_test_to_current_group(
                "blake2",
                &[
                    &format!("let index: u64 = {:?};", test.index),
                    &format!("let mut state: [u64; 16] = {:?};", test.state_in),
                    &format!("let input: [u64; 16] = {:?};", test.input),
                    "params.index = index;",
                    "params.state = &mut state;",
                    "params.input = &input;",
                    "syscall_blake2b_round(&mut params);",
                    &format!("let expected_out: [u64; 16] = {:?};", test.state_out),
                    "assert_eq!(params.state, &expected_out);",
                ],
            );
        }
    }

    // Write to file
    let file_name = "blake2";
    let fn_name = "test_blake2";
    let output_file = output_path.join(format!("{}.rs", file_name));
    builder.generate_to_file(output_file.to_str().unwrap(), fn_name);
    (file_name.to_string(), fn_name.to_string())
}
