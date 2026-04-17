use std::path::Path;

use super::{load_test_data_from_json, ProgramBuilder, TestData};

pub fn generate_poseidon2_tests(output_path: &Path, limit: Option<usize>) -> (String, String) {
    let mut builder = ProgramBuilder::new("Poseidon2");

    let limit = limit.unwrap_or(usize::MAX);

    // ========== Poseidon2 Test Group ==========
    let test_data = match load_test_data_from_json("src/tests/test_data/poseidon2_tests.json") {
        TestData::Poseidon2(data) => data,
        other => panic!("Expected Poseidon2 test data, but got: {:?}", other),
    };

    if !test_data.is_empty() {
        builder.add_test_group("Poseidon2 Tests");

        for (index, test) in test_data.iter().enumerate() {
            if index >= limit {
                break;
            }

            builder.add_test_to_current_group(
                "poseidon2",
                &[
                    &format!("let mut state = {:?};", test.state_in),
                    "unsafe { syscall_poseidon2(&mut state); }",
                    &format!("let expected_out: [u64; 16] = {:?};", test.state_out),
                    "assert_eq!(state, expected_out);",
                ],
            );
        }
    }

    // Write to file
    let file_name = "poseidon2";
    let fn_name = "test_poseidon2";
    let output_file = output_path.join(format!("{}.rs", file_name));
    builder.generate_to_file(output_file.to_str().unwrap(), fn_name);
    (file_name.to_string(), fn_name.to_string())
}
