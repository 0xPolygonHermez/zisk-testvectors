use std::path::Path;

use super::{load_keccakf_test_data, ProgramBuilder};

pub fn generate_keccakf_tests(output_path: &Path, limit: Option<usize>) -> (String, String) {
    let mut builder = ProgramBuilder::new("Keccakf");

    let limit = limit.unwrap_or(usize::MAX);

    let test_data = load_keccakf_test_data("src/tests/test_data/keccakf_tests.json");

    // ========== Keccakf Test Group ==========
    if !test_data.keccakf.is_empty() {
        builder.add_test_group("Keccakf Tests");

        for (index, test) in test_data.keccakf.iter().enumerate() {
            if index >= limit {
                break;
            }

            builder.add_test_to_current_group(
                "keccakf",
                &[
                    &format!("let mut state = {:?};", test.state_in),
                    "syscall_keccak_f(&mut state);",
                    &format!("let expected_out: [u64; 25] = {:?};", test.state_out),
                    "assert_eq!(state, expected_out);",
                ],
            );
        }
    }

    // Write to file
    let file_name = "keccakf_tests";
    let fn_name = "test_keccakf";
    let output_file = output_path.join(format!("{}.rs", file_name));
    builder.generate_to_file(output_file.to_str().unwrap(), fn_name);
    (file_name.to_string(), fn_name.to_string())
}
