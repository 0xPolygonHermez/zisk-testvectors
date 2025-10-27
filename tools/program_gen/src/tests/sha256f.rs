use std::path::Path;

use super::{load_sha256f_test_data, ProgramBuilder};

pub fn generate_sha256f_tests(output_path: &Path, limit: Option<usize>) -> (String, String) {
    let mut builder = ProgramBuilder::new("Sha256f");

    let limit = limit.unwrap_or(usize::MAX);

    let test_data = load_sha256f_test_data("src/tests/test_data/sha256f_tests.json");

    // ========== Sha256f Test Group ==========
    if !test_data.sha256f.is_empty() {
        builder.add_test_group("Sha256f Tests");
        builder.add_header_to_current_group(&[
            "let mut params = SyscallSha256Params { state: &mut state, input: &input };",
        ]);

        for (index, test) in test_data.sha256f.iter().enumerate() {
            if index >= limit {
                break;
            }

            builder.add_test_to_current_group(
                "sha256f",
                &[
                    &format!("let mut state: [u64; 4] = {:?};", test.state_in),
                    &format!("let input: [u64; 8] = {:?};", test.input),
                    "params.state = &mut state;",
                    "params.input = &input;",
                    "syscall_sha256_f(&mut params);",
                    &format!("let expected_out: [u64; 4] = {:?};", test.state_out),
                    "assert_eq!(params.state, &expected_out);",
                ],
            );
        }
    }

    // Write to file
    let file_name = "sha256f_tests";
    let fn_name = "test_sha256f";
    let output_file = output_path.join(format!("{}.rs", file_name));
    builder.generate_to_file(output_file.to_str().unwrap(), fn_name);
    (file_name.to_string(), fn_name.to_string())
}
