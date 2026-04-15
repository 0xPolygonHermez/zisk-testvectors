use precomp_arith_eq_384::test_data::get_arith384_mod_test_data;

use std::path::Path;

use super::ProgramBuilder;

pub fn generate_arith384_tests(output_path: &Path, limit: Option<usize>) -> (String, String) {
    let mut builder = ProgramBuilder::new("Arith384");

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

    // Write to file
    let file_name = "arith384";
    let fn_name = "test_arith384";
    let output_file = output_path.join(format!("{}.rs", file_name));
    builder.generate_to_file(output_file.to_str().unwrap(), fn_name);
    (file_name.to_string(), fn_name.to_string())
}
