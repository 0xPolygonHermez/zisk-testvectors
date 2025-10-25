use clap::Parser;
use path_clean::PathClean;
use std::fs;
use std::path::Path;

mod tests;

use tests::{generate_arith_eq_384_tests, generate_arith_eq_tests, generate_main_file};

const MINIMAL_TESTS: usize = 5;

#[derive(Parser)]
struct Args {
    /// Use minimal test set
    #[arg(long, short)]
    minimal: bool,

    /// Maximum number of tests per group (overrides --minimal default)
    #[arg(long, short = 'n')]
    max_tests: Option<usize>,
}

fn main() {
    let args = Args::parse();

    // Determine the actual max_tests value
    let max_tests = if let Some(n) = args.max_tests {
        Some(n)
    } else if args.minimal {
        Some(MINIMAL_TESTS)
    } else {
        None // No limit
    };

    let current_file_path = Path::new(file!());
    let current_dir = current_file_path
        .parent() // → tools/program_gen/src
        .and_then(|p| p.parent()) // → tools/program_gen
        .and_then(|p| p.parent()) // → tools
        .and_then(|p| p.parent()) // → zisk-testvectors
        .unwrap();

    let target_output_path = current_dir.join("zisk-programs/precompiles/program/src").clean();
    fs::create_dir_all(&target_output_path).expect("Failed to create test directory");

    // Generate each test module and collect their info
    let mut modules = Vec::new();

    let (fn_name, file_name) = generate_arith_eq_tests(&target_output_path, max_tests);
    modules.push((fn_name, file_name));

    let (fn_name, file_name) = generate_arith_eq_384_tests(&target_output_path, max_tests);
    modules.push((fn_name, file_name));

    // Generate main.rs to call all test modules
    generate_main_file(&target_output_path, &modules);
}
