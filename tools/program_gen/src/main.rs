use clap::Parser;
use path_clean::PathClean;
use std::{
    fs::{self},
    path::Path,
};

mod tests;

use tests::{
    generate_arith_eq_384_tests, generate_arith_eq_tests, generate_bigint_tests,
    generate_cargo_toml, generate_main_file,
};

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

    let current_file_path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let current_dir = current_file_path
        .parent() // → tools/
        .and_then(|p| p.parent()) // → zisk-testvectors
        .unwrap();

    // Create build/src directory
    let build_dir = current_dir.join("build");
    let src_dir = build_dir.join("src").clean();
    fs::create_dir_all(&src_dir).expect("Failed to create build/src directory");

    // Generate each test module and collect their info
    let mut modules = Vec::new();

    let (fn_name, file_name) = generate_arith_eq_tests(&src_dir, max_tests);
    modules.push((fn_name, file_name));

    let (fn_name, file_name) = generate_arith_eq_384_tests(&src_dir, max_tests);
    modules.push((fn_name, file_name));

    let (fn_name, file_name) = generate_bigint_tests(&src_dir, max_tests);
    modules.push((fn_name, file_name));

    // Generate main.rs to call all test modules
    generate_main_file(&src_dir, &modules);

    // Generate Cargo.toml
    generate_cargo_toml(&build_dir);

    println!("\nTest program generated successfully at: {}\n", build_dir.display());
}
