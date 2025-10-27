use clap::Parser;
use std::{
    fs::{self},
    path::{Path, PathBuf},
};

mod tests;

use tests::{
    generate_arith_eq_384_tests, generate_arith_eq_tests, generate_bigint_tests,
    generate_cargo_toml, generate_keccakf_tests, generate_main_file, generate_sha256f_tests,
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

    /// Output path for individual test files
    #[arg(long, short)]
    output_path: Option<PathBuf>,
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

    // Determine output directory
    let output_dir = if let Some(ref output_path) = args.output_path {
        // Use provided output path (can be relative or absolute)
        if output_path.is_absolute() {
            output_path.clone()
        } else {
            std::env::current_dir().unwrap().join(output_path)
        }
    } else {
        // Default: build/src directory
        current_dir.join("build").join("src")
    };

    fs::create_dir_all(&output_dir).expect("Failed to create output directory");

    // Generate each test module and collect their info
    let mut modules = Vec::new();

    let (fn_name, file_name) = generate_arith_eq_tests(&output_dir, max_tests);
    modules.push((fn_name, file_name));

    let (fn_name, file_name) = generate_arith_eq_384_tests(&output_dir, max_tests);
    modules.push((fn_name, file_name));

    let (fn_name, file_name) = generate_bigint_tests(&output_dir, max_tests);
    modules.push((fn_name, file_name));

    let (fn_name, file_name) = generate_keccakf_tests(&output_dir, max_tests);
    modules.push((fn_name, file_name));

    let (fn_name, file_name) = generate_sha256f_tests(&output_dir, max_tests);
    modules.push((fn_name, file_name));

    // Only generate main.rs and Cargo.toml if not using custom output path
    if args.output_path.is_none() {
        let build_dir = current_dir.join("build");

        // Generate main.rs to call all test modules
        generate_main_file(&output_dir, &modules);

        // Generate Cargo.toml
        generate_cargo_toml(&build_dir);

        println!("\n✓ Test program generated successfully at: {}", build_dir.display());
    } else {
        println!("\n✓ Test files generated successfully at: {}", output_dir.display());
    }
}
