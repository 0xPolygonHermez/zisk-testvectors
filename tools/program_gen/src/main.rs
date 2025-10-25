use clap::Parser;
use path_clean::PathClean;
use std::fs;
use std::path::Path;

mod tests;

use tests::generate_arith_eq_tests;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    minimal: bool,
}

fn main() {
    let args = Args::parse();

    let current_file_path = Path::new(file!());

    let current_dir = current_file_path
        .parent() // → tools/program_gen/src
        .and_then(|p| p.parent()) // → tools/program_gen
        .and_then(|p| p.parent()) // → tools
        .and_then(|p| p.parent()) // → zisk-testvectors
        .unwrap();

    let target_output_path = current_dir.join("zisk-programs/precompiles/program/src").clean();

    // Ensure output directory exists
    fs::create_dir_all(&target_output_path).expect("Failed to create test directory");

    // Generate different types of tests
    generate_arith_eq_tests(&target_output_path, args.minimal);
}
