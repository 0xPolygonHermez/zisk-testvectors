use std::fs;
use std::io;
use std::path::Path;

use zisk_sdk::ZiskIO;

// Define constants for the directory and file names
const OUTPUT_DIR: &str = "build/";
const FILE_NAME: &str = "input.bin";

// Sha256fSM: circuit_size = 31488, num_available_circuits = 133, num_available_sha256fs = 7448
fn main() -> io::Result<()> {
    let num_sha256fs: u64 = 1;

    // Ensure the output directory exists
    let output_dir = Path::new(OUTPUT_DIR);
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    // Create the file and write the inputs
    let file_path = output_dir.join(FILE_NAME);
    
    let stdin = zisk_sdk::ZiskStdin::new();
    stdin.write(&num_sha256fs);
    stdin.save(&file_path).expect("Failed to write input to file");

    Ok(())
}
