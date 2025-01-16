use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

// Define constants for the directory and file names
const OUTPUT_DIR: &str = "build/";
const FILE_NAME: &str = "input.bin";

fn main() -> io::Result<()> {
    let number_to_hash: u64 = 20;
    let full_keccak: bool = false;

    // Ensure the output directory exists
    let output_dir = Path::new(OUTPUT_DIR);
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    // Create the file and write the inputs
    let file_path = output_dir.join(FILE_NAME);
    let mut file = File::create(&file_path)?;
    file.write_all(&number_to_hash.to_le_bytes())?;
    file.write_all(&[full_keccak as u8])?;

    Ok(())
}
