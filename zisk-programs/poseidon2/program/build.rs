use std::fs;
use std::io;
use std::path::Path;

use zisk_sdk::ZiskIO;

// Define constants for the directory and file names
const OUTPUT_DIR: &str = "build/";
const FILE_NAME: &str = "input.bin";

fn main() -> io::Result<()> {
    let hash_values: [u64; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    // Ensure the output directory exists
    let output_dir = Path::new(OUTPUT_DIR);
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    // Create the file and write the inputs
    let file_path = output_dir.join(FILE_NAME);
   
    let stdin = zisk_sdk::ZiskStdin::new();
    stdin.write(&hash_values);
    stdin.save(&file_path).expect("Failed to write input to file");

    Ok(())
}
