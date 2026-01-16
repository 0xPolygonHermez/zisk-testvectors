use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use bytemuck::cast_slice;

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
    let mut file = File::create(&file_path)?;
    file.write_all(cast_slice(&hash_values))?;
    Ok(())
}
