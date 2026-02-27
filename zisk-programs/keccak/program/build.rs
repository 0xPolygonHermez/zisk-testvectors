use std::fs;
use std::io;
use std::path::Path;

use zisk_sdk::ZiskIO;

const OUTPUT_DIR: &str = "../inputs";

fn main() -> io::Result<()> {
    let num_keccakfs: u64 = 1;

    // Ensure the output directory exists
    let output_dir = Path::new(OUTPUT_DIR);
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    // Create the file and write the inputs
    let file_name = format!("input_keccakf_{}.bin", num_keccakfs);
    let file_path = output_dir.join(file_name);

    let stdin = zisk_sdk::ZiskStdin::new();
    stdin.write(&num_keccakfs);
    stdin.save(&file_path).expect("Failed to write input to file");

    Ok(())
}
