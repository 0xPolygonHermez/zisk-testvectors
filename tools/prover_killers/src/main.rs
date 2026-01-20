use clap::Parser;
use core::cmp::max;
use hex::{decode, encode};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use serde_json::Value;
use std::fs::{create_dir_all, read_dir, write, File};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Args {
    /// Input JSON files or directories
    inputs: Vec<String>,

    /// Output directory (default: current directory)
    #[clap(short, long, default_value = ".")]
    output_dir: String,

    /// Output filename (default: prover_killers.rs)
    #[clap(short, long, default_value = "prover_killers.rs")]
    filename: String,

    /// Verbose output
    #[clap(short, long, default_value_t = false)]
    verbose: bool,
}

fn collect_json_files(input: &str) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    let path = Path::new(input);

    if path.is_file() {
        // Single file
        if input.ends_with(".json") {
            files.push(path.to_path_buf());
        }
    } else if path.is_dir() {
        // Directory
        for entry in read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                files.push(path);
            }
        }
    }

    Ok(files)
}

fn parse_modexp_input(hexstr: &str) -> Option<(usize, usize, usize, String, String, String)> {
    const MIN_INPUT_LEN: usize = 96; // 3 * 32 bytes for base_len, exp_len, mod_len

    let s = hexstr.strip_prefix("0x").unwrap_or(hexstr);
    let data = match decode(s) {
        Ok(d) => d,
        Err(_) => return None,
    };
    if data.len() < MIN_INPUT_LEN {
        return None;
    }

    // Parse 32-byte big-endian lengths
    let be_u32 = |slice: &[u8]| -> usize {
        let mut v: usize = 0;
        for &b in slice {
            v = (v << 8) | (b as usize);
        }
        v
    };
    let base_len = be_u32(&data[0..32]);
    let exp_len = be_u32(&data[32..64]);
    let mod_len = be_u32(&data[64..96]);

    let mut pos = MIN_INPUT_LEN;
    if data.len() < pos + base_len + exp_len + mod_len {
        return None;
    }

    let base = encode(&data[pos..pos + base_len]);
    pos += base_len;
    let exp = encode(&data[pos..pos + exp_len]);
    pos += exp_len;
    let modu = encode(&data[pos..pos + mod_len]);

    Some((base_len, exp_len, mod_len, base, exp, modu))
}

fn find_tx_input(tx_val: &Value) -> Option<(String, Option<Value>)> {
    let mut inner = tx_val;
    if let Some(t) = tx_val.get("transaction") {
        inner = t;
    }

    // Handle wrapper objects like "Legacy": {...}
    if let Some(obj) = inner.as_object() {
        if obj.len() == 1 {
            if let Some((_k, v)) = obj.iter().next() {
                inner = v;
            }
        }
    }

    if let Some(inp) = inner.get("input").or(inner.get("data")) {
        if let Some(s) = inp.as_str() {
            let gas = inner.get("gas_limit").or_else(|| inner.get("gasLimit")).cloned();
            return Some((s.to_string(), gas));
        }
    }
    None
}

fn hex_to_biguint(hex: &str) -> BigUint {
    if hex.is_empty() {
        return BigUint::ZERO;
    }

    let bytes = decode(hex).unwrap_or_default();
    BigUint::from_bytes_be(&bytes)
}

fn bigint_to_u256_array(value: &BigUint) -> String {
    let bytes = value.to_bytes_le();
    let mut padded_bytes = vec![0u8; ((bytes.len() + 31) / 32) * 32]; // Round up to nearest 32 bytes

    if !bytes.is_empty() {
        padded_bytes[..bytes.len()].copy_from_slice(&bytes);
    }

    let mut u256s = Vec::new();

    // Convert bytes to U256 chunks (32 bytes per U256)
    for chunk in padded_bytes.chunks(32) {
        let mut u256_bytes = [0u8; 32];
        u256_bytes.copy_from_slice(chunk);

        // Convert 32 bytes to 4 u64s in little-endian format
        let mut u64s = [0u64; 4];
        for i in 0..4 {
            let start = i * 8;
            let mut u64_bytes = [0u8; 8];
            u64_bytes.copy_from_slice(&u256_bytes[start..start + 8]);
            u64s[i] = u64::from_le_bytes(u64_bytes);
        }

        u256s.push(format!(
            "U256::from_u64s(&[0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}])",
            u64s[0], u64s[1], u64s[2], u64s[3]
        ));
    }

    // Remove trailing zero U256s
    while u256s.len() > 1
        && u256s.last() == Some(&"U256::from_u64s(&[0x0, 0x0, 0x0, 0x0])".to_string())
    {
        u256s.pop();
    }

    if u256s.is_empty()
        || (u256s.len() == 1 && u256s[0] == "U256::from_u64s(&[0x0, 0x0, 0x0, 0x0])")
    {
        "vec![U256::ZERO]".to_string()
    } else {
        format!("vec![\n\t\t\t{}\n\t\t]", u256s.join(",\n\t\t\t"))
    }
}

fn hex_to_u256_array(hex: &str) -> String {
    let bigint = hex_to_biguint(hex);
    bigint_to_u256_array(&bigint)
}

fn compute_modexp_and_gas(base_hex: &str, exp_hex: &str, mod_hex: &str) -> (usize, String, u64) {
    let base = hex_to_biguint(base_hex);
    let exp = hex_to_biguint(exp_hex);
    let modulus = hex_to_biguint(mod_hex);

    // Compute the length of each input as the number of bytes
    let base_len = if base.is_zero() { 0 } else { (base.bits() + 7) / 8 };
    let exp_len = if exp.is_zero() { 0 } else { (exp.bits() + 7) / 8 };
    let mod_len = if modulus.is_zero() { 0 } else { (modulus.bits() + 7) / 8 };

    let result = if modulus.is_zero() { BigUint::ZERO } else { base.modpow(&exp, &modulus) };
    let gas = modexp_gas(base_len, exp_len, mod_len, &exp);

    let result_array = bigint_to_u256_array(&result);
    let result_len = if result.is_zero() { 1 } else { (result.bits() + 255) / 256 };

    (result_len as usize, result_array, gas)
}

fn extract_from_file(
    path: &Path,
) -> Result<Vec<(String, String, String, String, usize, String, u64)>, String> {
    let mut f = File::open(path).map_err(|e| format!("open {}: {}", path.display(), e))?;
    let mut txt = String::new();
    f.read_to_string(&mut txt).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let j: Value =
        serde_json::from_str(&txt).map_err(|e| format!("json {}: {}", path.display(), e))?;

    let name = j
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(path.file_name().and_then(|p| p.to_str()).unwrap_or(""))
        .to_string();

    let mut results = Vec::new();
    let txs = j
        .pointer("/block_and_witness/block/body/transactions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for tx in txs {
        if let Some((inp, _gas_val)) = find_tx_input(&tx) {
            if let Some((_base_len, _exp_len, _mod_len, base_hex, exp_hex, mod_hex)) =
                parse_modexp_input(&inp)
            {
                let base_array = hex_to_u256_array(&base_hex);
                let exp_array = hex_to_u256_array(&exp_hex);
                let mod_array = hex_to_u256_array(&mod_hex);

                // Compute expected result
                let (expected_len, expected_result, gas) =
                    compute_modexp_and_gas(&base_hex, &exp_hex, &mod_hex);

                results.push((
                    base_array,
                    exp_array,
                    mod_array,
                    name.clone(),
                    expected_len,
                    expected_result,
                    gas,
                ));
            }
        }
    }
    Ok(results)
}

// Calculate gas cost according to EIP 2565:
// https://eips.ethereum.org/EIPS/eip-2565
pub fn modexp_gas(base_length: u64, exp_length: u64, mod_length: u64, exp_highp: &BigUint) -> u64 {
    fn calculate_iteration_count(exp_length: u64, exp_highp: &BigUint) -> u64 {
        let mut iteration_count: u64 = 0;

        if exp_length <= 32 && exp_highp.is_zero() {
            iteration_count = 0;
        } else if exp_length <= 32 {
            iteration_count = exp_highp.bits() as u64 - 1;
        } else if exp_length > 32 {
            iteration_count = (8u64.saturating_mul(exp_length - 32))
                .saturating_add(max(1, exp_highp.bits() as u64) - 1);
        }

        max(iteration_count, 1)
    }

    fn calculate_multiplication_complexity(base_length: u64, mod_length: u64) -> BigUint {
        let max_length = max(base_length, mod_length);
        let mut words = max_length / 8;
        if max_length % 8 > 0 {
            words += 1;
        }
        let words = BigUint::from(words);
        words.clone() * words.clone()
    }

    let multiplication_complexity = calculate_multiplication_complexity(base_length, mod_length);
    let iteration_count = calculate_iteration_count(exp_length, exp_highp);
    let gas = (multiplication_complexity * BigUint::from(iteration_count)) / BigUint::from(3u8);
    max(200, gas.to_u64().unwrap())
}

fn generate_rust_code(
    test_cases: Vec<(String, String, String, String, usize, String, u64)>,
) -> String {
    let mut code = String::new();

    // File header
    code.push_str("// Auto-generated Prover Killer test cases\n\n");
    code.push_str("#![no_main]\n");
    code.push_str("ziskos::entrypoint!(main);\n\n");
    code.push_str("use ziskos::array_lib::{modexp, U256};\n\n"); // Add all the necessary imports
    code.push_str("fn main() {\n");

    // Generate individual test functions
    for (
        i,
        (base_array, exp_array, mod_array, original_name, expected_len, expected_result, gas),
    ) in test_cases.iter().enumerate()
    {
        // Compute the number of iteration until 10M gas is reached
        let iterations = 10_000_000 / max(*gas, 1);

        code.push_str(&format!("\t// Test #{i}: {original_name}\n"));
        code.push_str(&format!("\tlet base = {base_array};\n"));
        code.push_str(&format!("\tlet exp = {exp_array};\n"));
        code.push_str(&format!("\tlet modulus = {mod_array};\n"));
        code.push_str(&format!(
            "\tfor _ in 0..{iterations} {{ modexp(&base, &exp, &modulus); }}\n"
        ));
        code.push_str(&format!("\tlet result = modexp(&base, &exp, &modulus);\n"));
        code.push_str(&format!("\tlet expected = {expected_result};\n"));
        code.push_str(&format!("\tassert_eq!(result.len(), {expected_len});\n"));
        code.push_str(&format!("\tassert_eq!(result, expected);\n\n"));
        break;
    }

    // File footer
    code.push_str("}\n");

    code
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut all_files = Vec::new();

    // Create output directory if it doesn't exist
    let output_dir = Path::new(&args.output_dir);
    create_dir_all(output_dir)?;

    // Collect files from all inputs (files or directories)
    for input in &args.inputs {
        match collect_json_files(input) {
            Ok(mut files) => all_files.append(&mut files),
            Err(e) => eprintln!("Warning: failed to process '{}': {}", input, e),
        }
    }

    if all_files.is_empty() {
        eprintln!("No JSON files found in the specified inputs");
        return Ok(());
    }

    if args.verbose {
        println!("Found {} JSON files", all_files.len());
    }

    let mut all_test_cases = Vec::new();

    for f in all_files {
        match extract_from_file(&f) {
            Ok(test_cases) => {
                if !test_cases.is_empty() {
                    if args.verbose {
                        println!("Extracted {} test cases from {}", test_cases.len(), f.display());
                    }
                    all_test_cases.extend(test_cases);
                }
            }
            Err(e) => eprintln!("warning: {}: {}", f.display(), e),
        }
    }

    if all_test_cases.is_empty() {
        eprintln!("No modexp test cases found");
        return Ok(());
    }

    let total_tests = all_test_cases.len();
    let rust_code = generate_rust_code(all_test_cases);

    // Create output file path
    let output_path = output_dir.join(&args.filename);

    // Check if file exists and show overwrite message
    if output_path.exists() {
        println!("File {} already exists, overwriting...", output_path.display());
    }

    write(&output_path, rust_code)?;

    println!("Generated Rust test file: {} with {} test cases", output_path.display(), total_tests);

    Ok(())
}
