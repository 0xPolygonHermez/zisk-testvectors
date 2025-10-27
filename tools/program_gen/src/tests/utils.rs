use serde::{de::Error, Deserialize, Deserializer};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Add256TestCase {
    #[serde(deserialize_with = "parse_hex_to_u64_array")]
    pub a: [u64; 4],
    #[serde(deserialize_with = "parse_hex_to_u64_array")]
    pub b: [u64; 4],
    #[serde(deserialize_with = "parse_hex_to_u64")]
    pub cin: u64,
    #[serde(deserialize_with = "parse_hex_to_u64_array")]
    pub c: [u64; 4],
    #[serde(deserialize_with = "parse_hex_to_u64")]
    pub cout: u64,
}

#[derive(Debug, Deserialize)]
pub struct BigIntTestData {
    #[serde(default)]
    pub add256: Vec<Add256TestCase>,
    // Add other bigint test case vectors here as needed
}

#[derive(Debug, Deserialize)]
#[serde(tag = "test_type")]
pub enum TestData {
    BigInt(BigIntTestData),
    // Add other test data types here as needed
}

pub fn load_test_data_from_json(json_path: &str) -> TestData {
    let current_file_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(json_path);

    let data = fs::read_to_string(&current_file_path)
        .unwrap_or_else(|_| panic!("Failed to read test data file: {}", json_path));
    serde_json::from_str(&data)
        .unwrap_or_else(|_| panic!("Failed to parse test data JSON: {}", json_path))
}

pub fn load_bigint_test_data(json_path: &str) -> BigIntTestData {
    match load_test_data_from_json(json_path) {
        TestData::BigInt(data) => data,
        // other => panic!("Expected BigInt test data, but got: {:?}", other),
    }
}

fn parse_hex_to_u64_array<'de, D>(deserializer: D) -> Result<[u64; 4], D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;

    // Remove "0x" prefix if present
    let hex_str = s.trim_start_matches("0x");

    // Parse the hex string to bytes
    let bytes =
        hex::decode(hex_str).map_err(|e| D::Error::custom(format!("Invalid hex string: {}", e)))?;

    // Pad with zeros if needed (max 32 bytes for [u64; 4])
    let mut padded = [0u8; 32];
    let start = 32 - bytes.len().min(32);
    padded[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);

    // Convert to [u64; 4] in little-endian order
    let mut result = [0u64; 4];
    for (i, r) in result.iter_mut().enumerate() {
        let offset = i * 8;
        *r = u64::from_le_bytes([
            padded[offset],
            padded[offset + 1],
            padded[offset + 2],
            padded[offset + 3],
            padded[offset + 4],
            padded[offset + 5],
            padded[offset + 6],
            padded[offset + 7],
        ]);
    }

    Ok(result)
}

fn parse_hex_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let hex_str = s.trim_start_matches("0x");
    u64::from_str_radix(hex_str, 16)
        .map_err(|e| D::Error::custom(format!("Invalid u64 hex: {}", e)))
}
