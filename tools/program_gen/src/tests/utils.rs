use serde::{de::Error, Deserialize, Deserializer};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Add256 {
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
pub struct BigIntPre {
    #[serde(default)]
    pub add256: Vec<Add256>,
    // Add other bigint test case vectors here as needed
}

#[derive(Debug, Deserialize)]
pub struct Keccakf {
    #[serde(deserialize_with = "parse_hex_to_u64_array")]
    pub state_in: [u64; 25],
    #[serde(deserialize_with = "parse_hex_to_u64_array")]
    pub state_out: [u64; 25],
}

#[derive(Debug, Deserialize)]
pub struct KeccakfPre {
    #[serde(default)]
    pub keccakf: Vec<Keccakf>,
}

#[derive(Debug, Deserialize)]
pub struct Sha256f {
    #[serde(deserialize_with = "parse_hex_to_u64_array")]
    pub state_in: [u64; 4],
    #[serde(deserialize_with = "parse_hex_to_u64_array")]
    pub input: [u64; 8],
    #[serde(deserialize_with = "parse_hex_to_u64_array")]
    pub state_out: [u64; 4],
}

#[derive(Debug, Deserialize)]
pub struct Sha256fPre {
    #[serde(default)]
    pub sha256f: Vec<Sha256f>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "test_type")]
pub enum TestData {
    BigInt(BigIntPre),
    Keccakf(KeccakfPre),
    Sha256f(Sha256fPre),
    // Add other test data types here as needed
}

pub fn load_test_data_from_json(json_path: &str) -> TestData {
    let current_file_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(json_path);

    let data = fs::read_to_string(&current_file_path)
        .unwrap_or_else(|_| panic!("Failed to read test data file: {}", json_path));
    serde_json::from_str(&data)
        .unwrap_or_else(|_| panic!("Failed to parse test data JSON: {}", json_path))
}

pub fn load_bigint_test_data(json_path: &str) -> BigIntPre {
    match load_test_data_from_json(json_path) {
        TestData::BigInt(data) => data,
        other => panic!("Expected BigInt test data, but got: {:?}", other),
    }
}

pub fn load_keccakf_test_data(json_path: &str) -> KeccakfPre {
    match load_test_data_from_json(json_path) {
        TestData::Keccakf(data) => data,
        other => panic!("Expected Keccakf test data, but got: {:?}", other),
    }
}

pub fn load_sha256f_test_data(json_path: &str) -> Sha256fPre {
    match load_test_data_from_json(json_path) {
        TestData::Sha256f(data) => data,
        other => panic!("Expected Sha256f test data, but got: {:?}", other),
    }
}

fn parse_hex_to_u64_array<'de, D, const N: usize>(deserializer: D) -> Result<[u64; N], D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;

    // Remove "0x" prefix if present
    let hex_str = s.trim_start_matches("0x");

    // Pad with a leading zero if odd length
    let padded_hex = if hex_str.len() % 2 == 1 {
        format!("0{}", hex_str)
    } else {
        hex_str.to_string()
    };

    // Parse the hex string to bytes
    let bytes =
        hex::decode(padded_hex).map_err(|e| D::Error::custom(format!("Invalid hex string: {}", e)))?;

    // Calculate required byte size (N * 8 bytes per u64)
    let required_bytes = N * 8;

    // Pad with zeros if needed
    let mut padded = vec![0u8; required_bytes];
    let start = required_bytes - bytes.len().min(required_bytes);
    padded[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(required_bytes)..]);

    // Convert to [u64; N] in little-endian order
    let mut result = vec![0u64; N];
    for (i, r) in result.iter_mut().enumerate() {
        let offset = required_bytes - (i + 1) * 8;
        *r = u64::from_le_bytes([
            padded[offset + 7],
            padded[offset + 6],
            padded[offset + 5],
            padded[offset + 4],
            padded[offset + 3],
            padded[offset + 2],
            padded[offset + 1],
            padded[offset],
        ]);
    }

    Ok(result.try_into().unwrap_or_else(|_| unreachable!()))
}

fn parse_hex_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;

    // Remove "0x" prefix if present
    let hex_str = s.trim_start_matches("0x");
    
    // Pad with a leading zero if odd length
    let padded_hex = if hex_str.len() % 2 == 1 {
        format!("0{}", hex_str)
    } else {
        hex_str.to_string()
    };

    u64::from_str_radix(&padded_hex, 16)
        .map_err(|e| D::Error::custom(format!("Invalid u64 hex: {}", e)))
}
