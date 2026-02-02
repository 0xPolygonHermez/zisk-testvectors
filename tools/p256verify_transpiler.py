#!/usr/bin/env python3
"""
Tool to convert secp256r1 ECDSA test vectors from assembly format to Rust format.

Input format (assembly):
    0xhex_value => A ; hash
    0xhex_value => B ; r
    0xhex_value => C ; s
    0xhex_value => D ; x
    0xhex_value => E ; y
    :CALL(p256verify)
    0|1 :ASSERT  ; expected result
    B => A
    0-10 :ASSERT ; error code (ignored)

Output formats:
1. Chunk format (for ziskos direct usage):
    let z = [0x..., 0x..., 0x..., 0x...];
    let r = [0x..., 0x..., 0x..., 0x...];
    let s = [0x..., 0x..., 0x..., 0x...];
    let pk = [0x..., 0x..., 0x..., 0x..., 0x..., 0x..., 0x..., 0x...];
    assert!(secp256r1_ecdsa_verify(&pk, &z, &r, &s));

2. Byte format (for Crypto trait - revm precompile):
    let msg = hex_to_32("...");
    let sig = build_sig("...", "...");
    let pk = build_pk("...", "...");
    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk));
"""

import re
import sys
import argparse

def hex_to_u64_chunks(hex_str: str) -> list[str]:
    """
    Convert a hex string to little-endian u64 chunks.
    Example: 0x2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838
    -> [0x69c8c4df6c732838, 0x2903269919f70860, 0xdcfe467828128bad, 0x2927b10512bae3ed]
    """
    # Remove 0x prefix and 'n' suffix if present
    hex_str = hex_str.strip()
    if hex_str.endswith('n'):
        hex_str = hex_str[:-1]
    if hex_str.startswith('0x') or hex_str.startswith('0X'):
        hex_str = hex_str[2:]
    
    # Pad to 64 characters (32 bytes = 256 bits)
    hex_str = hex_str.zfill(64)
    
    # Split into 16-character chunks from right to left (little-endian)
    chunks = []
    for i in range(4):
        start = 64 - (i + 1) * 16
        end = 64 - i * 16
        chunk = hex_str[start:end]
        chunks.append(f"0x{chunk}")
    
    return chunks


def normalize_hex(hex_str: str) -> str:
    """Normalize hex string to 64 characters without 0x prefix."""
    hex_str = hex_str.strip()
    if hex_str.endswith('n'):
        hex_str = hex_str[:-1]
    if hex_str.startswith('0x') or hex_str.startswith('0X'):
        hex_str = hex_str[2:]
    return hex_str.zfill(64)


def parse_test_block(lines: list[str], start_idx: int) -> tuple[dict, int]:
    """
    Parse a single test block starting at start_idx.
    Returns (test_data, next_index).
    """
    test = {
        'hash': None,
        'r': None,
        's': None,
        'x': None,
        'y': None,
        'expected': None,
        'comment': None
    }
    
    i = start_idx
    
    # Look for comment line first
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith(';'):
            test['comment'] = line[1:].strip()
            i += 1
            break
        elif '=>' in line:
            break
        i += 1
    
    # Parse assignments
    while i < len(lines):
        line = lines[i].strip()
        
        if not line or line.startswith(';'):
            i += 1
            continue
            
        # Match: 0xhex_value => A ; comment
        match = re.match(r'(0x[0-9a-fA-F]+n?|%[A-Z_0-9]+)\s*=>\s*([A-E])', line)
        if match:
            value = match.group(1)
            register = match.group(2)
            
            # Handle constants like %SECP256R1_G_X
            if value.startswith('%'):
                if 'G_X' in value:
                    value = '0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
                elif 'G_Y' in value:
                    value = '0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'
            
            if register == 'A':
                test['hash'] = value
            elif register == 'B':
                test['r'] = value
            elif register == 'C':
                test['s'] = value
            elif register == 'D':
                test['x'] = value
            elif register == 'E':
                test['y'] = value
            i += 1
            continue
        
        # Match: :CALL(p256verify)
        if ':CALL(p256verify)' in line:
            i += 1
            continue
        
        # Match: 0|1 :ASSERT
        match = re.match(r'(\d+)\s*:ASSERT', line)
        if match and test['expected'] is None:
            test['expected'] = match.group(1) == '1'
            i += 1
            # Skip the next "B => A" and error code assert
            while i < len(lines):
                next_line = lines[i].strip()
                if 'B => A' in next_line:
                    i += 1
                    continue
                match2 = re.match(r'\d+\s*:ASSERT', next_line)
                if match2:
                    i += 1
                    break
                if not next_line or next_line.startswith(';'):
                    break
                i += 1
            break
        
        i += 1
    
    return test, i


def generate_rust_test_chunks(test: dict, test_num: int) -> str:
    """Generate Rust code for a single test in chunk format (for ziskos)."""
    if not all([test['hash'], test['r'], test['s'], test['x'], test['y'], test['expected'] is not None]):
        return f"    // Test {test_num}: incomplete data\n"
    
    z_chunks = hex_to_u64_chunks(test['hash'])
    r_chunks = hex_to_u64_chunks(test['r'])
    s_chunks = hex_to_u64_chunks(test['s'])
    x_chunks = hex_to_u64_chunks(test['x'])
    y_chunks = hex_to_u64_chunks(test['y'])
    
    comment = f"    // {test['comment']}\n" if test['comment'] else ""
    
    result = comment
    result += f"    let z{test_num} = [{', '.join(z_chunks)}];\n"
    result += f"    let r{test_num} = [{', '.join(r_chunks)}];\n"
    result += f"    let s{test_num} = [{', '.join(s_chunks)}];\n"
    result += f"    let pk{test_num} = [\n"
    result += f"        {', '.join(x_chunks)},\n"
    result += f"        {', '.join(y_chunks)},\n"
    result += f"    ];\n"
    
    if test['expected']:
        result += f"    assert!(secp256r1_ecdsa_verify(&pk{test_num}, &z{test_num}, &r{test_num}, &s{test_num}));\n"
    else:
        result += f"    assert!(!secp256r1_ecdsa_verify(&pk{test_num}, &z{test_num}, &r{test_num}, &s{test_num}));\n"
    
    return result


def generate_rust_test_bytes(test: dict, test_num: int) -> str:
    """Generate Rust code for a single test in byte format (for Crypto trait)."""
    if not all([test['hash'], test['r'], test['s'], test['x'], test['y'], test['expected'] is not None]):
        return f"    // Test {test_num}: incomplete data\n"
    
    msg_hex = normalize_hex(test['hash'])
    r_hex = normalize_hex(test['r'])
    s_hex = normalize_hex(test['s'])
    x_hex = normalize_hex(test['x'])
    y_hex = normalize_hex(test['y'])
    
    comment = f"    // {test['comment']}\n" if test['comment'] else ""
    
    result = comment
    result += f"    let msg = hex_to_32(\"{msg_hex}\");\n"
    result += f"    let sig = build_sig(\"{r_hex}\", \"{s_hex}\");\n"
    result += f"    let pk = build_pk(\"{x_hex}\", \"{y_hex}\");\n"
    
    if test['expected']:
        result += f"    assert!(crypto.secp256r1_verify_signature(&msg, &sig, &pk), \"Test {test_num} failed\");\n"
    else:
        result += f"    assert!(!crypto.secp256r1_verify_signature(&msg, &sig, &pk), \"Test {test_num} should fail\");\n"
    
    return result


def generate_header_chunks():
    """Generate header for chunk format output."""
    return """use ziskos::zisklib::secp256r1_ecdsa_verify;

use crate::constants::{G_X, G_Y};

// Tests from https://github.com/ethereum/go-ethereum/blob/master/core/vm/testdata/precompiles/p256Verify.json
pub fn ecdsa_tests() {
"""


def generate_header_bytes():
    """Generate header for byte format output."""
    return """use revm::precompile::Crypto;

/// Convert hex string (without 0x prefix) to 32-byte array
fn hex_to_32(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).expect("valid hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

/// Build signature from r and s hex strings (32 bytes each, big-endian)
fn build_sig(r: &str, s: &str) -> [u8; 64] {
    let mut sig = [0u8; 64];
    let r_bytes = hex::decode(r).expect("valid hex");
    let s_bytes = hex::decode(s).expect("valid hex");
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s_bytes);
    sig
}

/// Build public key from x and y hex strings (32 bytes each, big-endian)
fn build_pk(x: &str, y: &str) -> [u8; 64] {
    let mut pk = [0u8; 64];
    let x_bytes = hex::decode(x).expect("valid hex");
    let y_bytes = hex::decode(y).expect("valid hex");
    pk[..32].copy_from_slice(&x_bytes);
    pk[32..].copy_from_slice(&y_bytes);
    pk
}

pub fn secp256r1_tests(crypto: &impl Crypto) {
"""


def generate_footer():
    """Generate footer for output."""
    return "}\n"


def main():
    parser = argparse.ArgumentParser(
        description='Convert secp256r1 ECDSA test vectors from assembly to Rust format'
    )
    parser.add_argument('input_file', nargs='?', help='Input assembly file')
    parser.add_argument(
        '-f', '--format',
        choices=['chunks', 'bytes', 'both'],
        default='chunks',
        help='Output format: chunks (ziskos), bytes (Crypto trait), or both'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file (default: stdout)'
    )
    
    args = parser.parse_args()
    
    # Read input
    if args.input_file:
        with open(args.input_file, 'r') as f:
            content = f.read()
    else:
        print("Usage: python p256verify_transpiler.py <input_file> [-f chunks|bytes|both]", file=sys.stderr)
        print("Or paste assembly code and press Ctrl+D when done:", file=sys.stderr)
        content = sys.stdin.read()
    
    lines = content.split('\n')
    
    # Parse all tests
    tests = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Look for test start (comment or first assignment)
        if (line.startswith(';') and (']' in line or 'test' in line.lower() or 'hash' in line.lower())) or \
           ('=>' in line and ('=> A' in line or '=> B' in line)):
            test, i = parse_test_block(lines, i)
            if test['expected'] is not None:
                tests.append(test)
        else:
            i += 1
    
    # Generate output
    output_lines = []
    
    if args.format in ['chunks', 'both']:
        output_lines.append(generate_header_chunks())
        for idx, test in enumerate(tests, 1):
            output_lines.append(generate_rust_test_chunks(test, idx))
        output_lines.append(generate_footer())
    
    if args.format == 'both':
        output_lines.append("\n// " + "=" * 70 + "\n")
        output_lines.append("// Byte format (for Crypto trait / revm precompile)\n")
        output_lines.append("// " + "=" * 70 + "\n\n")
    
    if args.format in ['bytes', 'both']:
        output_lines.append(generate_header_bytes())
        for idx, test in enumerate(tests, 1):
            output_lines.append(generate_rust_test_bytes(test, idx))
        output_lines.append(generate_footer())
    
    output = ''.join(output_lines)
    
    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()