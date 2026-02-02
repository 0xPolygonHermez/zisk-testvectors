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

Output format (Rust):
    let z = [0x..., 0x..., 0x..., 0x...];
    let r = [0x..., 0x..., 0x..., 0x...];
    let s = [0x..., 0x..., 0x..., 0x...];
    let pk = [0x..., 0x..., 0x..., 0x..., 0x..., 0x..., 0x..., 0x...];
    assert!(secp256r1_ecdsa_verify(&pk, &z, &r, &s));  // or assert!(!...)
"""

import re
import sys

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
    
    # Pad to multiple of 16 characters (64 bits)
    while len(hex_str) < 64:
        hex_str = '0' + hex_str
    
    # Split into 16-character chunks from right to left (little-endian)
    chunks = []
    for i in range(0, len(hex_str), 16):
        chunk = hex_str[len(hex_str) - 16 - i:len(hex_str) - i] if len(hex_str) - 16 - i >= 0 else hex_str[:len(hex_str) - i]
        if chunk:
            chunks.append(f"0x{chunk}")
    
    # Ensure we have exactly 4 chunks for 256-bit values
    while len(chunks) < 4:
        chunks.append("0x0000000000000000")
    
    return chunks[:4]  # Return only first 4 chunks for 256-bit


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
        match = re.match(r'(0x[0-9a-fA-F]+n?|%[A-Z_]+)\s*=>\s*([A-E])', line)
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


def generate_rust_test(test: dict, test_num: int) -> str:
    """Generate Rust code for a single test."""
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


def main():
    # Read from stdin or file
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            content = f.read()
    else:
        print("Usage: python asm_to_rust.py <input_file>")
        print("Or paste assembly code and press Ctrl+D when done:")
        content = sys.stdin.read()
    
    lines = content.split('\n')
    
    # Generate header
    print("use ziskos::zisklib::secp256r1_ecdsa_verify;")
    print()
    print("pub fn ecdsa_tests() {")
    
    i = 0
    test_num = 1
    while i < len(lines):
        line = lines[i].strip()
        
        # Look for test start (comment or first assignment)
        if (line.startswith(';') and (']' in line or 'test' in line.lower() or 'hash' in line.lower())) or \
           ('=>' in line and ('=> A' in line or '=> B' in line)):
            test, i = parse_test_block(lines, i)
            if test['expected'] is not None:
                print(generate_rust_test(test, test_num))
                test_num += 1
        else:
            i += 1
    
    print("}")


if __name__ == "__main__":
    main()