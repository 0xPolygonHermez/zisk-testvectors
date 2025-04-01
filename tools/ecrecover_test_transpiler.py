import re

def is_hex_line(line):
    return re.match(r"^0x[0-9a-fA-F]+n?\s*=>\s*[A-Z]$", line)

def is_assert_line(line):
    return re.match(r"^0x[0-9a-fA-F]+n?\s*:\s*ASSERT", line)

def hex_to_be_bytes(x_hex, v=32):
    """Convert a 256-bit hex string to 32 big-endian bytes"""
    x = int(x_hex, 16)
    return [f"0x{(x >> (8 * ((v-1) - i))) & 0xFF:02X}" for i in range(v)]

def hex_to_byte_array(hex_str, length=20):
    """Convert a hex string to a byte array of given length"""
    hex_str = hex_str[2:]
    hex_str = hex_str.rjust(length * 2, '0')
    bytes_out = [f"0x{hex_str[i:i+2].upper()}" for i in range(0, length * 2, 2)]
    return reversed(bytes_out)

def parse_test_blocks(file_path):
    with open(file_path) as f:
        lines = f.readlines()

    blocks = []
    current = {}
    assert_count = 0

    def maybe_add_block():
        if (
            assert_count == 1
            and {"A", "B", "C", "D", "expected", "mode"}.issubset(current)
        ):
            blocks.append(current)

    for line in lines:
        line = line.strip()

        if not line:
            maybe_add_block()
            current = {}
            assert_count = 0
            continue

        if is_hex_line(line):
            try:
                hex_val, var = line.split("=>")
                hex_val = hex_val.strip().rstrip("n").lower()
                var = var.strip()
                if var in {"A", "B", "C", "D"}:
                    current[var] = hex_val
            except ValueError:
                continue

        elif line.startswith(":CALL"):
            if "ecrecover_precompiled" in line:
                current["mode"] = True
            elif "ecrecover_tx" in line:
                current["mode"] = False

        elif is_assert_line(line):
            assert_count += 1
            if assert_count == 1:
                expected = line.split(":")[0].strip().rstrip("n").lower()
                if len(expected) <= 42:
                    current["expected"] = expected

    # Also handle final block
    maybe_add_block()

    return blocks

def print_rust_tests(blocks):
    for i, block in enumerate(blocks):
        print(f"// Test {i + 1}")

        hash_words = hex_to_be_bytes(block["A"], 32)
        r_words = hex_to_be_bytes(block["B"], 32)
        s_words = hex_to_be_bytes(block["C"], 32)
        v_int = int(block["D"], 16)
        if v_int == 28:
            v_int = "0x01"
        elif v_int == 27:
            v_int = "0x00"
        expected_bytes = hex_to_be_bytes(block["expected"], 20)
        mode_str = "true" if block.get("mode") else "false"

        print(f"let hash = [{', '.join(hash_words)}];")
        print(f"let sig = [{', '.join(r_words)}, {', '.join(s_words)}, {v_int}];")
        print(f"let (addr, error_code) = ecrecover(&sig, &hash, {mode_str});")
        print(f"let addr_expected = [{', '.join(expected_bytes)}];")
        print("assert_eq!(error_code, 0);")
        print("assert_eq!(addr, addr_expected);\n")

file_path = "tmp/ecrecover_test.zkasm"
blocks = parse_test_blocks(file_path)
print_rust_tests(blocks)