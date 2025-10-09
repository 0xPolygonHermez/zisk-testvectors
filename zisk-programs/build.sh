#!/bin/bash

# Build script for zisk programs
# Compiles all programs and copies binaries as .elf files

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROGRAMS_DIR="$SCRIPT_DIR"
TARGET_DIR="$PROGRAMS_DIR/target/riscv64ima-zisk-zkvm-elf/release"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Building zisk programs...${NC}"

# Change to programs directory
cd "$PROGRAMS_DIR"

# Build all programs with cargo-zisk
cargo clean
if ! cargo-zisk build --release; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"
echo -e "${BLUE}Copying binaries...${NC}"

# List of programs (matching the workspace members)
PROGRAMS=(
    "arith_eq_384_gen"
    "arith_eq_gen"
    "arith_eq_pow"
    "bls12_381"
    "bn254"
    "ecrecover"
    "fcall"
    "fcall_msb"
    "keccak"
    "modexp"
    "prover_killers"
    "sha256"
)

# Copy binaries to their respective folders
for program in "${PROGRAMS[@]}"; do
    BINARY_PATH="$TARGET_DIR/$program"
    DEST_DIR="$PROGRAMS_DIR/$program"
    DEST_FILE="$DEST_DIR/$program.elf"
    
    if [ -f "$BINARY_PATH" ]; then
        # Create destination directory if it doesn't exist
        mkdir -p "$DEST_DIR"
        
        # Copy binary with .elf extension
        cp "$BINARY_PATH" "$DEST_FILE"
    else
        echo -e "${RED}✗${NC} Binary not found: $BINARY_PATH"
    fi
done

echo -e "${GREEN}All binaries copied successfully!${NC}"