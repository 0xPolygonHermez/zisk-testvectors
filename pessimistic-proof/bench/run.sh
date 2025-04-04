#!/bin/bash

processors=6
threads=37

# cargo-zisk command path
cargo_zisk="$HOME/zisk/target/release/cargo-zisk"

# witness library path
witness_lib="$HOME/zisk/target/release/libzisk_witness.so"

# mpi command
mpi="mpirun --bind-to none -np $processors -x OMP_NUM_THREADS=$threads"

# Path for the elf program
elf_program="../program/pessimistic-proof-program-keccak.elf"

# Path for the input files
inputs_dir="../inputs/bench"

# Array with the list of input files (modify as needed)
files=(
  "pp_input_1_1.bin"
  "pp_input_2_1.bin"
  "pp_input_4_1.bin"
  "pp_input_8_1.bin"
  "pp_input_10_10.bin"
  "pp_input_16_1.bin"
  "pp_input_32_1.bin"
  "pp_input_50_50.bin"
  "pp_input_64_1.bin"
  "pp_input_100_100.bin"
  "pp_input_128_1.bin"
  "pp_input_256_1.bin"
  "pp_input_511_1.bin"
  "pp_input_767_1.bin"
  "pp_input_1024_1.bin"
  "pp_input_2048_1.bin"
  "pp_input_4096_1.bin"
)

# Function to print a bold green message inside a '#' box.
print_boxed_message() {
  local message="$1"
  local message_box="# $message #"
  local len=${#message_box}
  local border
  border=$(printf '%*s' "$len" | tr ' ' '#')

  echo -e "\033[1;32m$border"
  echo "$message_box"
  echo -e "$border\033[0m"
}

# Loop through the files in the array
for file in "${files[@]}"; do
  # Ensure that the file exists
  if [[ ! -e "$inputs_dir/$file" ]]; then
    echo "File not found: $file. Skipping."
    continue
  fi
  
  # Extract the filename without the path
  filename=$(basename "$file")
  
  # Remove the ".bin" extension from the filename
  output_folder="proof_${filename%.bin}"

  print_boxed_message "Generating proof for input file: $filename"

  # Generate the proof, show the log in real time, and capture the output
  output="$output_folder/$output_folder.log"  # Create a temporary file to store the output
  $mpi "$cargo_zisk" prove -e "$elf_program" -i "$inputs_dir/$file" -w "$witness_lib" --proving-key "$HOME/.zisk/provingKey" -o "$output_folder" -a 2>&1 | tee "$output"
  
  # Read only the first matching line
  proof_time=$(grep -oP '\[INFO \]      stop <<< GENERATING_VADCOP_PROOF \K[0-9]+(?=ms)' "$output" | head -n 1)

  # Clean up temporary file
  # rm "$output"

  if [[ -n "$proof_time" ]]; then
    print_boxed_message "Proof generation time for $filename: ${proof_time}ms"
  else
    echo "Proof generation time not found for $filename."
  fi

  # Pause until a key is pressed
  echo -e "\nPress any key to continue..."
  read -n 1 -s  
done
