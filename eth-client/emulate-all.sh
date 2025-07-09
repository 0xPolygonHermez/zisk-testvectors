#!/bin/bash

echo "Emulate an ELF file on all input files found in a directory"

# Check that at least 2 arguments have been passed
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <ELF file> <input directory> [-l|--list -b|--begin <first_input> -e|--end <last_input>]"
    exit 1
fi

ELF_FILE="$1"
INPUT_DIR="$2"
shift 2

# Parse optional arguments
LIST=0
BEGIN=0
END=0
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -l|--list) LIST=1 ;;
        -b|--begin) BEGIN=$2; shift ;;
        -e|--end) END=$2; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

INPUT_FILES=$(find "$INPUT_DIR" -type f | sort)

# List files with their corresponding index
COUNTER=0
for INPUT in $INPUT_FILES; do
    COUNTER=$((COUNTER + 1))
    echo "Input ${COUNTER}: ${INPUT}"
done

if [ "$LIST" -eq 1 ]; then
    echo "Exiting after listing input files"
    exit 0
fi

MAX_COUNTER=$COUNTER
COUNTER=0
for INPUT in $INPUT_FILES; do
    COUNTER=$((COUNTER + 1))

    if [ $BEGIN -ne 0 ] && [ $COUNTER -lt $BEGIN ]; then
        continue
    fi
    if [ $END -ne 0 ] && [ $COUNTER -gt $END ]; then
        continue
    fi

    echo ""
    echo "Emulating input ${COUNTER} of ${MAX_COUNTER}: ${INPUT}"

    ../zisk/target/release/ziskemu -e "$ELF_FILE" -i "$INPUT"
done