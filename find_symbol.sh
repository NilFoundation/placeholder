#!/bin/bash

# Symbol to search for
SYMBOL="$2"

# Check if a directory was provided
if [ -z "$1" ]; then
    echo "Usage: $0 /path/to/directory symbol"
    exit 1
fi

# Directory to search
DIR="$1"

# Find all .so and .a files and process them
find "$DIR" -type f \( -name '*.so*' -o -name '*.a' \) -print0 | while IFS= read -r -d '' file; do
    # Run nm and search for the symbol
    if nm -D -U "$file" 2>/dev/null | grep -Fq "$SYMBOL"; then
        echo "Symbol found in: $file"
    fi
done
