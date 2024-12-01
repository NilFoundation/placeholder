#!/usr/bin/env bash

# check-rpath.sh

#!/bin/bash

set -e

# Usage function
usage() {
    echo "Usage: $0 /path/to/directory"
    exit 1
}

# Check if directory is provided
if [ -z "$1" ]; then
    usage
fi

DIRECTORY="$1"

# Verify the directory exists
if [ ! -d "$DIRECTORY" ]; then
    echo "Error: Directory '$DIRECTORY' does not exist."
    exit 1
fi

LIBZ_DIR="/nix/store/2k9k3q1vk8z6w7743k6nb22vnb05xv06-zlib-1.3.1/lib/"
echo "Library directory: $LIBZ_DIR"

# Iterate over all files in the directory
find "$DIRECTORY" -maxdepth 1 -type f | while read -r FILE; do
    # Check if file is an ELF executable
    if file "$FILE" | grep -q 'ELF'; then
        echo "Processing ELF executable: $FILE"

        # Backup the original file
        cp "$FILE" "$FILE.bak"

        # Get existing RPATH
        EXISTING_RPATH=$(patchelf --print-rpath "$FILE" || true)

        # Determine the new RPATH
        if [ -z "$EXISTING_RPATH" ]; then
            NEW_RPATH="$LIBZ_DIR"
        else
            NEW_RPATH="$EXISTING_RPATH:$LIBZ_DIR"
        fi

        # Modify the RPATH
        patchelf --set-rpath "$NEW_RPATH" "$FILE"

        echo "Updated RPATH for $FILE to $NEW_RPATH"
    else
        echo "Skipping non-ELF file: $FILE"
    fi
done

echo "RPATH update complete."
