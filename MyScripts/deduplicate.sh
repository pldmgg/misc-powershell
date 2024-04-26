#!/bin/bash
# USAGE: ./deduplicate.sh /path/to/directory

# Directory to search for duplicate files
SEARCH_DIR="$1"

# Temporary file to store output of md5 sums and filenames
TEMP_FILE="$(mktemp /tmp/dedup.XXXXXX)"

# Ensure the directory is specified
if [ -z "$SEARCH_DIR" ]; then
    echo "Usage: $0 [directory]"
    exit 1
fi

# Find all files in the specified directory, calculate their MD5 checksums, and store results in a temp file
find "$SEARCH_DIR" -type f -exec md5 -r {} + > "$TEMP_FILE"

# Process the results to find duplicates
awk '{ print $1 }' "$TEMP_FILE" | sort | uniq -d | while read checksum; do
    echo "Duplicates for checksum $checksum:"
    grep $checksum "$TEMP_FILE" | awk '{print $2}'
done

# Clean up temporary file
rm "$TEMP_FILE"
