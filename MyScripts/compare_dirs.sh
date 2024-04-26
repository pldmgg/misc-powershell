#!/bin/bash
# USAGE: ./compare_dirs.sh /path/to/directory1 /path/to/directory2

# Directories to compare
DIR1="$1"
DIR2="$2"

# Temporary files to store output of md5 sums and filenames
TEMP_FILE1="$(mktemp /tmp/dedup1.XXXXXX)"
TEMP_FILE2="$(mktemp /tmp/dedup2.XXXXXX)"

# Ensure both directories are specified
if [ -z "$DIR1" ] || [ -z "$DIR2" ]; then
    echo "Usage: $0 [directory1] [directory2]"
    exit 1
fi

# Find all files in the first directory, calculate their MD5 checksums, and store results in temp file 1
find "$DIR1" -type f -exec md5 -r {} + > "$TEMP_FILE1"

# Find all files in the second directory, do the same, and store in temp file 2
find "$DIR2" -type f -exec md5 -r {} + > "$TEMP_FILE2"

# Process the results to find duplicates between the two directories
awk '{ print $1 }' "$TEMP_FILE1" "$TEMP_FILE2" | sort | uniq -d | while read checksum; do
    echo "Duplicates for checksum $checksum:"
    grep $checksum "$TEMP_FILE1" "$TEMP_FILE2" | awk '{print $2}'
done

# Clean up temporary files
rm "$TEMP_FILE1" "$TEMP_FILE2"
