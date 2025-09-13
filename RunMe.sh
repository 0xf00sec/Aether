#!/bin/bash

DEBUG=1
TARGET="bin/wisp"
SRC_DIR="src"

calc_hash() {
    shasum -a 256 "$1" | awk '{ print $1 }'
}

make clean
make DEBUG=1

if [ ! -f "$TARGET" ]; then echo "Error: '$TARGET' ain't here ?"
    exit 1
fi

hash_before=$(calc_hash "$TARGET")
echo "Before exec: $hash_before"

"$TARGET"

hash_after=$(calc_hash "$TARGET")
echo "After exec: $hash_after"

# Compare
if [ "$hash_before" == "$hash_after" ]; then
    echo "What!??"
else
    echo "Hashes differ!"
fi
