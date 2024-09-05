#!/usr/bin/env bash

#TODO: add comments

# We do not need to build llvm-project from source
rm -rf src/llvm-project

# Remove all .a/.dll/.exe/.lib files, this covers all remaining binaries
find . -type f -regex ".*\.\(a\|dll\|exe\|lib\)$" -delete

find . -type f -name ".cargo-checksum.json" -print0 | xargs -0 -I% sh -c 'echo "{\"files\":{}}" > "%"'

find . -type f -name "Cargo.lock" -delete

sed -i 's/args.append("--frozen")/pass/g' src/bootstrap/bootstrap.py

sed -i 's/cargo.arg("--frozen");//g' src/bootstrap/src/core/builder.rs