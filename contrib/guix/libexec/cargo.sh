#!/usr/bin/env bash
export LC_ALL=C
set -e -o pipefail

cd /monero/src/fcmp_pp/fcmp_pp_rust
cargo fetch

cd /monero

if [ ! -e "rustc-1.77.1-src.tar.gz" ]; then
    wget --no-check-certificate https://static.rust-lang.org/dist/rustc-1.77.1-src.tar.gz
fi

echo "ee106e4c569f52dba3b5b282b105820f86bd8f6b3d09c06b8dce82fb1bb3a4a1  rustc-1.77.1-src.tar.gz" | sha256sum -c

if [ ! -d "rust" ]; then
    tar -xvf rustc-1.77.1-src.tar.gz
    mv rustc-1.77.1-src rust
fi

rm -rf /monero/cargo
mv /home/user/.cargo /monero/cargo
