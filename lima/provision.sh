#!/bin/bash -ex

sudo apt update
sudo apt install lsb-release wget gnupg zstd libzstd-dev \ # bpf-linker deps
  bpftool gpg build-essential git protobuf-compiler pkg-config libssl-dev # system deps

# LLVM required for bpf-linker
# see: https://github.com/aya-rs/bpf-linker?tab=readme-ov-file
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 21 all

# Install bpf-linker
cargo install bpf-linker --no-default-features --features llvm-21

# Install Rustup, cargo-binstall
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
source ~/.bashrc
source ~/.profile
