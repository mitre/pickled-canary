#!/usr/bin/env bash

# This script generates test coverage for the rust portion of this codebase.
# Results can be viewed in VS Code by installing and enabling the "Coverage
# Gutters" plugin.
#
# Installation prerequisites:
#
# sudo apt install jq
# rustup component add llvm-tools-preview
# cargo install rustfilt
# cargo install cargo-binutils
#
# Must also be using a nightly Rust compiler

# Copyright (C) 2025 The MITRE Corporation All Rights Reserved


RUSTFLAGS="-C instrument-coverage" \
    LLVM_PROFILE_FILE="mytest-%m.profraw" \
    cargo test --tests

cargo profdata -- merge -sparse $( for file in $( find . -name "*.profraw" ) ; do echo $file ; done ) -o mytest.profdata

cargo cov -- export \
    $( for file in \
            $( \
                      RUSTFLAGS="-C instrument-coverage" \
                                  cargo test --tests --no-run --message-format=json \
              | jq -r "select(.profile.test == true) | .filenames[]" \
              | grep -v dSYM - \
        ); \
      do \
        printf "%s %s " -object $file; \
      done \
    ) \
  --instr-profile=mytest.profdata --format=lcov > lcov_all.info

# Filter out all libraries
lcov -o lcov.info -r lcov_all.info '**/.cargo/**' '/home/user1/.cargo/registry/src/*'

lcov --summary lcov.info
lcov --summary lcov.info > lcov_summary.txt

# Cleanup temporary files
find . -name "*.profraw" -delete
rm mytest.profdata
