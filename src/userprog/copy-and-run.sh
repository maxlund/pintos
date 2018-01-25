#!/bin/bash

# Make first
make -j8
# Go to the target directory
cd build
# Build examples just in case
make -C ../../examples
# Copy our labtest
pintos --qemu -p ../../examples/lab1test -a lab1test -- -q
# Run labtest
pintos --qemu -- run lab1test
