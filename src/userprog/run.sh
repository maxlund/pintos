#!/bin/bash

# Clean
make clean
# Make
make -j8
# Cd into build
cd build
make -C ../../examples
# Create disk
pintos-mkdisk fs.dsk 2
# Format it
pintos --qemu -- -f -q
# Copy our labtest
pintos --qemu -p ../../examples/lab1test -a lab1test -- -q
# Run labtest
pintos --qemu -- run lab1test
