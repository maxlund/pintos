#!/bin/bash

test -d build ||
    {
        echo "Build first" 2>&1
        exit 1 
    }

cd build

# Create disk
pintos-mkdisk fs.dsk 2
# Format it
pintos --qemu -- -f -q

pintos --qemu -p ../../examples/lab1test -a lab1test -- -q
