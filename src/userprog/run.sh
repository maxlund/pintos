#!/bin/bash

test -d build ||
    {
        echo "Build first" 2>&1
        exit 1 
    }

cd build

pintos --qemu -- run lab1test

