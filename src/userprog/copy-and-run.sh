#!/bin/bash

FILESYS_TESTS="lg-create \
    lg-full \
    lg-random \
    lg-seq-block \
    lg-seq-random \
    sm-create \
    sm-full \
    sm-random \
    sm-seq-block \
    sm-seq-random \
    syn-read \
    syn-remove \
    syn-write"

USERPROG_TESTS="close-twice \
    read-normal \
    multi-recurse \
    multi-child-fd"

FILESYS_BASE=../filesys

TESTDIR_FILESYS=$FILESYS_BASE/build/tests/filesys
TESTDIR_USERPROG=tests/userprog

# Make userprog and filesys first
make -C $FILESYS_BASE -j8
make -j8

# Go to the target directory
cd build

echo "PWD=$PWD"
# Copy our labtest
for test in $FILESYS_TESTS; do
    echo pintos --qemu -p $TESTDIR_FILESYS/$test -a $test -- -q
done

for test in $USERPROG_TESTS; do
    echo pintos --qemu -p $TESTDIR_USERPROG/$test -a $test -- -q
done

