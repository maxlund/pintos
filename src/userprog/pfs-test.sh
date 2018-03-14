#!/bin/bash

if [ $(basename `pwd`) != "userprog" ]; then
    echo "Run this script from src/userprog"
    exit 1
fi

cd build

# Remove if existing
test -f fs.dsk && rm -f fs.dsk
# Create pintos disk
pintos-mkdisk fs.dsk 2
# Format it
pintos --qemu -- -f -q
# Make the examples
make -C ../../examples -j8
# Put the pfs files into the disk
pintos --qemu -p ../../examples/pfs -a pfs -- -q
pintos --qemu -p ../../examples/pfs_reader -a pfs_reader -- -q
pintos --qemu -p ../../examples/pfs_writer -a pfs_writer -- -q
# Run pfs
pintos --qemu -- run pfs
# Get the messages file and remove the old one
test -f messages && rm -f messages
pintos --qemu -g messages -- -q
# Compare output
if [ $(cat messages | wc -l) == "500" ]; then
    echo "Output looks good!"
else
    echo "Something went wrong ..."
fi

exit 0
