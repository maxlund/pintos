#!/bin/bash

set -e

GIT_ROOT=$HOME/TDDB68/linuxpintos/src
SVN_ROOT=$HOME/TDDB68/linuxpintos-svn/src

# Get the changed files
echo "List of files that changed"
FILES=$(svn diff | \grep ^Index | sed -e 's/\s\+//g' | cut -d: -f2)
echo $FILES

for file in $FILES; do
    dir=$(dirname $file)
    name=$(basename $file)
    echo -n "Moving $file to git ..."
    mv -f $file $GIT_ROOT/$dir
    echo "[done]"
done
