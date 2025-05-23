#!/bin/bash

FILES="$@"

if [ -z "$FILES" ]; then
    echo "No C/C++ files to check - clang-tidy skipped"
    exit 0
fi

clang-tidy --use-color \
           --extra-arg=-Wno-unknown-warning-option \
           --extra-arg=-Wno-unused-command-line-argument \
           -p=netarmageddon/core/traffic_c \
           --config-file=netarmageddon/core/traffic_c/.clang-tidy \
           $FILES
