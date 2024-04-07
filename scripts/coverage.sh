#!/bin/sh

root=$(git rev-parse --show-toplevel)
cd $root

mkdir -p ./coverage

# default to nextest
tester="nextest"
[ "$1" = "test" ] && tester="test"

exec cargo llvm-cov ${tester} --lcov --output-path ./coverage/lcov.info
