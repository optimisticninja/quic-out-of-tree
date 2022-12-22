#!/bin/sh

clang-format -i $(find . -name '**.h' -o -name '**.c')
