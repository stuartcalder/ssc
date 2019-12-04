#!/bin/sh
g++ -std=c++17 -O3 -o ext_threefish_test threefish_test.cc -lssc -Wl,--no-as-needed
