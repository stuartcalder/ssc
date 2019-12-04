#!/bin/sh
g++ -std=c++17 -O3 -o ext_skein_test skein_test.cc -lssc -Wl,--no-as-needed
