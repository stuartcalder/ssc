#!/bin/sh
g++ -std=c++17 -O3 -o master_sspkdf_test sspkdf_test.cc -lssc -Wl,--no-as-needed
