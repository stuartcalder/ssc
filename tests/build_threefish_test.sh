#!/bin/sh
g++ -std=c++17 -O3 -o master_sspkdf_test sspkdf_test.cc -lssc -Wl,--no-as-needed
g++ -std=c++17 -O3 -o master_threefish_test threefish_test.cc -lssc -Wl,--no-as-needed
