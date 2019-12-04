#!/bin/sh
g++ -std=c++17 -O3 -o sspkdf_test sspkdf_test.cc -Wl,--no-as-needed -lssc
