#!/bin/sh
g++ -std=c++17 -O3 -o main entropy_pool.cc -pthread -latomic -lpthread -Wl,--no-as-needed
