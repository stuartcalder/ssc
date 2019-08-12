# ssc
C++17 Library for Gnu/Linux and Microsoft Windows, providing cryptographic and Operating-System abstracted
file I/O capabilities.
## Dependencies
-   Meson Build System
## Linux Dependencies
-    __ncurses__
-    __tinfo__
## Building ssc
### The Meson Way (Gnu/Linux and MS Windows)
1. git clone [ssc](https://github.com/stuartcalder/ssc) into a system include
   directory
    - __'/usr/local/include'__ on Linux
    - __'C:\local\include\'__  on Windows
2. meson builddir
3. cd builddir
4. ninja
5. ninja install (as root)
### The Makefile Way (Gnu/Linux only)
1. git clone [ssc](https://github.com/stuartcalder/ssc) into a system include
   directory
    - __'/usr/local/include'__ on Linux
    - __'C:\local\include\'__  on Windows
2. cd ssc
3. make libssc.so
4. make install (as root)
