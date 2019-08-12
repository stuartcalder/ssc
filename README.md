# ssc
C++17 Library for Gnu/Linux and Microsoft Windows, providing cryptographic and Operating-System abstracted
file I/O capabilities.
## Dependencies
-   Meson Build System
### Linux Dependencies
-    **ncurses**
-    **tinfo**
### MS Windows Dependencies
-   Minimum Windows Vista/Server 2008
## Building ssc
### The Meson Way (Gnu/Linux and MS Windows)
1. git clone [ssc](https://github.com/stuartcalder/ssc) into a system include
   directory
    - **/usr/local/include** on Linux
    - **C:\local\include** on Windows
2. meson builddir
3. cd builddir
4. ninja
5. ninja install (**as root**)
### The Makefile Way (Gnu/Linux only)
1. git clone [ssc](https://github.com/stuartcalder/ssc) into **/usr/local/include**
2. cd ssc
3. make **libssc.so**
4. make install (**as root**)
