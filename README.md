# ssc
C++17 Cryptographic & File I/O Library for Gnu/Linux and Microsoft Windows.
Little Endian.
## Dependencies
-   Meson Build System
### Linux Dependencies
-    __ncurses__
-    __tinfo__
### MS Windows Dependencies
-   Minimum **Windows Vista/Server 2008**
-   Visual Studio 2019
## Building ssc with Meson on Gnu/Linux
1. git clone [ssc](https://github.com/stuartcalder/ssc) into **/usr/include**
2. cd into __/usr/include__ and do the following:
```
    mkdir builddir
    meson --backend ninja --prefix=/usr builddir
    cd builddir
    ninja
    sudo ninja install
```

## Building ssc with Meson on Microsoft Windows(c)
1. git clone [ssc](https://github.com/stuartcalder/ssc) into **C:/include**
2. Open a command-prompt, specifically open __"x64 Native Tools Command Prompt for VS 2019"__
2. cd into __C:/include__ and do the following:
```
    mkdir builddir
    meson --backend ninja builddir
    cd builddir
    ninja
```
3. Assuming success, ninja should have outputted a file __libssc.a__
4. Rename __libssc.a__ to __ssc.lib__
5. Manually copy __ssc.lib__ to __C:/lib__
