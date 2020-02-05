# ssc
C++17 Cryptography & Abstract File I/O Library for 64-bit OpenBSD, FreeBSD, GNU/Linux, and Microsoft Windows systems, on little-endian architectures only.
## Purpose
SSC aims to provide robust, easy-to-use abstract interfaces to a limited number of strong cryptographic primitives as C++ templates, including:
- The [Threefish Block Cipher](https://www.schneier.com/academic/skein/threefish.html), which we use as the essential crypto primtive in SSC.
	* CipherBlockChaining (CBC) Mode encryption for block ciphers, which we use to provide cryptographic confidentiality.
	* Counter             (CTR) Mode encryption for block ciphers, which we use to provide cryptographic confidentiality.
- The [Skein Cryptographic Hash Function](http://www.skein-hash.info/about), which is built out of the [Threefish Block Cipher](https://www.schneier.com/academic/skein/threefish.html).
	* The SSC implementation of Skein can output up to (2^64) - 1 bytes per invocation.
	* Skein's security proof states roughly: "If [Threefish](https://www.schneier.com/academic/skein/threefish.html) is an ideal block cipher, Skein is a cryptographically secure hash function."
	* From the specification, SSC has implementations of a Skein-based key-derivation function and a Skein-based Cryptographically Secure PseudoRandom Number Generator.
	* For authentication, we use Skein's native MAC instead of HMAC.

## Dependencies
-	[meson](https://mesonbuild.com) Build system
### GNU/Linux Dependencies
-	__ncurses__
-	__tinfo__
### MS Windows Dependencies
-	Minimum __Windows Vista/Server 2008__
-	Visual Studio 2019
## Building ssc with meson
### Building on OpenBSD and FreeBSD systems
1. git clone [ssc](https://github.com/stuartcalder/ssc) into __/usr/local/include__
2. cd into __/usr/local/include__ and do the following:
```
	$ mkdir builddir
	$ meson --backend=ninja builddir
	$ cd builddir
	$ ninja
	# ninja install
```

### Building on a GNU/Linux system
1. git clone [ssc](https://github.com/stuartcalder/ssc) into __/usr/include__
2. cd into __/usr/include__ and do the following:
```
	$ mkdir builddir
	$ meson --backend ninja --prefix=/usr builddir
	$ cd builddir
	$ ninja
	# ninja install
```

### Building on a Microsoft Windows(c) system
1. Create the following directories if they do not exist:
	- __C:/include__
	- __C:/lib__
2. git clone [ssc](https://github.com/stuartcalder/ssc) into __C:/include__
3. Open a command-prompt, specifically open __"x64 Native Tools Command Prompt for VS 2019"__
4. cd into __C:/include__ and do the following:
```
	mkdir builddir
	meson --backend ninja builddir
	cd builddir
	ninja
```
5. Assuming success, ninja should have output a file __libssc.a__
6. Rename __libssc.a__ to __ssc.lib__
7. Manually copy __ssc.lib__ to __C:/lib__
