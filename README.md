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
1. git clone [ssc](https://github.com/stuartcalder/ssc) and cd into it.
2. Execute the following:
```
	$ mkdir builddir
	$ meson --backend=ninja builddir
	$ cd builddir
	$ ninja
	# ninja install
```
3. ssc should now be installed on your BSD system.

### Building on a GNU/Linux system
1. git clone [ssc](https://github.com/stuartcalder/ssc) and cd into it.
2. Execute the following:
```
	$ mkdir builddir
	$ meson --backend ninja --prefix=/usr builddir
	$ cd builddir
	$ ninja
	# ninja install
```
3. ssc should now be installed on your GNU/Linux system.

### Building on a Microsoft Windows system
1. git clone [ssc](https://github.com/stuartcalder/ssc) and cd into it.
2. Open a __"x64 Native Tools Command Prompt for VS 2019"__ cmd prompt, then cd into the cloned ssc project directory.
3. Execute the following:
```
	mkdir builddir
	meson --backend ninja builddir
	cd builddir
	ninja
```
4. ssc should now be installed on your Microsoft Windows system.
