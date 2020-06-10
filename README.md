# ssc
Portable Cryptography Library
## Purpose
Provide strong symmetric security on many platforms, and take advantage of C++17 features to simplify the expression of cryptographic code.
SSC implements the following algorithms:
* [Threefish](https://www.schneier.com/academic/skein/threefish.html), tweakable block cipher
	- Two different implementations of the key schedule:
	1. Computed On-Demand : When re-keying is common, we compute the key schedule of the cipher on-demand instead of computing and storing all the sub-keys of the key-schedule.
	2. Computed And Stored: When re-keying is uncommon, we compute all the subkeys of the key-schedule and store it, to be accessed sequentially every cipher() and inverse\_cipher() call.
	- Accessed like so: Threefish<256,Key\_Schedule\_E::Stored>, or Threefish<1024,Key\_Schedule\_E::On\_Demand>. If not specified, Stored will be defaulted to.
* [Skein](https://www.schneier.com/academic/skein/), cryptographically-secure hash function
	- Uses Threefish as a tweakable block cipher in the Unique Block Iteration compression function.
	- Repeatedly re-keys the block cipher in its compression function; Skein uses Threefish with the On\_Demand implementation of the key-schedule.
	- Skein can process a near-abitrary amount of input bytes, and output a near-arbitrary amount of bytes. We can stop all those ad-hoc methods of getting arbitrary outputs with fixed-width output hash functions.
* [Catena](https://www.uni-weimar.de/fileadmin/user/fak/medien/professuren/Mediensicherheit/Research/Publications/catena-v3.2.pdf), password Scrambling Framework.
	- Catena attempts to tie the password-to-key computation of guessing a password to a memory-hard problem.
	- SSC's implementation of Catena includes the optional so-called Phi function, from Wenzel's Masters thesis,that provides Sequential-Memory-Hardness at the cost of vulnerability to cache-timing attacks.
	- In SSC, Skein is used, as advised in its specification, as a pseudorandom-number generator, under the assumption that Skein can be modelled as a random oracle.
* [CTR Mode & CBC Mode (Legacy)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
* From the specification, SSC has implementations of a Skein-based Cryptographically Secure PseudoRandom Number Generator.
* For authentication, we use Skein's native MAC instead of HMAC.

## Dependencies
-	[meson](https://mesonbuild.com) Build system
### Unixlike Systems
-	On GNU/Linux we need the ncurses development libraries, and tinfo installed.
-	On Mac OSX and the BSDs, we merely need the ncurses development libraries.
### Win64
-	Minimum __Windows Vista/Server 2008__
-	Visual Studio 2019
## Building ssc with meson
### Building on Mac OSX, OpenBSD, FreeBSD, NetBSD systems
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

### Building on Win64 system
1. git clone [ssc](https://github.com/stuartcalder/ssc) and cd into it.
2. Open a __"x64 Native Tools Command Prompt for VS 2019"__ cmd prompt, then cd into the cloned ssc project directory.
3. Execute the following:
```
	mkdir builddir
	meson --backend ninja builddir
	cd builddir
	ninja
	ninja install
```
4. ssc should now be installed on your Microsoft Windows system.
