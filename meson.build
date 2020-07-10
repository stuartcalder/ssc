# SSC
project('ssc', 'cpp',
	default_options: ['cpp_std=c++17', 'buildtype=release',
                          'optimization=3', 'strip=true',
			  'cpp_eh=none'],
	version: '1.0')
# Determine compiler, operating system.
cc = meson.get_compiler('cpp')
os = host_machine.system()
_SUPPORTED_OPERATING_SYSTEMS = ['openbsd', 'freebsd', 'netbsd', 'darwin', 'linux', 'windows']
_SUPPORTED_COMPILERS         = ['gcc', 'clang', 'msvc']
_GCC_COMPATIBLE_COMPILERS    = ['gcc', 'clang']
# Assert that we are building on a supported operating system, with a supported compiler.
assert (os in _SUPPORTED_OPERATING_SYSTEMS,  'You are trying to build SSC using an unsupported operating system!')
assert (cc.get_id() in _SUPPORTED_COMPILERS, 'You are tryingt o build SSC using an unsupported compiler!')
# Determine what prefix to use when passing macro defines.
if os == 'windows' and cc.get_id() == 'msvc'
	_D_PREFIX = '/D'
else
	_D_PREFIX = '-D'
endif
# Describe the source files we'll be compiling into libssc.
ssc_src = [ 'general/c_argument_map.cc',
	    'general/print.cc',
	    'general/parse_string.cc',
	]
# Setup these empty arrays that we will be appending to depending on OS, etc.
lib_deps  = []
cpp_flags = []
inc_dir   = []
# Determine flags to pass to gcc-compatible compilers.
gcc_compatible_flags = [
	'-fvisibility=hidden', # Only include symbols that are explicitly needed.
	'-fno-exceptions',     # Disable exceptions.
	'-fstrict-aliasing',   # Enable strict aliasing rules.
	'-Wall',               # Give us all the compile-time warnings.
	'-funroll-loops',      # Unroll loops to optimize for speed.
	'-fno-rtti',           # We don't use run-time type info, so disable it.
]
if os != 'netbsd'
	gcc_compatible_flags += '-flto' # Link-time optimizations (Disabled by default on NetBSD)
endif

# On OSX we require __STDC_WANT_LIB_EXT1__ to be defined as 1, for access to memset_s.
if os == 'darwin'
	_flag = _D_PREFIX + '__STDC_WANT_LIB_EXT1__=1'
	cpp_flags += _flag
endif
# On OpenBSD, FreeBSD, and OSX, the library dependencies and 'include_install' directory are the same.
if os == 'openbsd' or os == 'freebsd' or os == 'darwin'
	if cc.get_id() in _GCC_COMPATIBLE_COMPILERS
		cpp_flags += gcc_compatible_flags
	endif
	lib_deps  += cc.find_library('ncurses')
	include_install = '/usr/local/include'
# NetBSD uses different directories than the others, with pkgsrc.
elif os == 'netbsd'
	if cc.get_id() in _GCC_COMPATIBLE_COMPILERS
		cpp_flags += gcc_compatible_flags
	endif
	lib_deps += cc.find_library('ncurses', dirs: '/usr/pkg/lib')
	include_install = '/usr/local/include'
	inc_dir += '/usr/pkg/include'
# On GNU/Linux, we need ncurses as on the BSD's, but we also need tinfo. Use /usr/include for the 'include_install' directory.
elif os == 'linux'
	if cc.get_id() in _GCC_COMPATIBLE_COMPILERS
		cpp_flags += gcc_compatible_flags
	endif
	lib_deps  += cc.find_library('ncurses')
	lib_deps  += cc.find_library('tinfo')
	include_install = '/usr/include'
# On Win64, define SSC_BUILD_STATIC and use bcrypt.dll for access to the newer Microsoft crypto API. Use C:/include as the 'include_install' directory.
elif os == 'windows'
	_flag = _D_PREFIX + 'SSC_BUILD_STATIC'
	cpp_flags += _flag
	lib_deps += cc.find_library('bcrypt')
	include_install = 'C:/include'
endif

inc_dir += '..'

# If specified, do not lock memory to try to prevent sensitive data from swapping.
if get_option('disable_memorylocking')
	_flag = _D_PREFIX + 'SSC_EXT_DISABLE_MEMORYLOCKING'
	cpp_flags += _flag
endif
# If specified, disable certain correctness checks.
if get_option('disable_runtime_checks')
	_flag = _D_PREFIX + 'SSC_EXT_DISABLE_RUNTIME_CHECKS'
	cpp_flags += _flag
endif
# If specified, enable the SSC_DRAGONFLY_V1 encryption method.
if get_option('enable_dragonfly_v1')
	ssc_src += 'crypto/implementation/dragonfly_v1.cc'
endif
# If specified, enable the 3CRYPT_CBC_V2 encryption method.
if get_option('enable_cbc_v2')
	ssc_src += 'crypto/implementation/cbc_v2_f.cc'
	ssc_src += 'crypto/implementation/sspkdf.cc'
endif
# For compilers compatible with gcc flags...
if cc.get_id() in _GCC_COMPATIBLE_COMPILERS
#	If specified, leave debugging symbols in the binary.
	if get_option('enable_debugging_symbols')
		cpp_flags += '-g'
	endif
#	If specified, specify to build a native binary with access to all native instruction sets.
	if get_option('use_native_optimizations')
		cpp_flags += '-march=native'
	endif
endif

# Install the ssc git project directory into the specified include directory, where code that depends upon ssc will find ssc.
install_subdir('../ssc', install_dir: include_install, exclude_directories: ['builddir','.git'],
                                                       exclude_files: '.gitignore')

# For Win64, build ssc as a static library: ssc.lib
if os == 'windows'
	static_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       cpp_args: cpp_flags, include_directories: inc_dir,
		       name_suffix: 'lib', name_prefix: '',
		       install: true, install_dir: 'C:/lib')
# For Unix-like systems, build ssc as a shared object library: libssc.so
else
	shared_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       cpp_args: cpp_flags, include_directories: inc_dir,
		       install: true)
endif
