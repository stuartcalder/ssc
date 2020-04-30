# SSC
project('ssc', 'cpp',
	default_options: ['cpp_std=c++17', 'buildtype=release',
                          'optimization=3', 'strip=true',
			  'cpp_eh=none'])
cc = meson.get_compiler('cpp') # Get the C++ compiler.

os = host_machine.system() # Get the operating system.
assert (
	(os == 'openbsd' or os == 'freebsd' or os == 'darwin' or os == 'linux' or os == 'windows'),
	'You are trying to build SSC with an unsupported operating system!'
)
assert (
	(cc.get_id() == 'gcc' or cc.get_id() == 'clang' or cc.get_id() == 'msvc'),
	'The only supported compilers are GCC, Clang, And MSVC!'
)

if os == 'windows' and cc.get_id() == 'msvc'
	_Define_Flag_Prefix = '/D'
else
	_Define_Flag_Prefix = '-D'
endif
if cc.get_id() == 'gcc' or cc.get_id() == 'clang'
	is_gcc_compatible = true
else
	is_gcc_compatbile = false
endif

ssc_src = [
	# `General` Files
	'general/arg_mapping.cc',
	'general/print.cc',
	'general/parse_string.cc',
	]
lib_deps  = []
cpp_flags = []
inc_dir   = []
gcc_compatible_flags = [
	'-fvisibility=hidden', '-fno-exceptions', '-fstrict-aliasing',
	'-Wall', '-funroll-loops'
]

if os   == 'darwin'
	# OSX requires this define for access to memset_s
	_flag = _Define_Flag_Prefix + '__STDC_WANT_LIB_EXT1__=1'
	cpp_flags += _flag
endif
if os   == 'openbsd' or os == 'freebsd' or os == 'darwin'
	if is_gcc_compatible
		cpp_flags += gcc_compatible_flags
	endif
	lib_deps  += cc.find_library('ncurses')
	include_install = '/usr/local/include'
elif os == 'linux'
	if is_gcc_compatible
		cpp_flags += gcc_compatible_flags
	endif
	lib_deps  += cc.find_library('ncurses')
	lib_deps  += cc.find_library('tinfo')
	include_install = '/usr/include'
elif os == 'windows'
	_flag      = _Define_Flag_Prefix + '__BUILD_STATIC'
	cpp_flags += _flag
	lib_deps += cc.find_library('bcrypt')
	include_install = 'C:/include'
endif

inc_dir += '..'

# Begin parsing options.
if get_option('disable_memorylocking')
	_flag = _Define_Flag_Prefix + '__SSC_DISABLE_MEMORYLOCKING'
	cpp_flags += _flag
endif
if get_option('disable_runtime_checks')
	_flag = _Define_Flag_Prefix + '__SSC_DISABLE_RUNTIME_CHECKS'
	cpp_flags += _flag
endif
if get_option('enable_dragonfly_v1')
	ssc_src += 'crypto/implementation/dragonfly_v1.cc'
endif
if get_option('enable_cbc_v2')
	ssc_src += 'crypto/implementation/cbc_v2_f.cc'
	ssc_src += 'crypto/implementation/sspkdf.cc'
endif
if is_gcc_compatible
	if get_option('enable_debugging_symbols')
		cpp_flags += '-g'
	endif
	if get_option('use_native_optimizations')
		cpp_flags += '-march=native'
	endif
endif

# Stop parsing options.

install_subdir('../ssc', install_dir: include_install, exclude_directories: ['builddir','.git'],
                                                       exclude_files: '.gitignore')

if os == 'windows'
	static_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       cpp_args: cpp_flags, include_directories: inc_dir,
		       name_suffix: 'lib', name_prefix: '',
		       install: true, install_dir: 'C:/lib')
else
	shared_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       cpp_args: cpp_flags, include_directories: inc_dir,
		       install: true)
endif
