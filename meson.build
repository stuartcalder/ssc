project('ssc', 'cpp',
	default_options: ['cpp_std=c++17', 'buildtype=release',
                          'optimization=3', 'strip=true',
			  'cpp_eh=none'])
cc = meson.get_compiler('cpp')

os = host_machine.system()

if os != 'windows'
	DEFINE_FLAG_PREFIX = '-D'
else
	DEFINE_FLAG_PREFIX = '/D'
endif

ssc_src = [
	# `General` Files
	'general/arg_mapping.cc',
	'general/print.cc',
	'general/parse_string.cc',
	# `Crypto` Files
	'crypto/implementation/sspkdf.cc',
	'crypto/implementation/cbc_v2.cc',
	'crypto/implementation/common.cc',
	# `Interface` Files
	'interface/terminal.cc'
	]
lib_deps   = []
cpp_flags = []
inc_dir    = []

if os   == 'openbsd' or os == 'freebsd'
	cpp_flags += '-fvisibility=hidden'
	cpp_flags += '-fno-exceptions'
	lib_deps  += cc.find_library('ncurses')
	include = '/usr/local/include'
elif os == 'linux'
	cpp_flags += '-fvisibility=hidden'
	cpp_flags += '-fno-exceptions'
	lib_deps  += cc.find_library('ncurses')
	include = '/usr/include'
	lib_deps += cc.find_library('tinfo')
elif os == 'windows'
	flag = DEFINE_FLAG_PREFIX + '__BUILD_STATIC'
	cpp_flags += flag
	include = 'C:/include'
	lib_deps += cc.find_library('bcrypt')
endif

if get_option('include_directories').length() != 0
	include = get_option('include_directories')[0]
endif

inc_dir += include

if get_option('disable_memorylocking')
	flag = DEFINE_FLAG_PREFIX + '__SSC_DISABLE_MEMORYLOCKING'
	cpp_flags += flag
endif

if get_option('enable_testing')
	flag = DEFINE_FLAG_PREFIX + '__SSC_ENABLE_TESTING'
	cpp_flags += flag
endif

if get_option('enable_experimental_features')
	flag = DEFINE_FLAG_PREFIX + '__SSC_ENABLE_EXPERIMENTAL'
	cpp_flags += flag
	ssc_src += 'crypto/implementation/ctr_v1.cc'
endif

if os == 'windows'
	static_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       cpp_args: cpp_flags, include_directories: inc_dir)
else
	shared_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       cpp_args: cpp_flags, include_directories: inc_dir,
		       install: true)
endif
