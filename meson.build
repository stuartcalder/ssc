project('ssc', 'cpp', default_options: ['cpp_std=c++17', 'buildtype=release',
                                        'optimization=3', 'strip=true',
                                        'cpp_eh=none'])
cc = meson.get_compiler('cpp')

os = host_machine.system()
define_flag_prefix = '-D'
if os == 'windows'
	define_flag_prefix = '/D'
endif

ssc_src = [
	# `General` Files
	'general/arg_mapping.cc', 'general/base64.cc', 'general/print.cc',
	'general/parse_string.cc',
	# `Files` Files
	'files/files.cc', 'files/os_map.cc',
	# `Crypto` Files
	'crypto/sspkdf.cc', 'crypto/implementation/cbc_v2.cc',
	# `Interface` Files
	'interface/terminal.cc'
	]
lib_deps   = []
extra_args = []
inc_dir    = []

# Parse meson_options.txt
if get_option('disable_memorylocking')
	flag = define_flag_prefix + '__SSC_DISABLE_MEMORYLOCKING'
	extra_args += flag
endif
if get_option('enable_experimental_features')
	flag = define_flag_prefix + '__SSC_ENABLE_EXPERIMENTAL'
	extra_args += flag
endif

if os == 'openbsd'
	lib_deps   += cc.find_library('ncurses')
	extra_args += '-fvisibility=hidden'
	extra_args += '-fno-exceptions'
	inc_dir    += include_directories('..')
	shared_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       cpp_args: extra_args, install: true, include_directories: inc_dir)
elif os == 'linux'
	lib_deps   += cc.find_library('ncurses')
	lib_deps   += cc.find_library('tinfo')
	extra_args += '-fvisibility=hidden'
	extra_args += '-fno-exceptions'
	shared_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       cpp_args: extra_args, install: true)
elif os == 'windows'
	lib_deps   += cc.find_library('bcrypt')
	extra_args += '/D__BUILD_STATIC'
	inc_dir    += include_directories('C:/include')
	static_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       include_directories: inc_dir, cpp_args: extra_args)
else
	assert(false)
endif
