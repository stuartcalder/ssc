# SSC
project('ssc', 'cpp',
	default_options: ['cpp_std=c++17', 'buildtype=release',
                          'optimization=3', 'strip=true',
			  'cpp_eh=none'])
cc = meson.get_compiler('cpp')

os = host_machine.system()

if os == 'windows' and cc.get_id() == 'msvc'
	_Define_Flag_Prefix = '/D'
else
	_Define_Flag_Prefix = '-D'
endif

ssc_src = [
	# `General` Files
	'general/arg_mapping.cc',
	'general/print.cc',
	'general/parse_string.cc',
	# `Crypto` Files
	'crypto/implementation/sspkdf.cc',
	'crypto/implementation/cbc_v2.cc',
	]
lib_deps   = []
cpp_flags = []
inc_dir    = []

if os   == 'openbsd' or os == 'freebsd'
	cpp_flags += '-fvisibility=hidden'
	cpp_flags += '-fno-exceptions'
	lib_deps  += cc.find_library('ncurses')
	include_install = '/usr/local/include'
elif os == 'linux'
	cpp_flags += '-fvisibility=hidden'
	cpp_flags += '-fno-exceptions'
	lib_deps  += cc.find_library('ncurses')
	include_install = '/usr/include'
	lib_deps += cc.find_library('tinfo')
elif os == 'windows'
	_flag = _Define_Flag_Prefix + '__BUILD_STATIC'
	cpp_flags += _flag
	include_install = 'C:/include'
	lib_deps += cc.find_library('bcrypt')
endif

inc_dir += '..'

if get_option('disable_memorylocking')
	_flag = _Define_Flag_Prefix + '__SSC_DISABLE_MEMORYLOCKING'
	cpp_flags += _flag
endif

if get_option('disable_runtime_checks')
	_flag = _Define_Flag_Prefix + '__SSC_DISABLE_RUNTIME_CHECKS'
	cpp_flags += _flag
endif

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
