project('ssc', 'cpp', default_options: ['cpp_std=c++17', 'buildtype=release',
                                        'optimization=3', 'strip=true',
                                        'cpp_eh=none'])
cc = meson.get_compiler('cpp')

host_os = host_machine.system()
if host_os == 'openbsd' or host_os == 'linux'
	define_flag_prefix = '-D'
elif host_os == 'windows'
	define_flag_prefix = '/D'
else
	assert(false)
endif

ssc_src = ['general/arg_mapping.cc', 'general/base64.cc', 'general/print.cc',
           'files/files.cc', 'interface/terminal.cc', 'crypto/sspkdf.cc',
           'general/parse_string.cc', 'files/os_map.cc',
	   'crypto/implementation/cbc_v2.cc']
lib_deps = []
extra_args = []

if get_option('disable_memorylocking')
	flag = define_flag_prefix + '__SSC_DISABLE_MEMORYLOCKING'
	extra_args += flag
endif

if host_os == 'openbsd'
	lib_deps += cc.find_library('ncurses')
	extra_args += '-fvisibility=hidden'
	extra_args += '-fno-exceptions'
	inc_dir = include_directories('..')
	shared_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       cpp_args: extra_args, install: true, include_directories: inc_dir)
elif host_os == 'linux'
	lib_deps += cc.find_library('ncurses')
	lib_deps += cc.find_library('tinfo')
	extra_args += '-fvisibility=hidden'
	extra_args += '-fno-exceptions'
	shared_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       cpp_args: extra_args, install: true)
elif host_os == 'windows'
	lib_deps += cc.find_library('bcrypt')
	inc_dir = include_directories('C:/include')
	extra_args += '/DBUILD_STATIC'
	static_library('ssc', sources: ssc_src, dependencies: lib_deps,
		       include_directories: inc_dir, cpp_args: extra_args)
else
	assert(false)
endif
