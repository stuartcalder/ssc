project( 'ssc', 'cpp', default_options: [ 'cpp_std=c++17', 'buildtype=release',
                                          'optimization=3', 'strip=true',
                                          'cpp_eh=none' ] )

cc = meson.get_compiler( 'cpp' )
host_os = host_machine.system()

ssc_src = [ 'general/arg_mapping.cc', 'general/base64.cc', 'general/print.cc',
            'files/files.cc', 'interface/terminal.cc', 'crypto/sspkdf.cc',
            'general/parse_string.cc', 'files/os_map.cc' ]

lib_deps = []
if host_os == 'linux'
    lib_deps += cc.find_library( 'ncurses' )
    lib_deps += cc.find_library( 'tinfo' )
    extra_args = [ '-fvisibility=hidden',  '-fno-exceptions' ]
    shared_library( 'ssc', sources: ssc_src, dependencies: lib_deps,
                    cpp_args: extra_args, install: true )
elif host_os == 'windows'
    lib_deps += cc.find_library( 'bcrypt' )
    inc_dir = include_directories( 'C:/local/include' )
    extra_args = '-DBUILD_STATIC'
    static_library( 'ssc', sources: ssc_src, dependencies: lib_deps,
                    include_directories: inc_dir, cpp_args: extra_args )
else
    assert( false )
endif
