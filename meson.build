project( 'ssc', 'cpp', default_options: [ 'cpp_std=c++17', 'strip=true',
'buildtype=release', 'optimization=3' ] )

cc = meson.get_compiler( 'cpp' )

ssc_src = [ 'general/arg_mapping.cc', 'general/base64.cc', 'general/print.cc',
    'files/files.cc', 'interface/terminal.cc', 'crypto/operations.cc',
    'crypto/sspkdf.cc', 'general/error_conditions.cc', 'crypto/cbc.cc',
    'crypto/threefish.cc' ]

lib_deps = []
if host_machine.system() == 'linux'
    lib_deps += cc.find_library( 'ncurses' )
    lib_deps += cc.find_library( 'tinfo' )
    inc_dir  = include_directories( '/usr/local/include' )
endif

if host_machine.system() == 'windows'
    lib_deps += cc.find_library( 'bcrypt' )
    inc_dir = include_directories( 'C:\local\include' )
endif

shared_library( 'ssc', sources: ssc_src, dependencies: lib_deps,
    include_directories: inc_dir )
