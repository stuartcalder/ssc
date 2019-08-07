project( 'ssc', 'cpp', default_options: [ 'cpp_std=c++17', 'strip=true',
'buildtype=release', 'optimization=3' ] )

cc = meson.get_compiler( 'cpp' )

ssc_src = [ 'general/arg_mapping.cc', 'general/base64.cc', 'general/print.cc',
    'files/files.cc', 'interface/terminal.cc', 'crypto/operations.cc',
    'crypto/sspkdf.cc', 'general/error_conditions.cc' ]

ncurses_dep = cc.find_library( 'ncurses' )
tinfo_dep = cc.find_library( 'tinfo' )

ssc_inc = include_directories( '/usr/local/include' )

shared_library( 'ssc', sources: ssc_src, dependencies: [ ncurses_dep, tinfo_dep
    ], include_directories: ssc_inc )
