#pragma once

#if defined( BUILD_STATIC ) || defined( IMPORT_STATIC )
#   define DLL_PUBLIC
#   define DLL_LOCAL
#else
#   if defined( _WIN32 ) || defined( __CYGWIN__ )
#       if defined( BUILD_DLL )
#           if defined( __GNUC__ )
#               define DLL_PUBLIC __attribute__ ((dllexport))
#           else
#               define DLL_PUBLIC __declspec(dllexport)
#           endif
#       else
#           if defined( __GNUC__ )
#               define DLL_PUBLIC __attribute__ ((dllimport))
#           else
#               define DLL_PUBLIC __declspec(dllimport)
#           endif
#       endif
#       define DLL_LOCAL
#   else
#       if defined( __GNUC__ ) && ( __GNUC__ >= 4 )
#           define DLL_PUBLIC __attribute__ ((visibility ("default")))
#           define DLL_LOCAL  __attribute__ ((visibility ("hidden")))
#       else
#           define DLL_PUBLIC
#           define DLL_LOCAL
#       endif
#   endif
#endif
