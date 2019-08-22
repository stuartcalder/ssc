#pragma once

#include <cstdlib>
#include <cstdio>
#include <string>
#include <ssc/general/symbols.hh>

#ifdef _WIN64
    #include <windows.h>
#endif

namespace ssc
{

#if   defined( __gnu_linux__ )
    using OS_File_t = int;
#elif defined( _WIN64 )
    using OS_File_t = HANDLE;
#else
    #error "Unsupported platform"
#endif

    std::size_t DLL_PUBLIC  get_file_size   (OS_File_t const);
    std::size_t DLL_PUBLIC  get_file_size   (char const * filename);
    std::size_t DLL_PUBLIC  get_file_size   (std::FILE const * const file);
    bool        DLL_PUBLIC  file_exists     (char const * filename);
    void        DLL_PUBLIC  check_file_name_sanity (std::string const & str,
                                                    std::size_t const   min_size);
    void        DLL_PUBLIC  enforce_file_existence(char const * const __restrict filename,
                                                   bool const                    force_to_exist,
                                                   char const * const __restrict opt_error_msg = nullptr);
    OS_File_t   DLL_PUBLIC  open_existing_os_file (char const * filename, bool const readonly);
    OS_File_t   DLL_PUBLIC  create_os_file   (char const * filename);
    void        DLL_PUBLIC  close_os_file    (OS_File_t const os_file); 
    void        DLL_PUBLIC  set_os_file_size (OS_File_t const os_file, std::size_t const new_size);
}/* ! namespace ssc */
